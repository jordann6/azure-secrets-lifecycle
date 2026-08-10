# frozen_string_literal: true

module Analyzer
  # Reads secret access events out of Log Analytics with KQL.
  #
  # This is where the Azure design diverges from the AWS one and comes out
  # ahead. On AWS the equivalent question needs CloudTrail delivering to
  # S3, a Glue table with partition projection, and an Athena workgroup
  # before a single row can be read. Azure diagnostic settings put Key
  # Vault audit events into a workspace that is already queryable, so the
  # consumer map is one HTTP call against a typed table rather than a
  # data lake with a schema bolted on.
  #
  # Each table is queried separately on purpose. A vault configured with
  # the legacy AzureDiagnostics category and a vault configured with
  # resource specific tables both need covering, and a workspace missing
  # one of them should degrade to a smaller consumer map rather than fail
  # the scan.
  class LogAnalytics
    API_BASE = "https://api.loganalytics.io/v1"

    # Resource specific Key Vault audit table. Preferred: typed columns,
    # cheaper to query, and the only one new vaults get by default.
    KEY_VAULT_QUERY = <<~KQL
      AZKVAuditLogs
      | where TimeGenerated > ago(%<lookback>dd)
      | where OperationName in ("SecretGet", "CertificateGet", "KeyGet")
      | where ResultSignature == "OK"
      | extend parsed = parse_url(tostring(id_s))
      | extend segments = split(tostring(parsed["Path"]), "/")
      | extend resource_id = strcat("https://", tostring(parsed["Host"]), "/",
                                    tostring(segments[1]), "/", tostring(segments[2]))
      | where isnotempty(tostring(segments[2]))
      | summarize access_count = count(), last_accessed = max(TimeGenerated)
          by resource_id,
             principal_id = tostring(identity_claim_oid_g),
             principal_appid = tostring(identity_claim_appid_g),
             operation = OperationName
    KQL

    # Legacy shared table. Same shape, different column source.
    DIAGNOSTICS_QUERY = <<~KQL
      AzureDiagnostics
      | where TimeGenerated > ago(%<lookback>dd)
      | where ResourceProvider == "MICROSOFT.KEYVAULT" and Category == "AuditEvent"
      | where OperationName in ("SecretGet", "CertificateGet", "KeyGet")
      | where ResultSignature == "OK"
      | extend parsed = parse_url(tostring(id_s))
      | extend segments = split(tostring(parsed["Path"]), "/")
      | extend resource_id = strcat("https://", tostring(parsed["Host"]), "/",
                                    tostring(segments[1]), "/", tostring(segments[2]))
      | where isnotempty(tostring(segments[2]))
      | summarize access_count = count(), last_accessed = max(TimeGenerated)
          by resource_id,
             principal_id = tostring(identity_claim_oid_g),
             principal_appid = tostring(identity_claim_appid_g),
             operation = OperationName
    KQL

    # App Configuration audit events. The Audit category records the read
    # and the target key but does not always carry a caller object id, so
    # principal_id can come back empty. That is a real gap, not a bug: an
    # unidentifiable consumer is exactly what lowers the readiness score
    # and raises SECRET_UNIDENTIFIED_CONSUMERS, so it is reported as found
    # rather than silently dropped.
    APP_CONFIG_QUERY = <<~KQL
      AACAudit
      | where TimeGenerated > ago(%<lookback>dd)
      | where OperationName has "KeyValue"
      | extend resource_id = tostring(column_ifexists("Uri", ""))
      | where isnotempty(resource_id)
      | summarize access_count = count(), last_accessed = max(TimeGenerated)
          by resource_id,
             principal_id = tostring(column_ifexists("Identity", "")),
             principal_appid = "",
             operation = OperationName
    KQL

    QUERIES = {
      "AZKVAuditLogs" => KEY_VAULT_QUERY,
      "AzureDiagnostics" => DIAGNOSTICS_QUERY,
      "AACAudit" => APP_CONFIG_QUERY
    }.freeze

    def initialize(workspace_id: Rails.configuration.x.secops.workspace_id,
                   lookback_days: Rails.configuration.x.secops.lookback_days,
                   client: Azure::Client.new(scope: :logs, timeout: 120))
      @workspace_id = workspace_id
      @lookback_days = lookback_days
      @client = client
    end

    # @return [Array<Hash>] rows with resource_id, principal_id,
    #   principal_appid, operation, access_count, last_accessed
    def access_events
      raise ArgumentError, "LOG_ANALYTICS_WORKSPACE_ID is not set" if @workspace_id.blank?

      QUERIES.flat_map do |table, template|
        rows = query(format(template, lookback: @lookback_days))
        Rails.logger.info("log analytics: #{rows.size} access rows from #{table}")
        rows
      rescue Azure::Client::Error => e
        # A workspace with no data for a table answers with a semantic
        # error rather than an empty result set. Skipping it costs the
        # consumer map one source; failing the scan costs everything.
        Rails.logger.warn("log analytics query on #{table} failed (#{e.status}), skipping")
        []
      end
    end

    def query(kql)
      body = @client.post(
        "#{API_BASE}/workspaces/#{@workspace_id}/query",
        body: { "query" => kql, "timespan" => "P#{@lookback_days}D" }
      )
      to_rows(body)
    end

    private

    # Log Analytics answers with columns and positional rows. Turning that
    # into hashes here keeps every caller free of index arithmetic.
    def to_rows(body)
      table = Array(body["tables"]).first
      return [] unless table

      names = Array(table["columns"]).map { |c| c["name"] }
      Array(table["rows"]).map { |row| names.zip(row).to_h }
    end
  end
end
