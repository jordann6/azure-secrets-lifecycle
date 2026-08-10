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

    # Resource specific Key Vault audit table, which is what a vault with
    # log_analytics_destination_type = "Dedicated" writes to.
    #
    # Three things about this schema are easy to get wrong and were all
    # found against a real workspace rather than from the docs:
    #
    #   - The object uri is in RequestUri. There is no id_s column here;
    #     that one belongs to the legacy AzureDiagnostics shape below.
    #   - RequestUri carries the data plane port, as
    #     https://vault.vault.azure.net:8443/secrets/name. The inventory
    #     records no port, so it has to be stripped or nothing matches.
    #   - Caller claims are a JSON blob in Identity, not flattened into
    #     identity_claim_oid_g / identity_claim_appid_g columns.
    KEY_VAULT_QUERY = <<~KQL
      AZKVAuditLogs
      | where TimeGenerated > ago(%<lookback>dd)
      | where OperationName in ("SecretGet", "CertificateGet", "KeyGet")
      | where ResultSignature == "OK"
      | extend parsed = parse_url(tostring(RequestUri))
      | extend segments = split(tostring(parsed["Path"]), "/")
      | extend host = tostring(split(tostring(parsed["Host"]), ":")[0])
      | where isnotempty(tostring(segments[2]))
      | extend resource_id = strcat("https://", host, "/",
                                    tostring(segments[1]), "/", tostring(segments[2]))
      | extend claim = parse_json(tostring(Identity))["claim"]
      | summarize access_count = count(), last_accessed = max(TimeGenerated)
          by resource_id,
             principal_id = tostring(claim["oid"]),
             principal_appid = tostring(claim["appid"]),
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

    # App Configuration audit events.
    #
    # Restricted to reads. AACAudit records writes too (set-keyvalue), and
    # counting the operator who created a key as one of its consumers
    # would be worse than reporting no consumers at all: it would turn an
    # orphaned key into one that looks actively used.
    #
    # The target uri percent encodes the separators in a hierarchical key,
    # so secops-test/app/db-conn arrives as secops-test%2Fapp%2Fdb-conn.
    # Decoding it here is what lets the inventory side match on key name.
    #
    # Caller identity is an array of typed entries rather than a claims
    # object, and only the ObjectId entry is the principal. When it is
    # absent the consumer stays unidentified, which is a real finding
    # rather than a gap to paper over.
    APP_CONFIG_QUERY = <<~KQL
      AACAudit
      | where TimeGenerated > ago(%<lookback>dd)
      | where OperationName has "get" and OperationName has "keyvalue"
      | where ResultType == "Success"
      | extend target = parse_json(tostring(TargetResource))
      | extend parsed = parse_url(url_decode(tostring(target["TargetResourceName"])))
      | extend host = tostring(split(tostring(parsed["Host"]), ":")[0])
      | where isnotempty(host)
      | extend resource_id = strcat("https://", host, tostring(parsed["Path"]))
      | mv-apply entry = parse_json(tostring(CallerIdentity)) on (
          where tostring(entry["callerIdentityType"]) == "ObjectId"
          | project caller_oid = tostring(entry["callerIdentity"])
        )
      | summarize access_count = count(), last_accessed = max(TimeGenerated)
          by resource_id,
             principal_id = caller_oid,
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
