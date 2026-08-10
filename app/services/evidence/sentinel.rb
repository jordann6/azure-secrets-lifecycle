# frozen_string_literal: true

module Evidence
  # Pushes findings into Microsoft Sentinel through the Logs Ingestion API.
  #
  # This is the Security Hub BatchImportFindings analogue, and the plumbing
  # is genuinely different rather than renamed. There is no "import a
  # finding" call in Azure. Instead the findings land in a custom Log
  # Analytics table through a data collection endpoint and a data
  # collection rule, and Sentinel consumes that table like any other
  # source: analytics rules, workbooks, and hunting queries all work
  # against it with no extra wiring.
  #
  # The tradeoff versus ASFF is that the schema is the project's own
  # rather than an industry one, so the DCR transform in Terraform is
  # where the contract lives.
  class Sentinel
    API_VERSION = "2023-01-01"
    # The ingestion API caps a request at 1 MB. Findings are small, so
    # batching by count stays well inside that without measuring bytes.
    BATCH_SIZE = 500

    def initialize(dce_endpoint: Rails.configuration.x.secops.dce_endpoint,
                   dcr_immutable_id: Rails.configuration.x.secops.dcr_immutable_id,
                   stream: Rails.configuration.x.secops.dcr_stream,
                   enabled: Rails.configuration.x.secops.sentinel_enabled,
                   client: Azure::Client.new(scope: :monitor, timeout: 60))
      @dce_endpoint = dce_endpoint.to_s.chomp("/")
      @dcr_immutable_id = dcr_immutable_id
      @stream = stream
      @enabled = enabled
      @client = client
    end

    def enabled?
      @enabled && @dce_endpoint.present? && @dcr_immutable_id.present?
    end

    # @return [Integer] rows accepted by the ingestion endpoint
    def push(scan, findings)
      return 0 unless enabled?
      return 0 if findings.empty?

      rows = findings.map { |f| row(scan, f) }
      sent = 0

      rows.each_slice(BATCH_SIZE) do |batch|
        @client.post(
          "#{@dce_endpoint}/dataCollectionRules/#{@dcr_immutable_id}/streams/#{@stream}",
          params: { "api-version" => API_VERSION },
          body: batch
        )
        sent += batch.size
      end

      Rails.logger.info("sentinel: #{sent} findings ingested into #{@stream}")
      sent
    rescue Azure::Client::Error => e
      # Export is a downstream nicety. A scan that produced evidence and a
      # dashboard has done its job even if Sentinel is misconfigured, so
      # this reports zero rather than failing the run.
      Rails.logger.error("sentinel ingestion failed (#{e.status}): #{e.message}")
      0
    end

    private

    # Column names match the custom table schema declared in Terraform.
    # TimeGenerated is required by the platform; everything else is the
    # project's contract.
    def row(scan, finding)
      {
        "TimeGenerated" => finding[:evidence_timestamp].utc.iso8601,
        "ScanId" => scan.scan_id,
        "FindingId" => finding[:finding_id],
        "FindingType" => finding[:finding_type],
        "Title" => finding[:title],
        "Severity" => finding[:severity],
        "ControlIds" => finding[:control_ids],
        "ResourceId" => finding[:resource_id],
        "SubscriptionId" => Rails.configuration.x.secops.subscription_id.to_s,
        "OwnerTag" => finding[:owner_tag],
        "ReadinessScore" => finding[:readiness_score].to_i,
        "RemediationStatus" => finding[:remediation_status]
      }
    end
  end
end
