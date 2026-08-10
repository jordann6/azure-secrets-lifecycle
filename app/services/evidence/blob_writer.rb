# frozen_string_literal: true

module Evidence
  # Writes the per scan evidence artifact to Blob Storage.
  #
  # The container carries blob versioning plus a time based immutability
  # policy, which is the Azure equivalent of S3 Object Lock in governance
  # mode: the write succeeds, the overwrite and the delete do not, until
  # the retention window expires. The policy is created unlocked on
  # purpose. A locked policy cannot be shortened or removed by anyone
  # including the subscription owner, which is correct for a real
  # compliance program and fatal for a portfolio project that has to
  # terraform destroy cleanly. That tradeoff is called out in the README
  # rather than hidden here.
  class BlobWriter
    API_VERSION = "2023-11-03"

    def initialize(account: Rails.configuration.x.secops.evidence_account,
                   container: Rails.configuration.x.secops.evidence_container,
                   client: Azure::Client.new(scope: :storage, timeout: 60))
      @account = account
      @container = container
      @client = client
    end

    def enabled?
      @account.present?
    end

    # @return [String, nil] the blob path written, or nil when no evidence
    #   account is configured
    def write(scan, findings, metrics)
      return nil unless enabled?

      path = "evidence/#{scan.scan_id}/evidence.json"
      body = JSON.pretty_generate(artifact(scan, findings, metrics))

      @client.put(
        "https://#{@account}.blob.core.windows.net/#{@container}/#{path}",
        body: body,
        headers: {
          "x-ms-version" => API_VERSION,
          "x-ms-blob-type" => "BlockBlob",
          "Content-Type" => "application/json",
          # Recorded on the blob so an artifact pulled out of the
          # container years later still says which mapping produced it.
          "x-ms-meta-scanid" => scan.scan_id,
          "x-ms-meta-mappingversion" => Mapper.mappings["version"].to_s
        }
      )

      Rails.logger.info("evidence artifact written to #{@container}/#{path}")
      path
    end

    # The artifact is self describing on purpose. Someone reading it in an
    # audit two years from now has no access to this codebase.
    def artifact(scan, findings, metrics)
      Analyzer::Redact.call(
        "schema" => "secops.evidence/v1",
        "cloud" => "azure",
        "scan_id" => scan.scan_id,
        "subscription_id" => Rails.configuration.x.secops.subscription_id,
        "generated_at" => Time.now.utc.iso8601,
        "scan_started_at" => scan.started_at&.iso8601,
        "scan_duration_ms" => scan.duration_ms,
        "control_mapping_version" => Mapper.mappings["version"],
        "lookback_days" => Rails.configuration.x.secops.lookback_days,
        "sweep_errors" => scan.sweep_errors,
        "metrics" => metrics,
        "findings" => findings.map { |f| serialize(f) }
      )
    end

    private

    def serialize(finding)
      {
        "finding_id" => finding[:finding_id],
        "finding_type" => finding[:finding_type],
        "title" => finding[:title],
        "severity" => finding[:severity],
        "control_ids" => finding[:control_ids],
        "resource_id" => finding[:resource_id],
        "evidence_timestamp" => finding[:evidence_timestamp]&.iso8601,
        "remediation_status" => finding[:remediation_status],
        "owner_tag" => finding[:owner_tag],
        "readiness_score" => finding[:readiness_score]
      }
    end
  end
end
