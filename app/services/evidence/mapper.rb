# frozen_string_literal: true

module Evidence
  # Derives control mapped findings from an analyzed record.
  #
  # The finding logic decides what is true about a resource. The YAML
  # decides which framework cares. Keeping those apart is what makes it
  # possible to answer "show me every NIST IA-5 exception this quarter"
  # without touching Ruby, and to prove in a diff when the mapping last
  # changed.
  class Mapper
    MAPPINGS_PATH = Rails.root.join("config/control-mappings.yaml")

    def self.mappings
      @mappings ||= YAML.safe_load_file(MAPPINGS_PATH, permitted_classes: [], aliases: true)
    end

    def self.reset!
      @mappings = nil
    end

    def initialize(mappings: self.class.mappings, now: Time.now.utc)
      @mappings = mappings
      @now = now
    end

    def thresholds
      @mappings.fetch("thresholds")
    end

    # @return [Array<Hash>] finding attribute hashes, ready to insert
    def derive(record, analysis)
      types(record, analysis).map { |type| build(type, record, analysis) }
    end

    private

    def types(record, analysis)
      list = record.credential? ? credential_types(record) : secret_types(record)
      list.concat(consumer_types(analysis))
      list.concat(vault_types(record))
      list.uniq
    end

    def secret_types(record)
      t = thresholds
      out = []

      out << "SECRET_STALE" if record.age_days.to_i > t["stale_age_days"] && !record.rotation_enabled?
      out << "SECRET_NO_ROTATION_CONFIG" unless record.rotation_enabled?

      # Expiry findings only apply to Key Vault objects. An App
      # Configuration key value has no exp attribute to set, so claiming
      # the control fails there would be a false positive an auditor
      # would rightly reject.
      if record.kind.start_with?("key_vault")
        if record.expires_at.blank?
          out << "SECRET_NO_EXPIRY"
        elsif record.expired?
          out << "SECRET_EXPIRED"
        elsif record.expires_within?(t["expiring_soon_days"])
          out << "SECRET_EXPIRING_SOON"
        end
      end

      out
    end

    def credential_types(record)
      t = thresholds
      out = []

      out << "APP_CREDENTIAL_STALE" if record.age_days.to_i > t["credential_stale_age_days"]
      out << "APP_CREDENTIAL_LONG_LIVED" if record.rotation_days.to_i > t["max_credential_lifetime_days"]
      out << "SECRET_EXPIRED" if record.expired?
      out << "APP_CREDENTIAL_NO_FEDERATION" if record.details["federated_credential_count"].to_i.zero?

      out
    end

    def consumer_types(analysis)
      return ["SECRET_ORPHANED"] if analysis.orphaned?
      return ["SECRET_UNIDENTIFIED_CONSUMERS"] if analysis.unidentified?

      []
    end

    def vault_types(record)
      return [] unless record.kind.start_with?("key_vault")

      out = []
      out << "VAULT_PURGE_PROTECTION_DISABLED" unless record.access_model["purge_protection"]
      out << "VAULT_PUBLIC_NETWORK_ACCESS" if record.access_model["public_network_access"] == "Enabled"
      out
    end

    def build(type, record, analysis)
      meta = @mappings.fetch("findings").fetch(type)
      controls = meta.fetch("controls").map { |c| @mappings.fetch("frameworks").fetch(c) }

      {
        finding_id: "secops-#{fingerprint(record, type)}",
        finding_type: type,
        title: meta.fetch("title"),
        severity: meta.fetch("severity"),
        control_ids: controls,
        resource_id: record.resource_id,
        evidence_timestamp: @now,
        remediation_status: "OPEN",
        owner_tag: record.owner_tag,
        readiness_score: analysis.readiness_score
      }
    end

    # Stable within a scan and distinct across scans, so the same finding
    # on the same resource can be tracked over time without colliding with
    # this run's copy.
    def fingerprint(record, type)
      Digest::SHA256.hexdigest("#{record.resource_id}|#{type}|#{record.scan.scan_id}")[0, 16]
    end
  end
end
