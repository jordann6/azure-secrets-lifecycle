# frozen_string_literal: true

module Scanner
  # Every sweep produces the same record shape regardless of which Azure
  # service it came from. Keeping normalization in one place is what lets
  # the analyzer score a Key Vault secret, an App Configuration key value,
  # and an Entra app registration password with the same code path.
  module Normalize
    SIMULATED_AGE_TAG = "secops:simulated-age-days"

    KINDS = %w[
      key_vault_secret
      key_vault_certificate
      app_config_kv
      entra_app_credential
    ].freeze

    module_function

    # Fills in the derived fields and returns the record ready to persist.
    #
    # Real creation dates cannot be backdated in Azure any more than they
    # can in AWS, so seeded resources carry a simulated age tag. Records
    # built from it are flagged, so demo data is never mistaken for real
    # telemetry on the dashboard or in an evidence artifact.
    def finish(record, scan_id:, now: Time.now.utc)
      record = record.symbolize_keys
      tags = (record[:tags] || {}).transform_keys(&:to_s)

      simulated = tags[SIMULATED_AGE_TAG]
      if simulated.present? && simulated.to_s.match?(/\A\d+\z/)
        age_days = simulated.to_i
        age_simulated = true
      else
        created = record[:source_created_at]
        age_days = created ? ((now - created.to_time) / 86_400).floor : 0
        age_simulated = false
      end

      record.merge(
        scan_id: scan_id,
        tags: tags,
        age_days: [age_days, 0].max,
        age_simulated: age_simulated,
        scanned_at: now
      )
    end

    # Key Vault object ids look like
    #   https://vault-name.vault.azure.net/secrets/db-primary/8f3a...
    # The version suffix is optional and is dropped: the platform tracks
    # the logical secret, not one version of it.
    def parse_vault_object_id(object_id)
      uri = URI.parse(object_id)
      _, collection, name, _version = uri.path.split("/")
      {
        vault_name: uri.host.to_s.split(".").first,
        collection: collection,
        name: name,
        base_id: "#{uri.scheme}://#{uri.host}/#{collection}/#{name}"
      }
    rescue URI::InvalidURIError
      { vault_name: nil, collection: nil, name: object_id, base_id: object_id }
    end

    # ARM ids are /subscriptions/{s}/resourceGroups/{g}/providers/{p}/{type}/{n}
    def parse_arm_id(arm_id)
      parts = arm_id.to_s.split("/")
      {
        subscription_id: parts[2],
        resource_group: parts[4],
        name: parts.last
      }
    end

    # Azure hands back epoch seconds on the Key Vault data plane and ISO
    # 8601 everywhere else.
    def parse_time(value)
      return nil if value.blank?
      return Time.at(value).utc if value.is_a?(Numeric)
      return Time.at(value.to_i).utc if value.to_s.match?(/\A\d{9,11}\z/)

      Time.parse(value.to_s).utc
    rescue ArgumentError, TypeError
      nil
    end
  end
end
