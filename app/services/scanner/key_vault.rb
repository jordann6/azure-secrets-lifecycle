# frozen_string_literal: true

module Scanner
  # Sweeps Key Vault secrets and certificates.
  #
  # Metadata only, and structurally so. The listing endpoints
  # (GET /secrets, GET /certificates) return attributes, tags, and content
  # type but never the value; reading a value requires GET /secrets/{name}
  # which this code does not call and which the managed identity's
  # Key Vault Reader role does not permit. Both halves matter: the role
  # makes it impossible, the code makes it obvious.
  class KeyVault
    API_VERSION = "7.4"
    ARM_API_VERSION = "2023-07-01"
    RESOURCES_API_VERSION = "2021-04-01"

    def initialize(subscription_id:, concurrency: 8,
                   arm: Azure::Client.new(scope: :arm),
                   data: Azure::Client.new(scope: :key_vault))
      @subscription_id = subscription_id
      @arm = arm
      @data = data
      @pool = Pool.new(concurrency: concurrency)
    end

    # @return [Scanner::Pool::Result] records plus per-vault errors
    def sweep(scan_id:, now: Time.now.utc)
      vaults = list_vaults
      Rails.logger.info("key vault sweep: #{vaults.size} vaults in subscription")

      @pool.map(vaults) do |vault|
        secrets = sweep_secrets(vault, scan_id, now)
        certs = sweep_certificates(vault, scan_id, now)
        secrets + certs
      end
    end

    # Vault control plane properties are the Azure analogue of an AWS
    # resource policy: who is allowed to read, and by which model.
    def list_vaults
      resources = @arm.get_paged(
        "https://management.azure.com/subscriptions/#{@subscription_id}/resources",
        params: {
          "api-version" => RESOURCES_API_VERSION,
          "$filter" => "resourceType eq 'Microsoft.KeyVault/vaults'"
        }
      )

      resources.map do |r|
        detail = @arm.get("https://management.azure.com#{r['id']}",
                          params: { "api-version" => ARM_API_VERSION })
        props = detail["properties"] || {}
        {
          arm_id: r["id"],
          name: r["name"],
          location: r["location"],
          resource_group: Normalize.parse_arm_id(r["id"])[:resource_group],
          vault_uri: props["vaultUri"] || "https://#{r['name']}.vault.azure.net",
          access_model: access_model(props)
        }
      end
    end

    private

    # RBAC vaults carry no access policy list, so the readable-principal
    # set has to come from role assignments instead. Access policy vaults
    # name their principals inline, which is the closer match to a resource
    # policy and the cheaper one to read.
    def access_model(props)
      policies = Array(props["accessPolicies"]).filter_map do |p|
        perms = Array(p.dig("permissions", "secrets")) + Array(p.dig("permissions", "certificates"))
        readers = perms.map(&:downcase) & %w[get list all]
        next if readers.empty?

        { "object_id" => p["objectId"], "tenant_id" => p["tenantId"], "permissions" => perms }
      end

      {
        "rbac_authorization" => props["enableRbacAuthorization"] == true,
        "purge_protection" => props["enablePurgeProtection"] == true,
        "soft_delete_retention_days" => props["softDeleteRetentionInDays"],
        "public_network_access" => props["publicNetworkAccess"] || "Enabled",
        "read_principals" => policies
      }
    end

    def sweep_secrets(vault, scan_id, now)
      items = @data.get_paged("#{vault[:vault_uri]}/secrets",
                              params: { "api-version" => API_VERSION })

      items.map do |item|
        parsed = Normalize.parse_vault_object_id(item["id"])
        attrs = item["attributes"] || {}
        expires_at = Normalize.parse_time(attrs["exp"])

        Normalize.finish(
          {
            resource_id: parsed[:base_id],
            name: parsed[:name],
            kind: "key_vault_secret",
            subscription_id: @subscription_id,
            resource_group: vault[:resource_group],
            vault_name: vault[:name],
            location: vault[:location],
            source_created_at: Normalize.parse_time(attrs["created"]),
            source_updated_at: Normalize.parse_time(attrs["updated"]),
            expires_at: expires_at,
            enabled: attrs.fetch("enabled", true),
            # Key Vault secrets have no native rotation engine the way a
            # Secrets Manager secret does. An expiry date is the closest
            # honest signal that something owns this secret's lifecycle:
            # it is what Event Grid near-expiry automation keys off, and
            # what CIS Azure 8.4 requires. Recorded as a managed lifecycle,
            # not claimed as automatic rotation.
            rotation_enabled: expires_at.present?,
            rotation_days: rotation_window(attrs, expires_at),
            content_type: item["contentType"],
            managed: item["managed"] == true,
            access_model: vault[:access_model],
            tags: item["tags"] || {}
          },
          scan_id: scan_id, now: now
        )
      end
    end

    # Certificates do have a real rotation engine: a lifetime action of
    # AutoRenew on the issuance policy. That is the true Secrets Manager
    # rotation analogue in Key Vault, so it is read per certificate.
    def sweep_certificates(vault, scan_id, now)
      items = @data.get_paged("#{vault[:vault_uri]}/certificates",
                              params: { "api-version" => API_VERSION })

      items.map do |item|
        parsed = Normalize.parse_vault_object_id(item["id"])
        attrs = item["attributes"] || {}
        policy = fetch_policy(vault, parsed[:name])
        auto_renew = Array(policy["lifetime_actions"]).any? do |a|
          a.dig("action", "action_type") == "AutoRenew"
        end

        Normalize.finish(
          {
            resource_id: parsed[:base_id],
            name: parsed[:name],
            kind: "key_vault_certificate",
            subscription_id: @subscription_id,
            resource_group: vault[:resource_group],
            vault_name: vault[:name],
            location: vault[:location],
            source_created_at: Normalize.parse_time(attrs["created"]),
            source_updated_at: Normalize.parse_time(attrs["updated"]),
            expires_at: Normalize.parse_time(attrs["exp"]),
            enabled: attrs.fetch("enabled", true),
            rotation_enabled: auto_renew,
            rotation_days: certificate_rotation_days(policy),
            issuer: policy.dig("issuer", "name"),
            access_model: vault[:access_model],
            tags: item["tags"] || {}
          },
          scan_id: scan_id, now: now
        )
      end
    end

    def fetch_policy(vault, name)
      @data.get("#{vault[:vault_uri]}/certificates/#{name}/policy",
                params: { "api-version" => API_VERSION })
    rescue Azure::Client::Error => e
      # A certificate imported without a policy returns 404. Not fatal, and
      # not a rotation path either, so it stays absent rather than guessed.
      Rails.logger.debug("no policy for certificate #{name}: #{e.status}")
      {}
    end

    def certificate_rotation_days(policy)
      months = policy.dig("x509_props", "validity_months")
      months ? (months.to_i * 30) : 0
    end

    def rotation_window(attrs, expires_at)
      created = Normalize.parse_time(attrs["created"])
      return 0 unless created && expires_at

      ((expires_at - created) / 86_400).floor
    end
  end
end
