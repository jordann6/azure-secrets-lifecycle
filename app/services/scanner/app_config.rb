# frozen_string_literal: true

module Scanner
  # Sweeps App Configuration key values, the Azure analogue of SSM
  # SecureString parameters.
  #
  # This is the one sweep where the platform has to work to stay metadata
  # only. App Configuration Data Reader is the narrowest built in role and
  # it does return values, so the request uses $select to ask for metadata
  # fields only and never requests `value`. That is a weaker guarantee than
  # the Key Vault Reader role gives, so it is stated plainly rather than
  # papered over, and every record still goes through the redactor.
  class AppConfig
    API_VERSION = "2023-11-01"
    KEY_VAULT_REF_CONTENT_TYPE =
      "application/vnd.microsoft.appconfig.keyvaultref+json"

    # Deliberately excludes `value`.
    SELECT_FIELDS = "key,label,content_type,last_modified,tags,locked"

    RESOURCES_API_VERSION = "2021-04-01"
    ARM_API_VERSION = "2023-03-01"

    def initialize(subscription_id:, endpoint: nil, concurrency: 4,
                   arm: Azure::Client.new(scope: :arm),
                   data: Azure::Client.new(scope: :app_config))
      @subscription_id = subscription_id
      @endpoint = endpoint
      @arm = arm
      @data = data
      @pool = Pool.new(concurrency: concurrency)
    end

    def sweep(scan_id:, now: Time.now.utc)
      stores = @endpoint.present? ? [store_from_endpoint] : list_stores
      Rails.logger.info("app configuration sweep: #{stores.size} stores")

      @pool.map(stores) { |store| sweep_store(store, scan_id, now) }
    end

    # Addressing a store directly by endpoint skips the ARM lookup, so the
    # control plane properties that lookup provides are genuinely unknown
    # rather than absent. They are filled in explicitly: a store shape
    # missing access_model produced a NOT NULL violation on insert, since
    # insert_all! writes NULL for a key some rows omit instead of falling
    # back to the column default.
    def store_from_endpoint
      {
        arm_id: nil,
        name: host_of(@endpoint),
        location: nil,
        resource_group: nil,
        endpoint: @endpoint,
        access_model: {
          "rbac_authorization" => true,
          "read_principals" => [],
          "public_network_access" => "Unknown",
          "local_auth_disabled" => nil,
          "source" => "endpoint-only; control plane properties not read"
        }
      }
    end

    def list_stores
      resources = @arm.get_paged(
        "https://management.azure.com/subscriptions/#{@subscription_id}/resources",
        params: {
          "api-version" => RESOURCES_API_VERSION,
          "$filter" => "resourceType eq 'Microsoft.AppConfiguration/configurationStores'"
        }
      )

      resources.map do |r|
        detail = @arm.get("https://management.azure.com#{r['id']}",
                          params: { "api-version" => ARM_API_VERSION })
        {
          arm_id: r["id"],
          name: r["name"],
          location: r["location"],
          resource_group: Normalize.parse_arm_id(r["id"])[:resource_group],
          endpoint: detail.dig("properties", "endpoint") || "https://#{r['name']}.azconfig.io",
          access_model: {
            "public_network_access" => detail.dig("properties", "publicNetworkAccess") || "Enabled",
            "local_auth_disabled" => detail.dig("properties", "disableLocalAuth") == true,
            "rbac_authorization" => true,
            "read_principals" => []
          }
        }
      end
    end

    private

    def sweep_store(store, scan_id, now)
      items = @data.get_paged(
        "#{store[:endpoint]}/kv",
        params: { "api-version" => API_VERSION, "$select" => SELECT_FIELDS },
        value_key: "items"
      )

      items.map do |item|
        key_vault_ref = item["content_type"].to_s.start_with?(KEY_VAULT_REF_CONTENT_TYPE)
        label = item["label"].presence
        composite = label ? "#{item['key']}$#{label}" : item["key"]

        Normalize.finish(
          {
            resource_id: "#{store[:endpoint]}/kv/#{composite}",
            name: composite,
            kind: "app_config_kv",
            subscription_id: @subscription_id,
            resource_group: store[:resource_group],
            vault_name: store[:name],
            location: store[:location],
            source_created_at: Normalize.parse_time(item["last_modified"]),
            source_updated_at: Normalize.parse_time(item["last_modified"]),
            expires_at: nil,
            enabled: item["locked"] != true,
            # A Key Vault reference does not hold the material itself: its
            # lifecycle is delegated to the referenced secret, which this
            # same scan already covers. Scoring it as unrotatable would
            # double count the risk against the wrong resource.
            rotation_enabled: key_vault_ref,
            rotation_days: 0,
            content_type: item["content_type"],
            key_vault_reference: key_vault_ref,
            access_model: store[:access_model],
            tags: item["tags"] || {}
          },
          scan_id: scan_id, now: now
        )
      end
    end

    def host_of(endpoint)
      URI.parse(endpoint).host.to_s.split(".").first
    rescue URI::InvalidURIError
      endpoint
    end
  end
end
