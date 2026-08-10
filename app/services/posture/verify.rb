# frozen_string_literal: true

module Posture
  # Proves the platform's least-privilege claims against the live cloud,
  # from inside the platform's own identity.
  #
  # The README asserts that this platform can read secret metadata and
  # cannot read a secret value. A role definition in Terraform is evidence
  # of intent, not of outcome: roles get widened by someone debugging at
  # 2am, inherited from a management group, or shadowed by a second
  # assignment. This turns the claim into a test that fails loudly.
  #
  # Both directions are checked on purpose. A permission that is supposed
  # to work and does not is a broken scanner; a permission that is
  # supposed to be denied and is not is a broken security story, and the
  # second is the one nobody notices.
  class Verify
    Check = Struct.new(:name, :expectation, :passed, :detail, keyword_init: true) do
      def status = passed ? "PASS" : "FAIL"
    end

    KV_API = "7.4"
    APP_CONFIG_API = "2023-11-01"
    GRAPH_BASE = "https://graph.microsoft.com/v1.0"
    BLOB_API = "2023-11-03"

    def initialize(vault_name: ENV["KEY_VAULT_NAME"],
                   app_config_endpoint: Rails.configuration.x.secops.app_config_endpoint,
                   evidence_account: Rails.configuration.x.secops.evidence_account,
                   evidence_container: Rails.configuration.x.secops.evidence_container,
                   workspace_id: Rails.configuration.x.secops.workspace_id)
      @vault_uri = "https://#{vault_name}.vault.azure.net"
      @app_config_endpoint = app_config_endpoint.to_s.chomp("/")
      @evidence_account = evidence_account
      @evidence_container = evidence_container
      @workspace_id = workspace_id
      @checks = []
    end

    def call
      secret_name = nil

      # Positive: the sweeps must work.
      secret_name = check_list_secrets
      check_list_certificates
      check_certificate_policy

      # Negative: the whole security claim. This is the important one.
      check_secret_value_denied(secret_name)

      check_app_config_metadata_only
      check_log_analytics
      check_graph_applications
      check_openai

      # Evidence immutability, both directions.
      blob = check_evidence_write
      check_evidence_overwrite_denied(blob)

      @checks
    end

    private

    def record(name, expectation, passed, detail)
      @checks << Check.new(name: name, expectation: expectation, passed: passed, detail: detail)
      passed
    end

    def kv = @kv ||= Azure::Client.new(scope: :key_vault)

    # ── positive checks ──────────────────────────────────────────────

    def check_list_secrets
      body = kv.get("#{@vault_uri}/secrets", params: { "api-version" => KV_API })
      items = Array(body["value"])
      name = items.first && Scanner::Normalize.parse_vault_object_id(items.first["id"])[:name]

      record("key_vault.list_secrets", "allowed (readMetadata)", items.any?,
             "listed #{items.size} secrets, values absent from payload: " \
             "#{items.none? { |i| i.key?('value') }}")
      name
    rescue Azure::Client::Error => e
      record("key_vault.list_secrets", "allowed (readMetadata)", false,
             "unexpected #{e.status}: Key Vault Reader should permit listing")
      nil
    end

    def check_list_certificates
      body = kv.get("#{@vault_uri}/certificates", params: { "api-version" => KV_API })
      items = Array(body["value"])
      record("key_vault.list_certificates", "allowed", items.any?,
             "listed #{items.size} certificates")
      items.first && Scanner::Normalize.parse_vault_object_id(items.first["id"])[:name]
    rescue Azure::Client::Error => e
      record("key_vault.list_certificates", "allowed", false, "unexpected #{e.status}")
      nil
    end

    # The rotation story for certificates depends on reading the issuance
    # policy, which is a separate data action from listing.
    def check_certificate_policy
      body = kv.get("#{@vault_uri}/certificates", params: { "api-version" => KV_API })
      first = Array(body["value"]).first
      return record("key_vault.certificate_policy", "allowed", false, "no certificates to test") unless first

      name = Scanner::Normalize.parse_vault_object_id(first["id"])[:name]
      policy = kv.get("#{@vault_uri}/certificates/#{name}/policy", params: { "api-version" => KV_API })

      record("key_vault.certificate_policy", "allowed", policy.key?("issuer") || policy.key?("x509_props"),
             "read issuance policy for #{name}; auto-renew detection depends on this")
    rescue Azure::Client::Error => e
      record("key_vault.certificate_policy", "allowed", false,
             "unexpected #{e.status}: certificate rotation detection is broken without this")
    end

    # ── the negative check ───────────────────────────────────────────

    # If this ever passes, the platform can read secret values and the
    # central claim in the README is false.
    def check_secret_value_denied(secret_name)
      unless secret_name
        return record("key_vault.get_secret_value", "DENIED (403)", false,
                      "could not resolve a secret name to test against")
      end

      kv.get("#{@vault_uri}/secrets/#{secret_name}", params: { "api-version" => KV_API })

      record("key_vault.get_secret_value", "DENIED (403)", false,
             "SECURITY REGRESSION: read the value of #{secret_name}. The identity holds a " \
             "role granting getSecret; the metadata-only guarantee no longer holds.")
    rescue Azure::Client::Error => e
      record("key_vault.get_secret_value", "DENIED (403)", e.status == 403,
             e.status == 403 ? "denied as designed: Key Vault Reader carries no getSecret action"
                             : "denied, but with #{e.status} rather than 403")
    end

    # ── remaining surface ────────────────────────────────────────────

    def check_app_config_metadata_only
      return record("app_config.list_no_value", "allowed, no values", false, "no endpoint configured") if @app_config_endpoint.blank?

      client = Azure::Client.new(scope: :app_config)
      body = client.get("#{@app_config_endpoint}/kv",
                        params: { "api-version" => APP_CONFIG_API,
                                  "$select" => Scanner::AppConfig::SELECT_FIELDS })
      items = Array(body["items"])
      clean = items.none? { |i| i.key?("value") && i["value"].present? }

      record("app_config.list_no_value", "allowed, no values", items.any? && clean,
             "listed #{items.size} key values; value field withheld by $select: #{clean}")
    rescue Azure::Client::Error => e
      record("app_config.list_no_value", "allowed, no values", false, "unexpected #{e.status}")
    end

    def check_log_analytics
      rows = Analyzer::LogAnalytics.new.query("AZKVAuditLogs | take 1")
      record("log_analytics.query", "allowed", true, "query returned #{rows.size} row(s)")
    rescue StandardError => e
      record("log_analytics.query", "allowed", false, "#{e.class}: #{e.message.truncate(120)}")
    end

    def check_graph_applications
      unless Rails.configuration.x.secops.graph_enabled
        return record("graph.list_applications", "allowed", true, "skipped: GRAPH_ENABLED=false")
      end

      client = Azure::Client.new(scope: :graph)
      body = client.get("#{GRAPH_BASE}/applications", params: { "$top" => 1, "$select" => "appId" })
      record("graph.list_applications", "allowed", body.key?("value"),
             "Application.Read.All grant is effective")
    rescue Azure::Client::Error => e
      record("graph.list_applications", "allowed", false, "unexpected #{e.status}")
    end

    def check_openai
      runbook = Analyzer::Runbook.new
      unless runbook.enabled?
        return record("openai.chat_completions", "allowed", true, "skipped: no endpoint configured")
      end

      # An unsaved model instance rather than a stub, so this exercises the
      # same attribute surface the analyzer builds its prompt from.
      probe = SecretRecord.new(
        name: "posture-check", kind: "key_vault_secret", vault_name: "n/a",
        age_days: 1, age_simulated: false, expires_at: nil,
        rotation_enabled: false, rotation_days: 0,
        tags: {}, access_model: { "rbac_authorization" => true, "read_principals" => [] },
        details: {}
      )

      # synthesize, not generate: generate swallows failures into the
      # rule-based fallback, which is exactly what must not be hidden here.
      result = runbook.synthesize(probe, { "consumers" => [], "total_reads" => 0 })

      record("openai.chat_completions", "allowed", result["generator"] == "azure-openai",
             "model returned a runbook that passed strict JSON validation")
    rescue StandardError => e
      record("openai.chat_completions", "allowed", false, "#{e.class}: #{e.message.truncate(140)}")
    end

    def check_evidence_write
      return record("evidence.write", "allowed", false, "no evidence account configured") if @evidence_account.blank?

      path = "posture/#{Time.now.utc.strftime('%Y%m%dT%H%M%SZ')}.json"
      client = Azure::Client.new(scope: :storage)
      client.put(blob_url(path),
                 body: JSON.generate("posture_check" => true, "at" => Time.now.utc.iso8601),
                 headers: { "x-ms-version" => BLOB_API, "x-ms-blob-type" => "BlockBlob",
                            "Content-Type" => "application/json" })

      record("evidence.write", "allowed", true, "wrote #{path}")
      path
    rescue Azure::Client::Error => e
      record("evidence.write", "allowed", false, "unexpected #{e.status}")
      nil
    end

    # The immutability policy has to actually block something, or the
    # evidence container is just a bucket with a compliance-sounding name.
    def check_evidence_overwrite_denied(path)
      unless path
        return record("evidence.overwrite_denied", "DENIED (409/412)", false, "nothing written to test")
      end

      client = Azure::Client.new(scope: :storage)
      client.put(blob_url(path),
                 body: JSON.generate("tampered" => true),
                 headers: { "x-ms-version" => BLOB_API, "x-ms-blob-type" => "BlockBlob",
                            "Content-Type" => "application/json" })

      record("evidence.overwrite_denied", "DENIED (409/412)", false,
             "EVIDENCE REGRESSION: overwrote an existing artifact; the immutability policy is not in force")
    rescue Azure::Client::Error => e
      record("evidence.overwrite_denied", "DENIED (409/412)", [409, 412].include?(e.status),
             "blocked with #{e.status} by the time based immutability policy")
    end

    def blob_url(path)
      "https://#{@evidence_account}.blob.core.windows.net/#{@evidence_container}/#{path}"
    end
  end
end
