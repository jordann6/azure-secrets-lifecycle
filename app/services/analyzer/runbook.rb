# frozen_string_literal: true

module Analyzer
  # Rotation runbook synthesis via Azure OpenAI.
  #
  # Inputs are the observed consumer map, the vault authorization model,
  # and the expiry state for one high risk resource. The model is asked
  # for strict JSON, the response format is pinned to json_object so the
  # service enforces it too, and the parse is validated against a required
  # key set with one retry.
  #
  # The call authenticates with the same managed identity as everything
  # else through the Cognitive Services OpenAI User role. There is no API
  # key anywhere in this project, which is the least a secrets hygiene
  # platform can do.
  #
  # If the model is unreachable, unauthorized, or answers with something
  # that will not validate, the analyzer falls back to a deterministic
  # rule based runbook labeled generator=fallback. A scan run in a
  # subscription with no Azure OpenAI quota still produces a complete,
  # auditable result; it just produces a duller one.
  class Runbook
    # The GPT-5 series rejects the classic `max_tokens` and non-default
    # `temperature`, and needs an API version new enough to know about
    # `max_completion_tokens`.
    API_VERSION = "2025-04-01-preview"
    MAX_TOKENS = 4000
    ATTEMPTS = 2

    REQUIRED_KEYS = %w[resource_name steps rollback confidence confidence_rationale].freeze
    CONFIDENCE_LEVELS = %w[low medium high].freeze

    SYSTEM_PROMPT = <<~TEXT.freeze
      You are a cloud security engineer producing a rotation runbook for one
      Azure credential. Base every step on the observed consumer map: name the
      actual consumers by display name where one is known and by object id
      otherwise, order the steps so consumers move to the new version before
      the old one is invalidated, and keep the rollback path concrete.

      Confidence reflects how completely the consumers are identified. Unknown
      principals, zero observed consumers on an RBAC vault, or an App
      Configuration key whose audit log carries no caller identity all lower
      confidence. Do not invent consumers that are not in the input.

      Return strict JSON only, with exactly this shape:
      {"resource_name": string,
       "steps": [{"order": integer, "action": string, "verification": string}],
       "rollback": [string],
       "confidence": "low" | "medium" | "high",
       "confidence_rationale": string}
    TEXT

    class ParseError < StandardError; end

    def initialize(endpoint: Rails.configuration.x.secops.openai_endpoint,
                   deployment: Rails.configuration.x.secops.openai_deployment,
                   client: nil)
      @endpoint = endpoint.to_s.chomp("/")
      @deployment = deployment
      @client = client
    end

    def enabled?
      @endpoint.present?
    end

    # Always returns a runbook. Never raises: the caller has already
    # decided this resource deserves one, and a missing runbook is a worse
    # outcome than a rule derived one.
    def generate(record, consumer_map)
      return build_fallback(record, consumer_map) unless enabled?

      synthesize(record, consumer_map)
    rescue StandardError => e
      Rails.logger.warn(
        "azure openai runbook failed for #{record.name}, using rule based fallback: " \
        "#{e.class}: #{e.message}"
      )
      build_fallback(record, consumer_map)
    end

    def synthesize(record, consumer_map)
      context = Redact.call(prompt_context(record, consumer_map))
      last_error = nil

      ATTEMPTS.times do
        text = complete(context)
        begin
          return validate(text).merge("generator" => "azure-openai", "model" => @deployment)
        rescue ParseError, JSON::ParserError => e
          last_error = e
        end
      end

      raise ParseError, "runbook parse failed after #{ATTEMPTS} attempts: #{last_error&.message}"
    end

    # The deterministic path. Same shape as the synthesized runbook so the
    # dashboard, the evidence artifact, and the Sentinel row do not need a
    # branch anywhere downstream.
    def build_fallback(record, consumer_map)
      consumers = Array(consumer_map["consumers"])
      identified = consumers.select { |c| c["principal_id"].present? }
      steps = []
      order = 0

      steps << step(order += 1, *create_step(record))

      identified.each do |consumer|
        label = consumer["display_name"].presence || consumer["principal_id"]
        steps << step(order += 1,
                      "Point consumer #{label} at the new version",
                      "Reads by #{label} succeed against the new version with no 403 or 404 in the audit log")
      end

      if consumers.empty?
        steps << step(order += 1,
                      "No consumers observed in the #{lookback} day window; confirm with the owner tag " \
                      "(#{record.owner_tag}) before invalidating",
                      "Owner acknowledges in writing that the credential is unused")
      elsif identified.empty?
        steps << step(order += 1,
                      "Consumers were observed but no caller identity was recorded; enable the Audit " \
                      "diagnostic category on the source and re-run the scan before proceeding",
                      "A follow up scan returns consumers with a populated principal id")
      end

      steps << step(order += 1, *promote_step(record))

      if record.expires_at.blank?
        steps << step(order += 1,
                      "Set an expiry date on the new version so near-expiry automation has something to fire on",
                      "The object reports a non null exp attribute")
      end

      {
        "resource_name" => record.name,
        "steps" => steps,
        "rollback" => rollback_for(record),
        "confidence" => fallback_confidence(consumers, identified),
        "confidence_rationale" => fallback_rationale(consumers, identified),
        "generator" => "fallback"
      }
    end

    private

    def lookback
      Rails.configuration.x.secops.lookback_days
    end

    def step(order, action, verification)
      { "order" => order, "action" => action, "verification" => verification }
    end

    def create_step(record)
      case record.kind
      when "key_vault_certificate"
        ["Issue a new version of certificate #{record.name} in vault #{record.vault_name}, leaving the current version enabled",
         "The new version is listed and enabled alongside the current one"]
      when "entra_app_credential"
        ["Add a second credential to app registration #{record.details['app_id']} without removing the existing one",
         "The app registration lists two valid credentials"]
      when "app_config_kv"
        ["Create the replacement value under a new label on key #{record.name}, leaving the current label in place",
         "Both labels resolve and return distinct values"]
      else
        ["Create a new version of secret #{record.name} in vault #{record.vault_name}, leaving the current version enabled",
         "The new version is listed and enabled alongside the current one"]
      end
    end

    def promote_step(record)
      case record.kind
      when "entra_app_credential"
        ["Remove the old credential from the app registration",
         "No authentication failures for one full token lifetime"]
      else
        ["Disable the previous version once every consumer is confirmed on the new one",
         "No read failures for one full consumer access cycle"]
      end
    end

    def rollback_for(record)
      if record.credential?
        ["Re-add the previous credential to the app registration",
         "Revert consumer configuration to the previous credential",
         "Confirm token acquisition succeeds for every affected workload"]
      else
        ["Re-enable the previous version, which soft delete retains for the vault's retention window",
         "Revert consumer configuration to the previous version",
         "Confirm reads succeed against the restored version in the audit log"]
      end
    end

    def fallback_confidence(consumers, identified)
      return "low" if consumers.any? && identified.empty?
      return "medium" if consumers.empty?

      "medium"
    end

    def fallback_rationale(consumers, identified)
      if consumers.any? && identified.empty?
        "Consumers were observed but no caller identity was recorded, so the consumer set is unverified"
      elsif consumers.empty?
        "No consumers observed in the lookback window, so rotation carries low outage risk"
      else
        "All observed consumers are identified; the steps are rule derived rather than synthesized"
      end
    end

    def prompt_context(record, consumer_map)
      {
        "resource_name" => record.name,
        "kind" => record.kind,
        "vault_name" => record.vault_name,
        "age_days" => record.age_days,
        "age_simulated" => record.age_simulated,
        "expires_at" => record.expires_at&.iso8601,
        "expired" => record.expired?,
        "rotation_enabled" => record.rotation_enabled,
        "rotation_days" => record.rotation_days,
        "authorization_model" => record.rbac_vault? ? "rbac" : "access-policy",
        "policy_read_principals" => record.policy_principals,
        "owner_tag" => record.owner_tag,
        "lookback_days" => lookback,
        "consumer_map" => consumer_map
      }
    end

    def complete(context)
      body = client.post(
        "#{@endpoint}/openai/deployments/#{@deployment}/chat/completions",
        params: { "api-version" => API_VERSION },
        body: {
          "messages" => [
            { "role" => "system", "content" => SYSTEM_PROMPT },
            { "role" => "user", "content" => JSON.generate(context) }
          ],
          # Newer deployments count reasoning tokens against this budget,
          # so it is set well above what the runbook JSON itself needs.
          "max_completion_tokens" => MAX_TOKENS,
          "response_format" => { "type" => "json_object" }
        }
      )

      body.dig("choices", 0, "message", "content").to_s
    end

    def client
      @client ||= Azure::Client.new(scope: :openai, timeout: 90)
    end

    def validate(text)
      parsed = JSON.parse(strip_fences(text))
      raise ParseError, "runbook is not a JSON object" unless parsed.is_a?(Hash)

      missing = REQUIRED_KEYS - parsed.keys
      raise ParseError, "runbook missing #{missing.join(', ')}" if missing.any?

      unless CONFIDENCE_LEVELS.include?(parsed["confidence"])
        raise ParseError, "invalid confidence #{parsed['confidence'].inspect}"
      end

      steps = parsed["steps"]
      raise ParseError, "runbook has no steps" unless steps.is_a?(Array) && steps.any?

      steps.each do |s|
        missing_step = %w[order action verification] - s.keys
        raise ParseError, "step missing #{missing_step.join(', ')}" if missing_step.any?
      end

      parsed
    end

    # response_format pins the service to JSON, but a deployment on an
    # older API version silently ignores it and fences the object.
    def strip_fences(text)
      stripped = text.strip
      return stripped unless stripped.start_with?("```")

      inner = stripped.delete_prefix("```json").delete_prefix("```").delete_suffix("```")
      inner.strip
    end
  end
end
