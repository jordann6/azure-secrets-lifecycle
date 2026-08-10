# frozen_string_literal: true

module Analyzer
  # Redaction guard. Nothing in this pipeline requests a secret value, and
  # the managed identity does not hold a role that would let it. Every
  # payload headed for the logs, Postgres, the evidence blob, or Azure
  # OpenAI still passes through here as defense in depth.
  module Redact
    SENSITIVE_KEYS = /
      value|secret|password|passwd|private_key|client_secret|
      connection_?string|sas|token|credential|thumbprint_?key
    /xi

    # High entropy literals that look like key material regardless of the
    # key they arrived under.
    SUSPICIOUS_VALUE = Regexp.union(
      # Entra client secret values (the "~" separated form Azure issues).
      /\b[A-Za-z0-9_~.-]{3}8Q~[A-Za-z0-9_~.-]{30,}\b/,
      # Storage account keys are 88 char base64 ending in "==". No
      # trailing word boundary: "=" is not a word character, so \b there
      # would never match at the end of a string.
      /\b[A-Za-z0-9+\/]{86}==/,
      # Shared access signatures.
      /\bsig=[A-Za-z0-9%+\/=]{20,}/,
      # PEM private key material.
      /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
      # JWTs.
      /\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\b/,
      # Full connection strings.
      /AccountKey=[A-Za-z0-9+\/=]{20,}/
    )

    REDACTED = "[REDACTED]"

    # Keys that match SENSITIVE_KEYS but are known to hold metadata only.
    # Without this allowlist the redactor blanks the very fields the
    # analyzer scores on.
    SAFE_KEYS = %w[
      credential_kind credential_type federated_credential_count
      secret_uri_with_version token_endpoint sas_policy_enabled
    ].to_set.freeze

    module_function

    # Recursively redact suspicious keys and values. Returns a new
    # structure; the input is never mutated.
    def call(obj)
      case obj
      when Hash
        obj.each_with_object({}) do |(k, v), acc|
          acc[k] = redact_pair(k, v)
        end
      when Array
        obj.map { |v| call(v) }
      when String
        obj.gsub(SUSPICIOUS_VALUE, REDACTED)
      else
        obj
      end
    end

    # Key material is always a string. A count, a boolean, or a timestamp
    # under a key that happens to contain the word "secret" is metadata,
    # and blanking it is a silent correctness bug rather than a visible
    # one: "secrets under management: [REDACTED]" is not a safer
    # dashboard, it is a broken one. Values that are collections still
    # recurse, so nothing hides inside a nested structure.
    def redact_pair(key, value)
      return REDACTED if value.is_a?(String) && sensitive_key?(key)

      call(value)
    end

    def sensitive_key?(key)
      name = key.to_s
      return false if SAFE_KEYS.include?(name)

      SENSITIVE_KEYS.match?(name)
    end
  end
end
