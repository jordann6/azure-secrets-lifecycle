# frozen_string_literal: true

module Analyzer
  # Rotation readiness scoring.
  #
  # Readiness answers one question: how safely could this be rotated
  # today? Higher is safer. It is deliberately not a risk score. A secret
  # that is nine months old and read by nothing is dangerous to keep and
  # trivial to rotate; a secret that is thirty days old and read by eleven
  # unidentified principals is the opposite. Collapsing both into "risk"
  # is what produces backlogs nobody works.
  #
  # The Azure port adds two dimensions the AWS version had no equivalent
  # for: expiry state (Key Vault objects carry an exp attribute, and CIS
  # Azure requires it) and the vault authorization model, because on an
  # RBAC vault the readable-principal set is invisible from the resource
  # itself and the observed consumer map is the only evidence there is.
  module Scoring
    BASE = 50

    module_function

    def readiness_score(record, consumer_map)
      score = BASE
      consumers = Array(consumer_map["consumers"])
      count = consumers.size

      score += rotation_component(record)
      score += consumer_count_component(count)
      score += identifiability_component(consumers)
      score += age_component(record.age_days.to_i)
      score += expiry_component(record)
      score += authorization_component(record, count)

      score.clamp(0, 100)
    end

    def risk_tier(score)
      return "high" if score <= 55
      return "medium" if score < 75

      "low"
    end

    # A verified rotation path is the single largest safety factor: an
    # auto-renewing certificate or a federated app registration can be
    # rotated without a human in the loop at all.
    def rotation_component(record)
      record.rotation_enabled? ? 25 : 0
    end

    # Zero observed consumers means rotation breaks nothing that the audit
    # log can see. It is a readiness bonus and simultaneously an orphan
    # finding, which is the correct pair: safe to rotate, and probably
    # safe to delete instead.
    def consumer_count_component(count)
      return 15 if count.zero?
      return 5 if count <= 3

      -10
    end

    def identifiability_component(consumers)
      return 0 if consumers.empty?

      identified = consumers.all? { |c| c["principal_id"].present? }
      named = consumers.all? { |c| c["display_name"].present? }

      return 10 if identified && named
      return 0 if identified

      -10
    end

    def age_component(age_days)
      return -15 if age_days > 365
      return -5 if age_days > 180

      0
    end

    # Azure specific. An object with no expiry has no forcing function and
    # no near-expiry event to automate against; one already past expiry is
    # a live incident waiting for the next cold start.
    def expiry_component(record)
      return -20 if record.expired?

      if record.expires_at.blank?
        # An Entra credential with no end date is its own, worse finding
        # (APP_CREDENTIAL_NO_FEDERATION and the lifetime check). Charging
        # it the Key Vault expiry penalty here would double count it, but
        # it must not collect the bonus either: a credential that never
        # expires is not a credential with a healthy expiry.
        return 0 if record.credential?

        return -10
      end

      return -5 if record.expires_within?(30)

      5
    end

    # Azure specific. On an access policy vault the resource names the
    # principals that can read it, so a rotation plan can be built from
    # the resource alone. On an RBAC vault it cannot, and if the audit log
    # is also silent there is no evidence of the consumer set from either
    # direction.
    def authorization_component(record, observed_count)
      return 0 unless record.kind.start_with?("key_vault")
      return 0 unless record.rbac_vault?

      observed_count.zero? ? -5 : 0
    end
  end
end
