# frozen_string_literal: true

module Analyzer
  # The numbers the dashboard shows and the evidence artifact carries.
  #
  # Kept in one class rather than scattered across the view so that the
  # figure on the screen and the figure in the auditor's JSON are the same
  # figure, computed once.
  class Metrics
    def initialize(scan, analyses, findings)
      @scan = scan
      @analyses = analyses
      @findings = findings
    end

    def call
      ages = @analyses.map { |a| a[:record].age_days.to_i }

      {
        "total_resources" => @analyses.size,
        "total_secrets" => secrets.size,
        "total_credentials" => credentials.size,
        "by_kind" => @analyses.group_by { |a| a[:record].kind }.transform_values(&:size),
        "mean_age_days" => ages.any? ? (ages.sum.to_f / ages.size).round(1) : 0,
        "median_age_days" => median(ages),
        "pct_with_identified_consumers" => percentage(with_identified_consumers.size, secrets.size),
        "pct_with_verified_rotation_path" => percentage(with_verified_path.size, secrets.size),
        "pct_with_expiry_set" => percentage(with_expiry.size, key_vault_objects.size),
        "expired_count" => @analyses.count { |a| a[:record].expired? },
        "simulated_age_count" => @analyses.count { |a| a[:record].age_simulated? },
        "orphaned_count" => @analyses.count { |a| Array(a[:consumer_map]["consumers"]).empty? },
        "risk_tiers" => tally(@analyses.map { |a| a[:risk_tier] }, %w[low medium high]),
        "runbooks_generated" => @analyses.count { |a| a[:runbook] },
        "runbooks_by_generator" => @analyses.filter_map { |a| a[:runbook]&.dig("generator") }.tally,
        "finding_count" => @findings.size,
        "findings_by_severity" => tally(@findings.map { |f| f[:severity] }, %w[HIGH MEDIUM LOW]),
        "findings_by_control" => @findings.flat_map { |f| f[:control_ids] }.tally,
        "findings_by_type" => @findings.map { |f| f[:finding_type] }.tally,
        "resources_with_findings" => @findings.map { |f| f[:resource_id] }.uniq.size,
        "scan_duration_seconds" => @scan.duration_seconds,
        "resources_per_second" => @scan.secrets_per_second
      }
    end

    private

    # Entra credentials are counted separately throughout. Folding them
    # into the secret denominators would make "percent with a verified
    # rotation path" quietly measure two different things at once.
    def secrets
      @secrets ||= @analyses.reject { |a| a[:record].credential? }
    end

    def credentials
      @credentials ||= @analyses.select { |a| a[:record].credential? }
    end

    def key_vault_objects
      @key_vault_objects ||= @analyses.select { |a| a[:record].kind.start_with?("key_vault") }
    end

    def with_identified_consumers
      secrets.select do |a|
        consumers = Array(a[:consumer_map]["consumers"])
        consumers.any? && consumers.all? { |c| c["principal_id"].present? }
      end
    end

    # A rotation path counts as verified when the resource rotates itself,
    # or when a runbook exists that names its consumers with at least
    # medium confidence. A high confidence runbook nobody has run is still
    # a plan; an auto-renewing certificate needs no plan at all.
    def with_verified_path
      secrets.select do |a|
        a[:record].rotation_enabled? ||
          %w[medium high].include?(a[:runbook]&.dig("confidence"))
      end
    end

    def with_expiry
      key_vault_objects.select { |a| a[:record].expires_at.present? }
    end

    def percentage(numerator, denominator)
      return 0.0 if denominator.zero?

      (100.0 * numerator / denominator).round(1)
    end

    def median(values)
      return 0 if values.empty?

      sorted = values.sort
      mid = sorted.size / 2
      sorted.size.odd? ? sorted[mid] : ((sorted[mid - 1] + sorted[mid]) / 2.0).round(1)
    end

    # Keeps zero buckets in the output so a chart does not silently drop a
    # category between scans.
    def tally(values, keys)
      counted = values.tally
      keys.index_with { |k| counted.fetch(k, 0) }
    end
  end
end
