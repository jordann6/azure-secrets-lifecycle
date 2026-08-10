# frozen_string_literal: true

module DashboardHelper
  TIER_ORDER = %w[low medium high].freeze
  SEVERITY_ORDER = %w[HIGH MEDIUM LOW].freeze

  AGE_BUCKETS = [
    [0, 90, "0 to 90d"],
    [91, 180, "91 to 180d"],
    [181, 365, "181 to 365d"],
    [366, Float::INFINITY, "over 365d"]
  ].freeze

  def age_buckets(analyses)
    counts = AGE_BUCKETS.to_h { |_, _, label| [label, 0] }
    analyses.each do |analysis|
      age = analysis.secret_record.age_days.to_i
      _, _, label = AGE_BUCKETS.find { |low, high, _| age.between?(low, high) }
      counts[label] += 1 if label
    end
    counts
  end

  # One bar row. Widths are a percentage of the largest value in the set
  # rather than of the total, so a distribution with one dominant bucket
  # still shows the small ones.
  def bar_rows(counts, palette: {})
    return tag.p("Nothing to show.", class: "muted") if counts.blank?

    peak = counts.values.map(&:to_i).max
    safe_join(counts.map { |label, value|
      pct = peak.positive? ? (100.0 * value.to_i / peak).round : 0
      tag.div(class: "row") do
        safe_join([
          tag.span(label, class: "lbl", title: label.to_s),
          tag.span(class: "bar") do
            tag.span("", style: "width:#{pct}%;background:#{palette.fetch(label, '#3b6ea5')}")
          end,
          tag.span(value, class: "num")
        ])
      end
    })
  end

  def tier_palette
    { "low" => "#2f7a4f", "medium" => "#b8860b", "high" => "#b3352c" }
  end

  def severity_palette
    { "HIGH" => "#b3352c", "MEDIUM" => "#b8860b", "LOW" => "#3b6ea5" }
  end

  def tier_pill(tier)
    tag.span(tier, class: "pill", style: "background:#{tier_palette.fetch(tier, '#3b6ea5')}")
  end

  def severity_pill(severity)
    tag.span(severity.downcase, class: "pill",
             style: "background:#{severity_palette.fetch(severity, '#3b6ea5')}")
  end

  # Consumers are the whole point of the platform, so an unresolved one is
  # labeled as unresolved rather than blanked out. "unidentified" is a
  # finding, not a rendering gap.
  def consumer_label(consumer)
    consumer["display_name"].presence ||
      consumer["principal_id"].presence ||
      "unidentified caller"
  end

  def relative_delta(current, previous)
    return nil if previous.nil? || current.nil?

    delta = (current.to_f - previous.to_f).round(1)
    return nil if delta.zero?

    sign = delta.positive? ? "+" : ""
    tag.span("#{sign}#{delta}", class: "delta #{delta.positive? ? 'up' : 'down'}")
  end

  def metric(metrics, key, default = 0)
    metrics.fetch(key.to_s, default)
  end

  def format_time(time)
    return "never" if time.blank?

    time.utc.strftime("%Y-%m-%d %H:%M UTC")
  end
end
