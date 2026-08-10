# frozen_string_literal: true

class Analysis < ApplicationRecord
  belongs_to :scan
  belongs_to :secret_record

  TIERS = %w[low medium high].freeze

  validates :risk_tier, inclusion: { in: TIERS }
  validates :readiness_score, numericality: { in: 0..100 }

  scope :by_risk, -> { order(:readiness_score) }
  scope :high_risk, -> { where(risk_tier: "high") }

  def consumers
    Array(consumer_map["consumers"])
  end

  def identified_consumers
    consumers.select { |c| c["principal_id"].present? }
  end

  def unidentified?
    consumers.any? && identified_consumers.size < consumers.size
  end

  def orphaned? = consumers.empty?

  def total_reads
    consumer_map["total_reads"].to_i
  end

  # A runbook the model produced versus one the rule engine produced.
  # Surfaced on the dashboard so nobody mistakes the fallback for
  # synthesis, and so a scan run without model access is still legible.
  def runbook_generator
    runbook&.dig("generator")
  end

  def runbook_confidence
    runbook&.dig("confidence")
  end
end
