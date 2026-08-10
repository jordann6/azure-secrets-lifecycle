# frozen_string_literal: true

class Finding < ApplicationRecord
  belongs_to :scan
  belongs_to :secret_record

  SEVERITIES = %w[LOW MEDIUM HIGH].freeze
  SEVERITY_RANK = { "HIGH" => 0, "MEDIUM" => 1, "LOW" => 2 }.freeze

  validates :finding_id, :finding_type, :title, presence: true
  validates :severity, inclusion: { in: SEVERITIES }

  scope :open, -> { where(remediation_status: "OPEN") }
  scope :by_severity, -> { order(Arel.sql("CASE severity WHEN 'HIGH' THEN 0 WHEN 'MEDIUM' THEN 1 ELSE 2 END")) }

  def controls
    Array(control_ids)
  end

  # Counts findings per control across a scan. The dashboard renders this
  # and the evidence artifact carries it, so an auditor asking "show me
  # coverage for NIST IA-5" gets one number rather than a query.
  def self.count_by_control(scope = all)
    scope.pluck(:control_ids).flatten.tally
  end
end
