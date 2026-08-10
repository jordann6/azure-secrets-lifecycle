# frozen_string_literal: true

class Scan < ApplicationRecord
  # Declaration order is deletion order. Analyses and findings both carry
  # a foreign key to secret_records, so they have to go first or the
  # cascade trips the constraint.
  has_many :analyses, dependent: :delete_all
  has_many :findings, dependent: :delete_all
  has_many :secret_records, dependent: :delete_all

  STATUSES = %w[running analyzed reported failed].freeze

  validates :scan_id, presence: true, uniqueness: true
  validates :status, inclusion: { in: STATUSES }

  scope :recent, -> { order(started_at: :desc) }
  scope :complete, -> { where(status: %w[analyzed reported]) }

  # Scan ids sort lexicographically, which is what lets "the latest scan"
  # be a cheap ordered lookup here and a readable path segment on the
  # dashboard and in the evidence container.
  def self.generate_id(now = Time.now.utc)
    "#{now.strftime('%Y%m%dT%H%M%SZ')}-#{SecureRandom.hex(3)}"
  end

  def self.latest_complete
    complete.recent.first
  end

  def to_param = scan_id

  def duration_seconds
    duration_ms ? (duration_ms / 1000.0).round(1) : nil
  end

  def secrets_per_second
    return nil unless duration_ms&.positive? && resource_count.positive?

    (resource_count / (duration_ms / 1000.0)).round(2)
  end

  def partial?
    sweep_errors.present?
  end
end
