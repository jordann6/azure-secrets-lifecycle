# frozen_string_literal: true

class SecretRecord < ApplicationRecord
  belongs_to :scan
  has_one :analysis, dependent: :destroy
  has_many :findings, dependent: :delete_all

  KINDS = Scanner::Normalize::KINDS

  # Everything a sweep can emit that is not a column lands in `details`.
  # Keeps kind specific fields (certificate issuer, credential kind,
  # Key Vault reference flag) queryable without a column per service.
  COLUMN_KEYS = %i[
    resource_id name kind subscription_id resource_group vault_name location
    source_created_at source_updated_at expires_at scanned_at
    enabled rotation_enabled rotation_days age_days age_simulated
    tags access_model
  ].freeze

  validates :resource_id, :name, :kind, presence: true
  validates :kind, inclusion: { in: KINDS }

  scope :secrets_only, -> { where.not(kind: "entra_app_credential") }
  scope :credentials_only, -> { where(kind: "entra_app_credential") }

  # Splits a normalized sweep hash into columns plus the details bag.
  def self.attributes_from_sweep(record)
    record = record.symbolize_keys
    columns = record.slice(*COLUMN_KEYS)
    columns[:details] = record.except(*COLUMN_KEYS, :scan_id)
                              .transform_keys(&:to_s)
    columns
  end

  def owner_tag
    tags["owner"].presence || "unassigned"
  end

  def expired?
    expires_at.present? && expires_at < Time.now.utc
  end

  def expires_within?(days)
    expires_at.present? && expires_at < Time.now.utc + days.days
  end

  def credential? = kind == "entra_app_credential"

  # Principals a vault access policy grants read access to. On an RBAC
  # vault this is empty by design: authorization lives in role assignments
  # rather than on the resource, which is exactly why the observed
  # consumer map from the audit log matters more here than it does in AWS.
  def policy_principals
    Array(access_model["read_principals"]).filter_map { |p| p["object_id"] }
  end

  def rbac_vault?
    access_model["rbac_authorization"] == true
  end

  def display_kind
    kind.tr("_", " ")
  end
end
