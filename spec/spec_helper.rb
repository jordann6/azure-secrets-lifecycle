# frozen_string_literal: true

ENV["RAILS_ENV"] ||= "test"

require_relative "../config/environment"
abort("the test suite refuses to run outside RAILS_ENV=test") if Rails.env.production?

require "rspec/rails"
require "webmock/rspec"

# Nothing in this suite is allowed to reach Azure. A test that silently
# starts making real Graph calls is a test that will pass on a laptop with
# an az session and fail in CI for reasons nobody can reproduce.
WebMock.disable_net_connect!(allow_localhost: true)

RSpec.configure do |config|
  config.use_transactional_fixtures = true
  config.infer_spec_type_from_file_location!
  config.filter_rails_from_backtrace!

  config.expect_with :rspec do |expectations|
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
  end

  config.mock_with :rspec do |mocks|
    mocks.verify_partial_doubles = true
  end

  config.shared_context_metadata_behavior = :apply_to_host_groups
  config.disable_monkey_patching!
  config.order = :random
  Kernel.srand config.seed

  config.before do
    Azure::Token.reset!
    Evidence::Mapper.reset!
  end
end

# Builds a persisted SecretRecord with sensible defaults, so each example
# only states the attribute it actually cares about.
module RecordFactory
  def build_scan(scan_id: "20260810T120000Z-abc123", **attrs)
    Scan.create!(scan_id: scan_id, status: "running", started_at: Time.now.utc, **attrs)
  end

  # Records are unique on [scan_id, resource_id], so the default id is
  # generated. An example that cares about the id passes one.
  def next_record_seq
    @record_seq = (@record_seq || 0) + 1
  end

  def build_record(scan: nil, **attrs)
    scan ||= @default_scan ||= build_scan
    seq = next_record_seq
    defaults = {
      resource_id: "https://vault.vault.azure.net/secrets/db-primary-#{seq}",
      name: "db-primary-#{seq}",
      kind: "key_vault_secret",
      subscription_id: "00000000-0000-0000-0000-000000000000",
      vault_name: "vault",
      location: "eastus2",
      source_created_at: 400.days.ago.utc,
      scanned_at: Time.now.utc,
      enabled: true,
      rotation_enabled: false,
      rotation_days: 0,
      age_days: 400,
      age_simulated: false,
      tags: { "owner" => "platform-team" },
      access_model: { "rbac_authorization" => true, "purge_protection" => true,
                      "public_network_access" => "Disabled", "read_principals" => [] },
      details: {}
    }
    scan.secret_records.create!(defaults.merge(attrs))
  end

  def consumer_map(*consumers)
    {
      "consumers" => consumers,
      "total_reads" => consumers.sum { |c| c["access_count"].to_i },
      "sources" => []
    }
  end

  def consumer(principal_id: "8f2c1e04-0000-0000-0000-000000000001",
               display_name: "orders-api", access_count: 12, **attrs)
    {
      "principal_id" => principal_id,
      "principal_appid" => "appid-1",
      "display_name" => display_name,
      "identity_type" => "service-principal",
      "access_count" => access_count,
      "operations" => ["SecretGet"],
      "last_accessed" => 2.days.ago.utc.iso8601
    }.merge(attrs.transform_keys(&:to_s))
  end
end

RSpec.configure { |config| config.include RecordFactory }
