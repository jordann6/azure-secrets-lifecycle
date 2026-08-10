# frozen_string_literal: true

RSpec.describe Analyzer::ConsumerMap do
  let(:directory) { instance_double(Analyzer::Directory, resolve: {}, lookup: nil) }
  subject(:mapper) { described_class.new(directory: directory) }

  def row(resource_id:, principal_id: "oid-1", access_count: 3,
          last_accessed: "2026-08-01T00:00:00Z", operation: "SecretGet")
    {
      "resource_id" => resource_id,
      "principal_id" => principal_id,
      "principal_appid" => "app-1",
      "operation" => operation,
      "access_count" => access_count,
      "last_accessed" => last_accessed
    }
  end

  describe "#normalize_resource_id" do
    it "drops the version so a rotation does not look like a new consumer set" do
      versioned = "https://v.vault.azure.net/secrets/db-primary/8f3a9c2b1d"
      logical = "https://v.vault.azure.net/secrets/db-primary"

      expect(mapper.normalize_resource_id(versioned))
        .to eq(mapper.normalize_resource_id(logical))
    end

    it "falls back to the raw value for anything that is not a vault uri" do
      expect(mapper.normalize_resource_id("not a uri")).to eq("not a uri")
    end
  end

  describe "#build" do
    it "aggregates reads per principal across rows" do
      maps = mapper.build([
        row(resource_id: "https://v.vault.azure.net/secrets/a", access_count: 3),
        row(resource_id: "https://v.vault.azure.net/secrets/a/version-2", access_count: 4)
      ])

      map = maps.fetch("https://v.vault.azure.net/secrets/a")
      expect(map["consumers"].size).to eq(1)
      expect(map["consumers"].first["access_count"]).to eq(7)
      expect(map["total_reads"]).to eq(7)
    end

    it "keeps a caller with no object id as an unidentified consumer" do
      maps = mapper.build([row(resource_id: "https://v.vault.azure.net/secrets/a",
                               principal_id: nil)])

      consumer = maps.values.first["consumers"].first
      expect(consumer["principal_id"]).to be_nil
      expect(consumer["identity_type"]).to eq("unknown")
    end

    it "labels a resolvable principal that Graph declined to resolve" do
      maps = mapper.build([row(resource_id: "https://v.vault.azure.net/secrets/a")])

      expect(maps.values.first["consumers"].first["identity_type"]).to eq("unresolved")
    end

    it "attaches display names Graph did resolve" do
      allow(directory).to receive(:lookup).with("oid-1")
        .and_return("display_name" => "orders-api", "identity_type" => "service-principal")

      maps = mapper.build([row(resource_id: "https://v.vault.azure.net/secrets/a")])

      consumer = maps.values.first["consumers"].first
      expect(consumer["display_name"]).to eq("orders-api")
      expect(consumer["identity_type"]).to eq("service-principal")
    end

    it "orders consumers by read volume" do
      maps = mapper.build([
        row(resource_id: "https://v.vault.azure.net/secrets/a", principal_id: "quiet", access_count: 1),
        row(resource_id: "https://v.vault.azure.net/secrets/a", principal_id: "loud", access_count: 90)
      ])

      expect(maps.values.first["consumers"].map { |c| c["principal_id"] })
        .to eq(%w[loud quiet])
    end

    it "keeps the most recent access across duplicate rows" do
      maps = mapper.build([
        row(resource_id: "https://v.vault.azure.net/secrets/a", last_accessed: "2026-01-01T00:00:00Z"),
        row(resource_id: "https://v.vault.azure.net/secrets/a", last_accessed: "2026-06-01T00:00:00Z")
      ])

      expect(maps.values.first["consumers"].first["last_accessed"])
        .to start_with("2026-06-01")
    end

    it "ignores rows with no resource" do
      expect(mapper.build([row(resource_id: nil)])).to be_empty
    end
  end

  describe "#match" do
    it "matches a Key Vault record to its normalized map" do
      record = build_record(resource_id: "https://v.vault.azure.net/secrets/db-primary")
      maps = mapper.build([row(resource_id: "https://v.vault.azure.net/secrets/db-primary/abc")])

      expect(mapper.match(record, maps)["total_reads"]).to eq(3)
    end

    it "falls back to a key containment check for App Configuration" do
      # App Configuration audit rows carry the whole request uri, query
      # string included, so an exact match never lands.
      record = build_record(kind: "app_config_kv", name: "secops-test/app/db-conn$prod",
                            resource_id: "https://s.azconfig.io/kv/secops-test/app/db-conn$prod")
      maps = mapper.build([
        row(resource_id: "https://s.azconfig.io/kv/secops-test/app/db-conn?api-version=2023-11-01")
      ])

      expect(mapper.match(record, maps)["total_reads"]).to eq(3)
    end

    it "returns an empty map when nothing read the resource" do
      record = build_record

      expect(mapper.match(record, {})).to eq(described_class::EMPTY)
    end
  end
end
