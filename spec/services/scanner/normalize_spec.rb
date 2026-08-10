# frozen_string_literal: true

RSpec.describe Scanner::Normalize do
  let(:now) { Time.utc(2026, 8, 10, 12, 0, 0) }

  describe ".finish" do
    it "derives age from the real creation date" do
      record = described_class.finish(
        { name: "a", source_created_at: now - (120 * 86_400) },
        scan_id: "scan-1", now: now
      )

      expect(record[:age_days]).to eq(120)
      expect(record[:age_simulated]).to be(false)
    end

    it "honours the simulated age tag and flags the record" do
      # Azure will not backdate a creation date, so seeded resources
      # declare their age. Flagging it is what keeps demo data out of the
      # real telemetry story.
      record = described_class.finish(
        { name: "a", source_created_at: now - 86_400, tags: { "secops:simulated-age-days" => "400" } },
        scan_id: "scan-1", now: now
      )

      expect(record[:age_days]).to eq(400)
      expect(record[:age_simulated]).to be(true)
    end

    it "ignores a simulated age tag that is not a plain integer" do
      record = described_class.finish(
        { name: "a", source_created_at: now - (30 * 86_400), tags: { "secops:simulated-age-days" => "old" } },
        scan_id: "scan-1", now: now
      )

      expect(record[:age_days]).to eq(30)
      expect(record[:age_simulated]).to be(false)
    end

    it "never produces a negative age for a future dated resource" do
      record = described_class.finish(
        { name: "a", source_created_at: now + (10 * 86_400) },
        scan_id: "scan-1", now: now
      )

      expect(record[:age_days]).to eq(0)
    end

    it "defaults age to zero when there is no creation date at all" do
      record = described_class.finish({ name: "a" }, scan_id: "scan-1", now: now)

      expect(record[:age_days]).to eq(0)
    end
  end

  describe ".parse_vault_object_id" do
    it "splits a versioned object id into vault, collection, and name" do
      parsed = described_class.parse_vault_object_id(
        "https://secops-kv-ab12.vault.azure.net/secrets/db-primary/8f3a9c"
      )

      expect(parsed[:vault_name]).to eq("secops-kv-ab12")
      expect(parsed[:collection]).to eq("secrets")
      expect(parsed[:name]).to eq("db-primary")
      expect(parsed[:base_id]).to eq("https://secops-kv-ab12.vault.azure.net/secrets/db-primary")
    end

    it "drops the version so two versions of one secret are one record" do
      a = described_class.parse_vault_object_id("https://v.vault.azure.net/secrets/x/1")
      b = described_class.parse_vault_object_id("https://v.vault.azure.net/secrets/x/2")

      expect(a[:base_id]).to eq(b[:base_id])
    end
  end

  describe ".parse_arm_id" do
    it "pulls the subscription and resource group out of an ARM id" do
      parsed = described_class.parse_arm_id(
        "/subscriptions/sub-1/resourceGroups/secops-rg/providers/Microsoft.KeyVault/vaults/kv-1"
      )

      expect(parsed[:subscription_id]).to eq("sub-1")
      expect(parsed[:resource_group]).to eq("secops-rg")
      expect(parsed[:name]).to eq("kv-1")
    end
  end

  describe ".parse_time" do
    it "reads the epoch seconds the Key Vault data plane returns" do
      expect(described_class.parse_time(1_754_827_200)).to eq(Time.at(1_754_827_200).utc)
    end

    it "reads the ISO 8601 form every other Azure API returns" do
      expect(described_class.parse_time("2026-08-10T12:00:00Z")).to eq(Time.utc(2026, 8, 10, 12))
    end

    it "returns nil rather than raising on junk" do
      expect(described_class.parse_time("not a time")).to be_nil
      expect(described_class.parse_time(nil)).to be_nil
      expect(described_class.parse_time("")).to be_nil
    end
  end
end
