# frozen_string_literal: true

RSpec.describe SecretRecord do
  describe ".attributes_from_sweep" do
    let(:swept) do
      Scanner::Normalize.finish(
        {
          resource_id: "https://v.vault.azure.net/certificates/tls-edge",
          name: "tls-edge",
          kind: "key_vault_certificate",
          subscription_id: "sub-1",
          resource_group: "secops-rg",
          vault_name: "v",
          location: "eastus2",
          source_created_at: Time.utc(2025, 1, 1),
          expires_at: Time.utc(2027, 1, 1),
          enabled: true,
          rotation_enabled: true,
          rotation_days: 360,
          # Kind specific fields with no column of their own.
          issuer: "Self",
          key_vault_reference: false,
          access_model: { "rbac_authorization" => true },
          tags: { "owner" => "platform-team" }
        },
        scan_id: "scan-1", now: Time.utc(2026, 1, 1)
      )
    end

    it "maps the known fields onto columns" do
      attrs = described_class.attributes_from_sweep(swept)

      expect(attrs[:name]).to eq("tls-edge")
      expect(attrs[:kind]).to eq("key_vault_certificate")
      expect(attrs[:rotation_days]).to eq(360)
    end

    it "folds everything else into the details bag" do
      # Keeps certificate issuers and credential kinds queryable without a
      # column per Azure service.
      attrs = described_class.attributes_from_sweep(swept)

      expect(attrs[:details]).to include("issuer" => "Self", "key_vault_reference" => false)
      expect(attrs[:details]).not_to have_key("name")
    end

    it "drops scan_id, which the caller supplies as a foreign key" do
      expect(described_class.attributes_from_sweep(swept)).not_to have_key(:scan_id)
      expect(described_class.attributes_from_sweep(swept)[:details]).not_to have_key("scan_id")
    end

    it "round trips through the bulk insert the sweep actually uses" do
      # insert_all! bypasses ActiveRecord type casting, so this is the only
      # thing that proves a swept hash lands in Postgres jsonb intact.
      scan = build_scan
      now = Time.now.utc
      row = described_class.attributes_from_sweep(swept)
                           .merge(scan_id: scan.id, created_at: now, updated_at: now)

      described_class.insert_all!([row])
      stored = scan.secret_records.sole

      expect(stored.details["issuer"]).to eq("Self")
      expect(stored.tags["owner"]).to eq("platform-team")
      expect(stored.access_model["rbac_authorization"]).to be(true)
      expect(stored.expires_at).to eq(Time.utc(2027, 1, 1))
      expect(stored.age_days).to eq(365)
    end
  end

  describe "#policy_principals" do
    it "lists the object ids an access policy vault grants read to" do
      record = build_record(access_model: {
        "rbac_authorization" => false,
        "read_principals" => [{ "object_id" => "oid-1" }, { "object_id" => "oid-2" }]
      })

      expect(record.policy_principals).to eq(%w[oid-1 oid-2])
    end

    it "is empty on an RBAC vault, which is the point" do
      # Authorization lives in role assignments rather than on the
      # resource, so the observed consumer map is the only evidence there
      # is. The scoring model accounts for that.
      expect(build_record.policy_principals).to be_empty
    end
  end

  describe "#expired? and #expires_within?" do
    it "reads the expiry state the CIS controls are scored against" do
      expect(build_record(expires_at: 1.day.ago)).to be_expired
      expect(build_record(expires_at: 1.day.from_now)).not_to be_expired
      expect(build_record(expires_at: 10.days.from_now).expires_within?(30)).to be(true)
      expect(build_record(expires_at: nil).expires_within?(30)).to be(false)
    end
  end

  describe "#owner_tag" do
    it "falls back to unassigned so a finding always has a destination" do
      expect(build_record(tags: {}).owner_tag).to eq("unassigned")
    end
  end
end
