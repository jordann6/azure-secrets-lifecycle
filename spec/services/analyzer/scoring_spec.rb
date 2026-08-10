# frozen_string_literal: true

RSpec.describe Analyzer::Scoring do
  describe ".readiness_score" do
    it "rewards a resource nothing reads over one many unknown callers read" do
      quiet = build_record(age_days: 400, expires_at: 1.year.from_now)
      busy = build_record(resource_id: "https://v.vault.azure.net/secrets/busy",
                          name: "busy", age_days: 30, expires_at: 1.year.from_now)

      unknown = Array.new(5) { |i| consumer(principal_id: nil, display_name: nil, access_count: 40 + i) }

      quiet_score = described_class.readiness_score(quiet, consumer_map)
      busy_score = described_class.readiness_score(busy, consumer_map(*unknown))

      # The older secret is the bigger risk and the safer rotation. That
      # inversion is the entire reason readiness is scored separately.
      expect(quiet_score).to be > busy_score
    end

    it "treats a verified rotation path as the largest single factor" do
      without = build_record(rotation_enabled: false, expires_at: 1.year.from_now)
      with = build_record(resource_id: "https://v.vault.azure.net/secrets/auto",
                          name: "auto", rotation_enabled: true, expires_at: 1.year.from_now)

      delta = described_class.readiness_score(with, consumer_map) -
              described_class.readiness_score(without, consumer_map)

      expect(delta).to eq(25)
    end

    it "penalises consumers that cannot be identified" do
      record = build_record(expires_at: 1.year.from_now, age_days: 10)

      identified = described_class.readiness_score(record, consumer_map(consumer))
      anonymous = described_class.readiness_score(
        record, consumer_map(consumer(principal_id: nil, display_name: nil))
      )

      expect(identified - anonymous).to eq(20)
    end

    it "penalises a Key Vault object with no expiry date" do
      no_expiry = build_record(expires_at: nil)
      with_expiry = build_record(resource_id: "https://v.vault.azure.net/secrets/e",
                                 name: "e", expires_at: 1.year.from_now)

      expect(described_class.readiness_score(with_expiry, consumer_map))
        .to be > described_class.readiness_score(no_expiry, consumer_map)
    end

    it "penalises an object already past expiry hardest of the expiry states" do
      record = build_record(expires_at: 3.days.ago)

      expect(described_class.expiry_component(record)).to eq(-20)
    end

    it "neither penalises nor rewards an Entra credential with no end date" do
      credential = build_record(kind: "entra_app_credential", expires_at: nil,
                                resource_id: "/applications/a/credentials/b", name: "legacy")

      # A never expiring credential is its own, worse finding, so charging
      # it the Key Vault expiry penalty here would double count it. It
      # must not collect the healthy-expiry bonus either.
      expect(described_class.expiry_component(credential)).to eq(0)
    end

    it "still penalises an Entra credential that is already past its end date" do
      credential = build_record(kind: "entra_app_credential", expires_at: 2.days.ago,
                                resource_id: "/applications/a/credentials/c", name: "expired")

      expect(described_class.expiry_component(credential)).to eq(-20)
    end

    it "clamps to the 0 to 100 range" do
      worst = build_record(age_days: 5000, rotation_enabled: false, expires_at: 10.days.ago)
      many = Array.new(9) { consumer(principal_id: nil, display_name: nil) }

      score = described_class.readiness_score(worst, consumer_map(*many))
      expect(score).to be_between(0, 100)
    end

    it "docks an RBAC vault whose audit log shows nothing" do
      rbac = build_record(expires_at: 1.year.from_now,
                          access_model: { "rbac_authorization" => true, "read_principals" => [] })
      policy = build_record(resource_id: "https://v.vault.azure.net/secrets/p", name: "p",
                            expires_at: 1.year.from_now,
                            access_model: { "rbac_authorization" => false, "read_principals" => [] })

      # On an access policy vault the resource names its readers, so
      # silence in the log is only half the story. On an RBAC vault it is
      # the whole story, and there is none.
      expect(described_class.readiness_score(policy, consumer_map))
        .to be > described_class.readiness_score(rbac, consumer_map)
    end
  end

  describe ".risk_tier" do
    it "maps scores to tiers at the documented boundaries" do
      expect(described_class.risk_tier(55)).to eq("high")
      expect(described_class.risk_tier(56)).to eq("medium")
      expect(described_class.risk_tier(74)).to eq("medium")
      expect(described_class.risk_tier(75)).to eq("low")
    end
  end
end
