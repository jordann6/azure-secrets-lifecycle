# frozen_string_literal: true

RSpec.describe Evidence::Mapper do
  subject(:mapper) { described_class.new }

  def analysis_for(record, consumers: [], score: 40)
    Analysis.new(
      scan_id: record.scan_id, secret_record: record,
      consumer_map: { "consumers" => consumers, "total_reads" => 0 },
      readiness_score: score, risk_tier: "high"
    )
  end

  def types(record, **kwargs)
    mapper.derive(record, analysis_for(record, **kwargs)).map { |f| f[:finding_type] }
  end

  it "flags a stale secret with no rotation path" do
    record = build_record(age_days: 400, rotation_enabled: false, expires_at: 1.year.from_now)

    expect(types(record)).to include("SECRET_STALE", "SECRET_NO_ROTATION_CONFIG")
  end

  it "does not flag staleness when a rotation path exists" do
    record = build_record(age_days: 400, rotation_enabled: true, expires_at: 1.year.from_now)

    expect(types(record)).not_to include("SECRET_STALE", "SECRET_NO_ROTATION_CONFIG")
  end

  it "flags a Key Vault object with no expiry date" do
    expect(types(build_record(expires_at: nil))).to include("SECRET_NO_EXPIRY")
  end

  it "does not raise a missing expiry against App Configuration" do
    # App Configuration key values have no exp attribute to set, so
    # claiming CIS 8.3 fails there would be a false positive an auditor
    # would rightly throw out.
    record = build_record(kind: "app_config_kv", expires_at: nil,
                          resource_id: "https://s.azconfig.io/kv/a", name: "a")

    expect(types(record)).not_to include("SECRET_NO_EXPIRY")
  end

  it "reports expiry states as mutually exclusive" do
    expired = types(build_record(expires_at: 2.days.ago, name: "gone",
                                 resource_id: "https://v.vault.azure.net/secrets/gone"))
    soon = types(build_record(expires_at: 5.days.from_now, name: "soon",
                              resource_id: "https://v.vault.azure.net/secrets/soon"))

    expect(expired).to include("SECRET_EXPIRED")
    expect(expired).not_to include("SECRET_EXPIRING_SOON", "SECRET_NO_EXPIRY")
    expect(soon).to include("SECRET_EXPIRING_SOON")
    expect(soon).not_to include("SECRET_EXPIRED")
  end

  it "flags an orphaned secret when nothing read it" do
    expect(types(build_record)).to include("SECRET_ORPHANED")
  end

  it "flags unidentified consumers rather than orphaning a busy secret" do
    found = types(build_record, consumers: [{ "principal_id" => nil, "access_count" => 9 }])

    expect(found).to include("SECRET_UNIDENTIFIED_CONSUMERS")
    expect(found).not_to include("SECRET_ORPHANED")
  end

  it "flags a stale Entra credential with a lifetime beyond policy" do
    credential = build_record(kind: "entra_app_credential", age_days: 200, rotation_days: 730,
                              resource_id: "/applications/a/credentials/b", name: "legacy",
                              details: { "federated_credential_count" => 0 })

    found = types(credential)
    expect(found).to include("APP_CREDENTIAL_STALE", "APP_CREDENTIAL_LONG_LIVED",
                             "APP_CREDENTIAL_NO_FEDERATION")
  end

  it "does not flag federation on an app registration that already has it" do
    credential = build_record(kind: "entra_app_credential", age_days: 10, rotation_days: 30,
                              resource_id: "/applications/a/credentials/c", name: "modern",
                              details: { "federated_credential_count" => 2 })

    expect(types(credential)).not_to include("APP_CREDENTIAL_NO_FEDERATION")
  end

  it "raises vault posture findings from the access model" do
    record = build_record(
      access_model: { "rbac_authorization" => true, "purge_protection" => false,
                      "public_network_access" => "Enabled", "read_principals" => [] }
    )

    expect(types(record)).to include("VAULT_PURGE_PROTECTION_DISABLED",
                                     "VAULT_PUBLIC_NETWORK_ACCESS")
  end

  it "resolves control ids through the yaml rather than hardcoding them" do
    record = build_record(age_days: 400, expires_at: 1.year.from_now)
    finding = mapper.derive(record, analysis_for(record))
                    .find { |f| f[:finding_type] == "SECRET_STALE" }

    expect(finding[:control_ids]).to include("HIPAA 164.308(a)(5)(ii)(D)", "SOC 2 CC6.1")
    expect(finding[:severity]).to eq("HIGH")
  end

  it "carries the owner tag through so a finding has somewhere to go" do
    record = build_record(tags: { "owner" => "payments-team" })
    finding = mapper.derive(record, analysis_for(record)).first

    expect(finding[:owner_tag]).to eq("payments-team")
  end

  it "produces a stable id for the same finding within a scan" do
    record = build_record
    first = mapper.derive(record, analysis_for(record))
    second = mapper.derive(record, analysis_for(record))

    expect(first.map { |f| f[:finding_id] }).to eq(second.map { |f| f[:finding_id] })
  end

  it "produces a different id for the same finding in a different scan" do
    record = build_record
    other_scan = build_scan(scan_id: "20260811T120000Z-def456")
    other = build_record(scan: other_scan)

    ids = [record, other].map { |r| mapper.derive(r, analysis_for(r)).first[:finding_id] }
    expect(ids.uniq.size).to eq(2)
  end
end
