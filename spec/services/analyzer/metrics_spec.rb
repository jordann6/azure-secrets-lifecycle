# frozen_string_literal: true

RSpec.describe Analyzer::Metrics do
  let(:scan) { build_scan.tap { |s| s.update!(duration_ms: 4000, resource_count: 4) } }

  def entry(record, consumers: [], score: 60, tier: "medium", runbook: nil)
    {
      record: record,
      consumer_map: { "consumers" => consumers, "total_reads" => 0 },
      readiness_score: score,
      risk_tier: tier,
      runbook: runbook
    }
  end

  def finding(type: "SECRET_STALE", severity: "HIGH", controls: ["SOC 2 CC6.1"], resource: "r1")
    { finding_type: type, severity: severity, control_ids: controls, resource_id: resource }
  end

  it "counts secrets and credentials separately" do
    secret = build_record(scan: scan)
    credential = build_record(scan: scan, kind: "entra_app_credential",
                              resource_id: "/applications/a/credentials/b", name: "cred")

    metrics = described_class.new(scan, [entry(secret), entry(credential)], []).call

    expect(metrics["total_resources"]).to eq(2)
    expect(metrics["total_secrets"]).to eq(1)
    expect(metrics["total_credentials"]).to eq(1)
  end

  it "keeps credentials out of the secret percentage denominators" do
    # Folding them in would make "percent with a verified rotation path"
    # quietly measure two different populations at once.
    secret = build_record(scan: scan, rotation_enabled: true)
    credential = build_record(scan: scan, kind: "entra_app_credential", rotation_enabled: false,
                              resource_id: "/applications/a/credentials/b", name: "cred")

    metrics = described_class.new(scan, [entry(secret), entry(credential)], []).call

    expect(metrics["pct_with_verified_rotation_path"]).to eq(100.0)
  end

  it "counts a medium confidence runbook as a verified rotation path" do
    record = build_record(scan: scan, rotation_enabled: false)
    planned = entry(record, runbook: { "confidence" => "medium", "generator" => "fallback" })

    expect(described_class.new(scan, [planned], []).call["pct_with_verified_rotation_path"])
      .to eq(100.0)
  end

  it "does not count a low confidence runbook as a verified path" do
    record = build_record(scan: scan, rotation_enabled: false)
    guessed = entry(record, runbook: { "confidence" => "low", "generator" => "fallback" })

    expect(described_class.new(scan, [guessed], []).call["pct_with_verified_rotation_path"])
      .to eq(0.0)
  end

  it "requires every consumer to be identified before the secret counts" do
    partial = build_record(scan: scan)
    metrics = described_class.new(
      scan,
      [entry(partial, consumers: [{ "principal_id" => "a" }, { "principal_id" => nil }])],
      []
    ).call

    expect(metrics["pct_with_identified_consumers"]).to eq(0.0)
  end

  it "measures expiry coverage against Key Vault objects only" do
    kv = build_record(scan: scan, expires_at: 1.year.from_now)
    app_config = build_record(scan: scan, kind: "app_config_kv", expires_at: nil,
                              resource_id: "https://s.azconfig.io/kv/a", name: "a")

    metrics = described_class.new(scan, [entry(kv), entry(app_config)], []).call

    expect(metrics["pct_with_expiry_set"]).to eq(100.0)
  end

  it "keeps zero buckets so a chart does not drop a category between scans" do
    metrics = described_class.new(scan, [entry(build_record(scan: scan), tier: "high")], []).call

    expect(metrics["risk_tiers"]).to eq("low" => 0, "medium" => 0, "high" => 1)
  end

  it "tallies findings by control, severity, and type" do
    findings = [
      finding(controls: ["SOC 2 CC6.1", "NIST 800-53 IA-5"]),
      finding(type: "SECRET_ORPHANED", severity: "LOW", controls: ["SOC 2 CC6.1"], resource: "r2")
    ]

    metrics = described_class.new(scan, [entry(build_record(scan: scan))], findings).call

    expect(metrics["findings_by_control"]["SOC 2 CC6.1"]).to eq(2)
    expect(metrics["findings_by_severity"]).to eq("HIGH" => 1, "MEDIUM" => 0, "LOW" => 1)
    expect(metrics["resources_with_findings"]).to eq(2)
  end

  it "separates model runbooks from rule based ones" do
    a = entry(build_record(scan: scan), runbook: { "generator" => "azure-openai", "confidence" => "high" })
    b = entry(build_record(scan: scan, resource_id: "https://v.vault.azure.net/secrets/b", name: "b"),
              runbook: { "generator" => "fallback", "confidence" => "medium" })

    metrics = described_class.new(scan, [a, b], []).call

    expect(metrics["runbooks_generated"]).to eq(2)
    expect(metrics["runbooks_by_generator"]).to eq("azure-openai" => 1, "fallback" => 1)
  end

  it "reports zeroes rather than dividing by zero on an empty scan" do
    metrics = described_class.new(scan, [], []).call

    expect(metrics["mean_age_days"]).to eq(0)
    expect(metrics["median_age_days"]).to eq(0)
    expect(metrics["pct_with_identified_consumers"]).to eq(0)
  end

  it "computes the median for an even sized population" do
    records = [10, 20, 30, 40].each_with_index.map do |age, i|
      entry(build_record(scan: scan, age_days: age, name: "s#{i}",
                         resource_id: "https://v.vault.azure.net/secrets/s#{i}"))
    end

    expect(described_class.new(scan, records, []).call["median_age_days"]).to eq(25.0)
  end

  it "surfaces how much of the scan is simulated demo data" do
    real = build_record(scan: scan)
    fake = build_record(scan: scan, age_simulated: true, name: "seeded",
                        resource_id: "https://v.vault.azure.net/secrets/seeded")

    expect(described_class.new(scan, [entry(real), entry(fake)], []).call["simulated_age_count"])
      .to eq(1)
  end
end
