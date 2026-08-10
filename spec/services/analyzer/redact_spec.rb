# frozen_string_literal: true

RSpec.describe Analyzer::Redact do
  it "redacts keys that name credential material" do
    result = described_class.call(
      "name" => "db-primary",
      "value" => "hunter2",
      "clientSecret" => "abc",
      "connection_string" => "Server=x;Password=y"
    )

    expect(result["name"]).to eq("db-primary")
    expect(result["value"]).to eq("[REDACTED]")
    expect(result["clientSecret"]).to eq("[REDACTED]")
    expect(result["connection_string"]).to eq("[REDACTED]")
  end

  it "keeps counts under keys whose names merely look sensitive" do
    # Key material is always a string. Blanking a metric because its name
    # contains "secret" produces "secrets under management: [REDACTED]",
    # which is not a safer dashboard, only a broken one.
    result = described_class.call(
      "by_kind" => { "key_vault_secret" => 12, "entra_app_credential" => 3 },
      "total_reads" => 42
    )

    expect(result["by_kind"]).to eq("key_vault_secret" => 12, "entra_app_credential" => 3)
    expect(result["total_reads"]).to eq(42)
  end

  it "keeps a boolean or timestamp under a sensitive looking key" do
    result = described_class.call("rotation_enabled" => true, "secret_last_rotated" => nil)

    expect(result["rotation_enabled"]).to be(true)
    expect(result["secret_last_rotated"]).to be_nil
  end

  it "still scrubs a nested structure under a sensitive key" do
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    result = described_class.call("credentials" => [{ "note" => jwt }])

    expect(result["credentials"].first["note"]).to eq("[REDACTED]")
  end

  it "redacts high entropy literals wherever they appear" do
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    result = described_class.call("note" => "token was #{jwt} yesterday")

    expect(result["note"]).to eq("token was [REDACTED] yesterday")
  end

  it "redacts storage account keys and connection strings in free text" do
    key = "#{'A' * 86}=="
    result = described_class.call("log" => "AccountKey=#{'B' * 40}; other #{key}")

    expect(result["log"]).not_to include("B" * 40)
    expect(result["log"]).not_to include(key)
  end

  it "redacts PEM private key headers" do
    result = described_class.call(["-----BEGIN RSA PRIVATE KEY-----"])

    expect(result.first).to eq("[REDACTED]")
  end

  it "recurses through nested structures without mutating the input" do
    input = { "consumers" => [{ "display_name" => "api", "password" => "p" }] }
    frozen = Marshal.load(Marshal.dump(input))

    result = described_class.call(input)

    expect(result["consumers"].first["password"]).to eq("[REDACTED]")
    expect(result["consumers"].first["display_name"]).to eq("api")
    expect(input).to eq(frozen)
  end

  it "leaves non string scalars alone" do
    expect(described_class.call(42)).to eq(42)
    expect(described_class.call(nil)).to be_nil
    expect(described_class.call(true)).to be(true)
  end
end
