# frozen_string_literal: true

RSpec.describe Analyzer::LogAnalytics do
  let(:client) { instance_double(Azure::Client) }
  subject(:logs) { described_class.new(workspace_id: "ws-guid", lookback_days: 90, client: client) }

  def table(rows)
    {
      "tables" => [{
        "name" => "PrimaryResult",
        "columns" => [
          { "name" => "resource_id" }, { "name" => "principal_id" },
          { "name" => "principal_appid" }, { "name" => "operation" },
          { "name" => "access_count" }, { "name" => "last_accessed" }
        ],
        "rows" => rows
      }]
    }
  end

  it "turns positional rows into hashes keyed by column name" do
    allow(client).to receive(:post).and_return(
      table([["https://v.vault.azure.net/secrets/a", "oid-1", "app-1", "SecretGet", 4,
              "2026-08-01T00:00:00Z"]])
    )

    rows = logs.query("AZKVAuditLogs | take 1")

    expect(rows.first).to include(
      "resource_id" => "https://v.vault.azure.net/secrets/a",
      "principal_id" => "oid-1",
      "access_count" => 4
    )
  end

  it "returns nothing rather than raising on an empty result set" do
    allow(client).to receive(:post).and_return("tables" => [])

    expect(logs.query("AZKVAuditLogs")).to eq([])
  end

  it "queries every source table and concatenates the results" do
    allow(client).to receive(:post).and_return(
      table([["https://v.vault.azure.net/secrets/a", "oid-1", "app-1", "SecretGet", 1, "2026-08-01T00:00:00Z"]])
    )

    expect(logs.access_events.size).to eq(described_class::QUERIES.size)
  end

  it "skips a table the workspace does not have instead of failing the scan" do
    # A workspace with no data for a table answers with a semantic error,
    # not an empty result. Losing one source costs the consumer map a few
    # rows; failing the run costs everything.
    allow(client).to receive(:post).and_raise(Azure::Client::Error.new("bad request", status: 400))

    expect(logs.access_events).to eq([])
  end

  it "asks for the configured lookback window" do
    allow(client).to receive(:post).and_return(table([]))

    logs.query("AZKVAuditLogs")

    expect(client).to have_received(:post)
      .with(anything, hash_including(body: hash_including("timespan" => "P90D")))
  end

  it "refuses to run without a workspace id" do
    expect { described_class.new(workspace_id: nil, client: client).access_events }
      .to raise_error(ArgumentError, /LOG_ANALYTICS_WORKSPACE_ID/)
  end
end
