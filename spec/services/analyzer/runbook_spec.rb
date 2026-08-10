# frozen_string_literal: true

RSpec.describe Analyzer::Runbook do
  let(:record) { build_record(name: "db-primary", vault_name: "secops-kv") }
  let(:map) { consumer_map(consumer(display_name: "orders-api")) }

  def response(content)
    { "choices" => [{ "message" => { "content" => content } }] }
  end

  def valid_payload
    {
      "resource_name" => "db-primary",
      "steps" => [{ "order" => 1, "action" => "do a thing", "verification" => "check it" }],
      "rollback" => ["undo it"],
      "confidence" => "high",
      "confidence_rationale" => "every consumer is named"
    }
  end

  describe "#build_fallback" do
    it "names each identified consumer as its own step" do
      runbook = described_class.new(endpoint: "").build_fallback(
        record, consumer_map(consumer(display_name: "orders-api"),
                             consumer(principal_id: "oid-2", display_name: "billing-worker"))
      )

      actions = runbook["steps"].map { |s| s["action"] }
      expect(actions.join(" ")).to include("orders-api").and include("billing-worker")
      expect(runbook["generator"]).to eq("fallback")
    end

    it "orders steps so consumers move before the old version is retired" do
      runbook = described_class.new(endpoint: "").build_fallback(record, map)

      steps = runbook["steps"].sort_by { |s| s["order"] }
      consumer_index = steps.index { |s| s["action"].include?("orders-api") }
      retire_index = steps.index { |s| s["action"].include?("Disable the previous version") }

      expect(consumer_index).to be < retire_index
    end

    it "reports low confidence when consumers exist but cannot be named" do
      runbook = described_class.new(endpoint: "").build_fallback(
        record, consumer_map(consumer(principal_id: nil, display_name: nil))
      )

      expect(runbook["confidence"]).to eq("low")
      expect(runbook["confidence_rationale"]).to include("no caller identity")
    end

    it "tells the operator to confirm with the owner when nothing reads it" do
      runbook = described_class.new(endpoint: "").build_fallback(record, consumer_map)

      expect(runbook["steps"].map { |s| s["action"] }.join(" "))
        .to include("platform-team")
      expect(runbook["confidence"]).to eq("medium")
    end

    it "adds an expiry step when the object has none" do
      runbook = described_class.new(endpoint: "").build_fallback(
        build_record(expires_at: nil), map
      )

      expect(runbook["steps"].map { |s| s["action"] }.join(" "))
        .to include("Set an expiry date")
    end

    it "uses credential wording and rollback for an Entra credential" do
      credential = build_record(kind: "entra_app_credential", name: "legacy",
                                resource_id: "/applications/a/credentials/b",
                                details: { "app_id" => "app-guid" })

      runbook = described_class.new(endpoint: "").build_fallback(credential, map)

      expect(runbook["steps"].first["action"]).to include("app registration")
      expect(runbook["rollback"].join(" ")).to include("credential")
    end

    it "numbers steps consecutively from one" do
      runbook = described_class.new(endpoint: "").build_fallback(record, map)

      orders = runbook["steps"].map { |s| s["order"] }
      expect(orders).to eq((1..orders.size).to_a)
    end
  end

  describe "#generate" do
    it "falls back without a model when no endpoint is configured" do
      runbook = described_class.new(endpoint: "").generate(record, map)

      expect(runbook["generator"]).to eq("fallback")
    end

    it "returns the model's runbook when it validates" do
      client = instance_double(Azure::Client)
      allow(client).to receive(:post).and_return(response(JSON.generate(valid_payload)))

      runbook = described_class.new(endpoint: "https://x.openai.azure.com",
                                    deployment: "gpt-4o-mini", client: client)
                              .generate(record, map)

      expect(runbook["generator"]).to eq("azure-openai")
      expect(runbook["model"]).to eq("gpt-4o-mini")
      expect(runbook["confidence"]).to eq("high")
    end

    it "strips a markdown fence from a deployment that ignores response_format" do
      client = instance_double(Azure::Client)
      allow(client).to receive(:post)
        .and_return(response("```json\n#{JSON.generate(valid_payload)}\n```"))

      runbook = described_class.new(endpoint: "https://x.openai.azure.com", client: client)
                               .generate(record, map)

      expect(runbook["generator"]).to eq("azure-openai")
    end

    it "retries once before giving up on an unparseable response" do
      client = instance_double(Azure::Client)
      allow(client).to receive(:post)
        .and_return(response("not json"), response(JSON.generate(valid_payload)))

      runbook = described_class.new(endpoint: "https://x.openai.azure.com", client: client)
                               .generate(record, map)

      expect(runbook["generator"]).to eq("azure-openai")
      expect(client).to have_received(:post).twice
    end

    it "falls back rather than raising when both attempts fail" do
      client = instance_double(Azure::Client)
      allow(client).to receive(:post).and_return(response("not json"))

      runbook = described_class.new(endpoint: "https://x.openai.azure.com", client: client)
                               .generate(record, map)

      expect(runbook["generator"]).to eq("fallback")
    end

    it "rejects a runbook with an invalid confidence level" do
      payload = valid_payload.merge("confidence" => "very high")
      client = instance_double(Azure::Client)
      allow(client).to receive(:post).and_return(response(JSON.generate(payload)))

      expect(described_class.new(endpoint: "https://x.openai.azure.com", client: client)
                            .generate(record, map)["generator"]).to eq("fallback")
    end

    it "rejects a runbook whose steps are missing a verification" do
      payload = valid_payload.merge("steps" => [{ "order" => 1, "action" => "do it" }])
      client = instance_double(Azure::Client)
      allow(client).to receive(:post).and_return(response(JSON.generate(payload)))

      expect(described_class.new(endpoint: "https://x.openai.azure.com", client: client)
                            .generate(record, map)["generator"]).to eq("fallback")
    end

    it "falls back when the endpoint is unreachable" do
      client = instance_double(Azure::Client)
      allow(client).to receive(:post).and_raise(Azure::Client::Error.new("403", status: 403))

      runbook = described_class.new(endpoint: "https://x.openai.azure.com", client: client)
                               .generate(record, map)

      expect(runbook["generator"]).to eq("fallback")
    end

    it "never sends anything that looks like key material to the model" do
      sent = nil
      client = instance_double(Azure::Client)
      allow(client).to receive(:post) do |_url, **kwargs|
        sent = kwargs[:body]
        response(JSON.generate(valid_payload))
      end

      tainted = consumer_map(
        consumer(display_name: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0")
      )
      described_class.new(endpoint: "https://x.openai.azure.com", client: client)
                     .generate(record, tainted)

      user_message = sent["messages"].last["content"]
      expect(user_message).to include("[REDACTED]")
      expect(user_message).not_to include("eyJhbGci")
    end
  end
end
