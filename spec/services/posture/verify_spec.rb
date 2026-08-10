# frozen_string_literal: true

RSpec.describe Posture::Verify do
  subject(:verifier) do
    described_class.new(vault_name: "kv", app_config_endpoint: "",
                        evidence_account: "", evidence_container: "evidence",
                        workspace_id: nil)
  end

  def check(checks, name) = checks.find { |c| c.name == name }

  def stub_kv(client)
    allow(Azure::Client).to receive(:new).and_call_original
    allow(Azure::Client).to receive(:new).with(scope: :key_vault).and_return(client)
  end

  let(:secret_list) do
    { "value" => [{ "id" => "https://kv.vault.azure.net/secrets/db-primary",
                    "attributes" => { "enabled" => true } }] }
  end

  before do
    # Everything outside Key Vault is disabled or unreachable in these
    # examples; the Key Vault checks are the ones that carry the claim.
    allow(Analyzer::LogAnalytics).to receive(:new).and_raise(ArgumentError, "no workspace")
    allow(Rails.configuration.x.secops).to receive(:graph_enabled).and_return(false)
  end

  describe "the metadata-only guarantee" do
    it "passes when reading a secret value is denied with 403" do
      client = instance_double(Azure::Client)
      allow(client).to receive(:get).with("https://kv.vault.azure.net/secrets", any_args)
                                    .and_return(secret_list)
      allow(client).to receive(:get).with("https://kv.vault.azure.net/certificates", any_args)
                                    .and_return("value" => [])
      allow(client).to receive(:get).with("https://kv.vault.azure.net/secrets/db-primary", any_args)
                                    .and_raise(Azure::Client::Error.new("forbidden", status: 403))
      stub_kv(client)

      denied = check(verifier.call, "key_vault.get_secret_value")
      expect(denied.passed).to be(true)
      expect(denied.detail).to include("denied as designed")
    end

    it "FAILS loudly when a secret value can actually be read" do
      # This is the whole point of the check. If a role assignment ever
      # widens, the platform must fail its own verification rather than
      # keep advertising a guarantee it no longer provides.
      client = instance_double(Azure::Client)
      allow(client).to receive(:get).with("https://kv.vault.azure.net/secrets", any_args)
                                    .and_return(secret_list)
      allow(client).to receive(:get).with("https://kv.vault.azure.net/certificates", any_args)
                                    .and_return("value" => [])
      allow(client).to receive(:get).with("https://kv.vault.azure.net/secrets/db-primary", any_args)
                                    .and_return("value" => "hunter2")
      stub_kv(client)

      leaked = check(verifier.call, "key_vault.get_secret_value")
      expect(leaked.passed).to be(false)
      expect(leaked.detail).to include("SECURITY REGRESSION")
    end

    it "does not accept a non-403 denial as proof of the guarantee" do
      # A 404 or a 401 means something else went wrong. Treating it as a
      # pass would let a misconfigured vault masquerade as a locked one.
      client = instance_double(Azure::Client)
      allow(client).to receive(:get).with("https://kv.vault.azure.net/secrets", any_args)
                                    .and_return(secret_list)
      allow(client).to receive(:get).with("https://kv.vault.azure.net/certificates", any_args)
                                    .and_return("value" => [])
      allow(client).to receive(:get).with("https://kv.vault.azure.net/secrets/db-primary", any_args)
                                    .and_raise(Azure::Client::Error.new("not found", status: 404))
      stub_kv(client)

      expect(check(verifier.call, "key_vault.get_secret_value").passed).to be(false)
    end
  end

  describe "the positive checks" do
    it "fails listing when Key Vault Reader is not effective" do
      client = instance_double(Azure::Client)
      allow(client).to receive(:get).and_raise(Azure::Client::Error.new("forbidden", status: 403))
      stub_kv(client)

      listing = check(verifier.call, "key_vault.list_secrets")
      expect(listing.passed).to be(false)
      expect(listing.detail).to include("should permit listing")
    end

    it "reports certificate policy separately, since rotation detection depends on it" do
      client = instance_double(Azure::Client)
      allow(client).to receive(:get).with("https://kv.vault.azure.net/secrets", any_args)
                                    .and_return(secret_list)
      allow(client).to receive(:get).with("https://kv.vault.azure.net/certificates", any_args)
                                    .and_return("value" => [{ "id" => "https://kv.vault.azure.net/certificates/tls" }])
      allow(client).to receive(:get).with("https://kv.vault.azure.net/certificates/tls/policy", any_args)
                                    .and_raise(Azure::Client::Error.new("forbidden", status: 403))
      allow(client).to receive(:get).with("https://kv.vault.azure.net/secrets/db-primary", any_args)
                                    .and_raise(Azure::Client::Error.new("forbidden", status: 403))
      stub_kv(client)

      policy = check(verifier.call, "key_vault.certificate_policy")
      expect(policy.passed).to be(false)
      expect(policy.detail).to include("rotation detection is broken")
    end
  end

  describe "check reporting" do
    it "labels every check with a status the operator can scan" do
      client = instance_double(Azure::Client)
      allow(client).to receive(:get).and_raise(Azure::Client::Error.new("forbidden", status: 403))
      stub_kv(client)

      checks = verifier.call
      expect(checks).to all(satisfy { |c| %w[PASS FAIL].include?(c.status) })
      expect(checks.map(&:name)).to include("key_vault.list_secrets", "key_vault.get_secret_value")
    end
  end
end
