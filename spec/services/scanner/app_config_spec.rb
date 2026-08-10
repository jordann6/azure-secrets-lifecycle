# frozen_string_literal: true

RSpec.describe Scanner::AppConfig do
  describe "#store_from_endpoint" do
    subject(:sweeper) do
      described_class.new(subscription_id: "sub-1", endpoint: "https://s.azconfig.io")
    end

    it "fills in the control plane fields the ARM lookup would have provided" do
      # Addressing the store by endpoint skips list_stores entirely. The
      # shape still has to be complete: a store without access_model
      # produced a NOT NULL violation that failed the whole scan.
      store = sweeper.store_from_endpoint

      expect(store[:access_model]).to include("rbac_authorization", "read_principals")
      expect(store).to have_key(:resource_group)
      expect(store).to have_key(:location)
      expect(store[:name]).to eq("s")
    end

    it "marks the properties it could not read rather than inventing them" do
      expect(sweeper.store_from_endpoint[:access_model]["public_network_access"])
        .to eq("Unknown")
    end
  end
end
