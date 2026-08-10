# frozen_string_literal: true

module Scanner
  # Sweeps Entra ID app registration credentials through Microsoft Graph.
  #
  # This is the IAM access key analogue: a long lived credential attached
  # to a workload identity, typically created once during onboarding and
  # then forgotten until the day it expires and takes production with it.
  # Graph returns the credential descriptor (display name, start, end,
  # hint) and never the secret text, so there is nothing to redact at the
  # source, but records pass through the redactor anyway.
  #
  # Federated identity credentials are swept too and scored as the good
  # outcome: an app registration that authenticates with workload identity
  # federation has no secret to rotate at all.
  class EntraCredentials
    GRAPH_BASE = "https://graph.microsoft.com/v1.0"
    PAGE_SIZE = 100

    SELECT = "id,appId,displayName,createdDateTime,passwordCredentials,keyCredentials"

    def initialize(concurrency: 4, graph: Azure::Client.new(scope: :graph))
      @graph = graph
      @pool = Pool.new(concurrency: concurrency)
    end

    def sweep(scan_id:, now: Time.now.utc)
      apps = list_applications
      Rails.logger.info("entra sweep: #{apps.size} app registrations")

      @pool.map(apps) { |app| credentials_for(app, scan_id, now) }
    end

    def list_applications
      @graph.get_paged("#{GRAPH_BASE}/applications",
                       params: { "$select" => SELECT, "$top" => PAGE_SIZE })
    end

    private

    def credentials_for(app, scan_id, now)
      federated = federated_count(app["id"])

      passwords = Array(app["passwordCredentials"]).map do |cred|
        build_record(app, cred, "password", federated, scan_id, now)
      end
      keys = Array(app["keyCredentials"]).map do |cred|
        build_record(app, cred, "certificate", federated, scan_id, now)
      end

      passwords + keys
    end

    def build_record(app, cred, credential_kind, federated, scan_id, now)
      start_at = Normalize.parse_time(cred["startDateTime"])
      end_at = Normalize.parse_time(cred["endDateTime"])
      key_id = cred["keyId"]

      Normalize.finish(
        {
          resource_id: "/applications/#{app['appId']}/credentials/#{key_id}",
          name: "#{app['displayName']}:#{cred['displayName'].presence || key_id.to_s[0, 8]}",
          kind: "entra_app_credential",
          subscription_id: nil,
          resource_group: nil,
          vault_name: nil,
          location: "global",
          source_created_at: start_at,
          source_updated_at: start_at,
          expires_at: end_at,
          enabled: end_at.nil? || end_at > now,
          # An app registration that already has federated credentials has
          # a demonstrated migration path off static secrets, which is the
          # only rotation story here worth calling verified.
          rotation_enabled: federated.positive?,
          rotation_days: credential_lifetime_days(start_at, end_at),
          credential_kind: credential_kind,
          federated_credential_count: federated,
          app_id: app["appId"],
          access_model: {
            "rbac_authorization" => true,
            "read_principals" => [{ "object_id" => app["id"], "permissions" => ["owner"] }]
          },
          tags: {}
        },
        scan_id: scan_id, now: now
      )
    end

    def federated_count(object_id)
      body = @graph.get("#{GRAPH_BASE}/applications/#{object_id}/federatedIdentityCredentials")
      Array(body["value"]).size
    rescue Azure::Client::Error => e
      Rails.logger.debug("federated credential read failed for #{object_id}: #{e.status}")
      0
    end

    def credential_lifetime_days(start_at, end_at)
      return 0 unless start_at && end_at

      ((end_at - start_at) / 86_400).floor
    end
  end
end
