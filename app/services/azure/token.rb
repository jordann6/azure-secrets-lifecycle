# frozen_string_literal: true

module Azure
  # Bearer tokens for every Azure endpoint the platform touches.
  #
  # In Container Apps the user assigned managed identity is reached through
  # IDENTITY_ENDPOINT / IDENTITY_HEADER. On a plain VM or in AKS it is the
  # IMDS address. Locally there is no identity at all, so the chain falls
  # back to the signed in az CLI. No client secret is ever configured,
  # which is the point: a platform that audits credential hygiene should
  # not be carrying a static credential of its own.
  class Token
    IMDS_ENDPOINT = "http://169.254.169.254/metadata/identity/oauth2/token"
    IMDS_API_VERSION = "2018-02-01"
    APP_SERVICE_API_VERSION = "2019-08-01"

    # Refresh a little before expiry so a long scan never trips over a
    # token that goes stale mid sweep.
    EXPIRY_SKEW_SECONDS = 300

    SCOPES = {
      arm:        "https://management.azure.com/",
      key_vault:  "https://vault.azure.net",
      graph:      "https://graph.microsoft.com",
      logs:       "https://api.loganalytics.io",
      storage:    "https://storage.azure.com/",
      monitor:    "https://monitor.azure.com/",
      openai:     "https://cognitiveservices.azure.com/",
      app_config: "https://azconfig.io",
      postgres:   "https://ossrdbms-aad.database.windows.net"
    }.freeze

    class Error < StandardError; end

    def self.instance
      @instance ||= new
    end

    # Test seam: drops every cached token.
    def self.reset!
      @instance = nil
    end

    def initialize(client_id: ENV["AZURE_CLIENT_ID"])
      @client_id = client_id
      @cache = {}
      @mutex = Mutex.new
    end

    # @param scope [Symbol] a key of SCOPES
    # @return [String] a bearer token, cached until shortly before expiry
    def for(scope)
      resource = SCOPES.fetch(scope) { raise ArgumentError, "unknown scope #{scope}" }
      @mutex.synchronize do
        cached = @cache[scope]
        return cached[:token] if cached && cached[:expires_at] > Time.now.utc

        fetched = fetch(resource)
        @cache[scope] = fetched
        fetched[:token]
      end
    end

    def header(scope)
      { "Authorization" => "Bearer #{self.for(scope)}" }
    end

    private

    def fetch(resource)
      body =
        if ENV["IDENTITY_ENDPOINT"].present? && ENV["IDENTITY_HEADER"].present?
          fetch_from_app_service(resource)
        elsif ENV["SECOPS_USE_AZ_CLI"] == "true"
          fetch_from_az_cli(resource)
        else
          fetch_from_imds(resource)
        end

      expires_on = (body["expires_on"] || body["expiresOn"]).to_s
      expires_at =
        if expires_on.match?(/\A\d+\z/)
          Time.at(expires_on.to_i).utc
        else
          Time.parse(expires_on).utc
        end

      { token: body.fetch("access_token"), expires_at: expires_at - EXPIRY_SKEW_SECONDS }
    rescue KeyError, ArgumentError, TypeError => e
      raise Error, "malformed token response for #{resource}: #{e.message}"
    end

    def fetch_from_app_service(resource)
      conn = Faraday.new(url: ENV["IDENTITY_ENDPOINT"]) { |f| f.response :json }
      resp = conn.get do |req|
        req.params["api-version"] = APP_SERVICE_API_VERSION
        req.params["resource"] = resource
        req.params["client_id"] = @client_id if @client_id.present?
        req.headers["X-IDENTITY-HEADER"] = ENV["IDENTITY_HEADER"]
      end
      raise Error, "identity endpoint returned #{resp.status}" unless resp.success?

      resp.body
    end

    def fetch_from_imds(resource)
      conn = Faraday.new(url: IMDS_ENDPOINT) do |f|
        f.request :retry, max: 3, interval: 1, backoff_factor: 2,
                  retry_statuses: [429, 500, 502, 503, 504]
        f.response :json
        f.options.timeout = 10
      end
      resp = conn.get do |req|
        req.params["api-version"] = IMDS_API_VERSION
        req.params["resource"] = resource
        req.params["client_id"] = @client_id if @client_id.present?
        req.headers["Metadata"] = "true"
      end
      raise Error, "IMDS returned #{resp.status}: #{resp.body}" unless resp.success?

      resp.body
    end

    # Local development only. Shells out to the CLI the operator is already
    # signed in with rather than asking them to mint a service principal.
    def fetch_from_az_cli(resource)
      require "open3"
      out, err, status = Open3.capture3(
        "az", "account", "get-access-token", "--resource", resource, "--output", "json"
      )
      raise Error, "az account get-access-token failed: #{err.strip}" unless status.success?

      JSON.parse(out)
    end
  end
end
