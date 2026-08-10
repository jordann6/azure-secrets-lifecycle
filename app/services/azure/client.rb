# frozen_string_literal: true

module Azure
  # Thin REST client over the Azure control plane, data planes, and Graph.
  #
  # The azure_mgmt_* Ruby SDKs were retired and never covered the Key Vault
  # or Graph data planes anyway, so this speaks the REST APIs directly. That
  # is a feature here: every request the platform makes is visible in one
  # file, which matters when the security claim is "this never reads a
  # secret value".
  class Client
    class Error < StandardError
      attr_reader :status, :body

      def initialize(message, status: nil, body: nil)
        super(message)
        @status = status
        @body = body
      end
    end

    # Azure paginates with an opaque nextLink on ARM and Graph, and with
    # @nextLink or a Link header on the Key Vault data plane.
    NEXT_LINK_KEYS = %w[nextLink @odata.nextLink @nextLink].freeze

    def initialize(scope:, token: Azure::Token.instance, timeout: 30)
      @scope = scope
      @token = token
      @timeout = timeout
    end

    def get(url, params: {})
      request(:get, url, params: params)
    end

    def post(url, body:, params: {}, scope: nil)
      request(:post, url, params: params, body: body, scope: scope)
    end

    def put(url, body:, params: {}, headers: {})
      request(:put, url, params: params, body: body, headers: headers)
    end

    # Follows nextLink until exhausted, yielding each page's `value` array.
    # Returns the flattened list.
    def get_paged(url, params: {}, value_key: "value", max_pages: 100)
      items = []
      next_url = url
      next_params = params
      pages = 0

      while next_url && pages < max_pages
        body = get(next_url, params: next_params)
        items.concat(Array(body[value_key]))
        next_url = NEXT_LINK_KEYS.filter_map { |k| body[k] }.first
        # nextLink already carries the query string.
        next_params = {}
        pages += 1
      end

      items
    end

    private

    def request(method, url, params: {}, body: nil, headers: {}, scope: nil)
      conn = connection
      resp = conn.public_send(method) do |req|
        req.url url
        params.each { |k, v| req.params[k.to_s] = v }
        req.headers.merge!(@token.header(scope || @scope))
        req.headers.merge!(headers)
        if body
          req.headers["Content-Type"] ||= "application/json"
          req.body = body.is_a?(String) ? body : JSON.generate(body)
        end
      end

      unless resp.success?
        raise Error.new(
          "#{method.to_s.upcase} #{sanitize(url)} returned #{resp.status}",
          status: resp.status, body: resp.body
        )
      end

      resp.body.is_a?(Hash) ? resp.body : {}
    end

    def connection
      @connection ||= Faraday.new do |f|
        f.request :retry,
                  max: 4,
                  interval: 1,
                  backoff_factor: 2,
                  retry_statuses: [408, 429, 500, 502, 503, 504],
                  # Azure honours Retry-After on 429 for Graph and ARM.
                  retry_block: ->(env:, **) { Rails.logger.warn("azure retry #{env.status} #{sanitize(env.url.to_s)}") }
        f.response :json, content_type: /\bjson$/
        f.options.timeout = @timeout
        f.options.open_timeout = 10
      end
    end

    # URLs can carry SAS tokens or continuation tokens; never log them whole.
    def sanitize(url)
      url.to_s.split("?").first
    end
  end
end
