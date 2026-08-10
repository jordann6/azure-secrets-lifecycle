# frozen_string_literal: true

module Analyzer
  # Resolves Entra object ids to something a human can act on.
  #
  # An audit row gives back a GUID. A runbook that says "update
  # 8f2c1e04-... before invalidating the old version" is not a runbook,
  # it is a puzzle. Graph turns the GUID into a display name and an
  # identity type, which is the difference between a consumer that is
  # identified and one that merely exists.
  class Directory
    GRAPH_BASE = "https://graph.microsoft.com/v1.0"
    BATCH_SIZE = 1000

    TYPE_MAP = {
      "#microsoft.graph.servicePrincipal" => "service-principal",
      "#microsoft.graph.user" => "user",
      "#microsoft.graph.group" => "group",
      "#microsoft.graph.application" => "application"
    }.freeze

    def initialize(graph: Azure::Client.new(scope: :graph),
                   enabled: Rails.configuration.x.secops.graph_enabled)
      @graph = graph
      @enabled = enabled
      @cache = {}
    end

    # @param object_ids [Array<String>]
    # @return [Hash{String => Hash}] object_id => {display_name, identity_type}
    def resolve(object_ids)
      ids = object_ids.compact.reject(&:blank?).uniq - @cache.keys
      return @cache if ids.empty? || !@enabled

      ids.each_slice(BATCH_SIZE) do |slice|
        body = @graph.post("#{GRAPH_BASE}/directoryObjects/getByIds",
                           body: { "ids" => slice, "types" => %w[servicePrincipal user group application] })
        Array(body["value"]).each do |obj|
          @cache[obj["id"]] = {
            "display_name" => obj["displayName"],
            "identity_type" => TYPE_MAP.fetch(obj["@odata.type"], "unknown")
          }
        end
      rescue Azure::Client::Error => e
        # Directory.Read.All not granted, or an id that belongs to another
        # tenant. Unresolved consumers stay unresolved and the score
        # penalty for that is applied downstream.
        Rails.logger.warn("directory lookup failed (#{e.status}); #{slice.size} ids stay unresolved")
      end

      # Negative cache so a second scan does not re-ask for ids Graph
      # already declined to resolve.
      ids.each { |id| @cache[id] ||= nil }
      @cache
    end

    # Cache read for an id already passed through #resolve. Returns nil for
    # an id Graph could not or would not resolve.
    def lookup(object_id)
      @cache[object_id]
    end
  end
end
