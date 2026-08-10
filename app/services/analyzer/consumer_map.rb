# frozen_string_literal: true

module Analyzer
  # Turns raw access rows into a per resource consumer map: who actually
  # reads this secret, how often, and how recently.
  #
  # This is the question the whole platform exists to answer. Azure Policy
  # and Defender for Cloud will both tell you a secret has no expiry set.
  # Neither will tell you which workloads break if you rotate it, which is
  # the real reason nobody rotates it.
  class ConsumerMap
    EMPTY = { "consumers" => [], "total_reads" => 0, "sources" => [] }.freeze

    def initialize(directory: Directory.new)
      @directory = directory
    end

    # @param rows [Array<Hash>] access rows from Analyzer::LogAnalytics
    # @return [Hash{String => Hash}] resource_id => consumer map
    def build(rows)
      rows = rows.select { |r| r["resource_id"].present? }
      resolve_names(rows)

      rows.group_by { |r| normalize_resource_id(r["resource_id"]) }
          .transform_values { |group| build_one(group) }
    end

    VAULT_COLLECTIONS = %w[secrets keys certificates].freeze

    # Key Vault audit rows carry the versioned object uri; the inventory
    # tracks the logical object. Trimming the version off both sides is
    # what keeps a rotation that adds a version from looking like a brand
    # new consumer set.
    #
    # Only Key Vault uris get trimmed. An App Configuration request uri
    # has no version segment and a multi part key, so cutting it at two
    # segments would collapse every key in the store into one bucket.
    def normalize_resource_id(resource_id)
      uri = URI.parse(resource_id.to_s)
      segments = uri.path.split("/").reject(&:empty?)

      if uri.host.to_s.end_with?("vault.azure.net") &&
         segments.size >= 2 && VAULT_COLLECTIONS.include?(segments[0])
        return "#{uri.scheme}://#{uri.host}/#{segments[0]}/#{segments[1]}".downcase
      end

      # Everything else keeps its full path and loses only the query
      # string, which carries api-version and label rather than identity.
      "#{uri.scheme}://#{uri.host}#{uri.path}".downcase
    rescue URI::InvalidURIError, NoMethodError
      resource_id.to_s.downcase
    end

    # Matches an inventory record to its consumer map.
    #
    # Key Vault matches on the normalized object uri. App Configuration
    # audit rows carry the request uri, which embeds the key but also the
    # api-version and label query string, so that side falls back to a
    # containment check on the key name.
    def match(record, maps)
      direct = maps[normalize_resource_id(record.resource_id)]
      return direct if direct

      if record.kind == "app_config_kv"
        key = record.name.split("$").first.to_s.downcase
        found = maps.find { |resource_id, _| key.present? && resource_id.include?(key) }
        return found.last if found
      end

      EMPTY.dup
    end

    private

    def build_one(group)
      by_principal = Hash.new { |h, k| h[k] = { count: 0, last: nil, ops: Set.new, appid: nil } }

      group.each do |row|
        principal_id = row["principal_id"].presence
        entry = by_principal[principal_id]
        entry[:count] += row["access_count"].to_i
        entry[:appid] ||= row["principal_appid"].presence
        entry[:ops] << row["operation"]
        last = parse_time(row["last_accessed"])
        entry[:last] = [entry[:last], last].compact.max
      end

      consumers = by_principal.map do |principal_id, agg|
        resolved = principal_id ? @directory.lookup(principal_id) : nil
        {
          "principal_id" => principal_id,
          "principal_appid" => agg[:appid],
          "display_name" => resolved&.dig("display_name"),
          "identity_type" => resolved&.dig("identity_type") || (principal_id ? "unresolved" : "unknown"),
          "access_count" => agg[:count],
          "operations" => agg[:ops].to_a.sort,
          "last_accessed" => agg[:last]&.iso8601
        }
      end

      consumers.sort_by! { |c| -c["access_count"] }

      {
        "consumers" => consumers,
        "total_reads" => consumers.sum { |c| c["access_count"] },
        "sources" => group.map { |r| r["operation"] }.uniq.sort
      }
    end

    def resolve_names(rows)
      @directory.resolve(rows.map { |r| r["principal_id"] })
    end

    def parse_time(value)
      return nil if value.blank?

      Time.parse(value.to_s).utc
    rescue ArgumentError, TypeError
      nil
    end
  end
end
