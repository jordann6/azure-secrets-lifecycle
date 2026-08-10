# frozen_string_literal: true

module Scanner
  # Bounded worker pool for the sweeps.
  #
  # Sweeping every certificate policy in every vault is one HTTP call per
  # certificate, so it wants concurrency, but Key Vault and Graph both
  # throttle hard and an unbounded fan out just converts the scan into a
  # wall of 429s. The bound is the whole point.
  #
  # Errors are collected rather than raised: one unreachable vault must not
  # cost the scan every other vault's inventory. The caller decides what a
  # partial sweep means.
  class Pool
    Result = Struct.new(:values, :errors, keyword_init: true) do
      def partial? = errors.any?
    end

    def initialize(concurrency: 8)
      @concurrency = [concurrency.to_i, 1].max
    end

    # Runs the block once per item, in at most `concurrency` threads.
    # Nil results are dropped; arrays are flattened one level, so a worker
    # can return either a single record or a batch.
    def map(items)
      items = Array(items)
      return Result.new(values: [], errors: []) if items.empty?

      queue = Queue.new
      items.each { |item| queue << item }
      values = Concurrent::Array.new
      errors = Concurrent::Array.new

      workers = Array.new([@concurrency, items.size].min) do
        Thread.new do
          while (item = pop(queue))
            begin
              out = yield(item)
              values.concat(Array(out).compact) unless out.nil?
            rescue StandardError => e
              errors << { item: describe(item), error: "#{e.class}: #{e.message}" }
              Rails.logger.warn("sweep worker failed on #{describe(item)}: #{e.class}: #{e.message}")
            end
          end
        end
      end
      workers.each(&:join)

      Result.new(values: values.to_a, errors: errors.to_a)
    end

    private

    def pop(queue)
      queue.pop(true)
    rescue ThreadError
      nil
    end

    # Items are vault descriptors or object ids; never log a whole object.
    def describe(item)
      case item
      when Hash then item[:name] || item["name"] || item[:vault_name] || "item"
      when String then item.split("?").first
      else item.class.name
      end
    end
  end
end
