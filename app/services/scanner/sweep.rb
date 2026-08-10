# frozen_string_literal: true

module Scanner
  # Runs every sweep, normalizes the results, and writes one scan's
  # inventory in a single transaction.
  #
  # A sweep that fails is recorded, not fatal. Graph permissions are a
  # separate consent grant from the subscription role assignments, and a
  # tenant that has not granted Application.Read.All should still get a
  # Key Vault inventory rather than a stack trace.
  class Sweep
    Outcome = Struct.new(:scan, :records, :errors, keyword_init: true)

    def initialize(subscription_id: Rails.configuration.x.secops.subscription_id,
                   app_config_endpoint: Rails.configuration.x.secops.app_config_endpoint,
                   graph_enabled: Rails.configuration.x.secops.graph_enabled,
                   concurrency: Rails.configuration.x.secops.scan_concurrency)
      @subscription_id = subscription_id
      @app_config_endpoint = app_config_endpoint
      @graph_enabled = graph_enabled
      @concurrency = concurrency
    end

    def call(scan_id: nil, now: Time.now.utc)
      raise ArgumentError, "AZURE_SUBSCRIPTION_ID is not set" if @subscription_id.blank?

      scan_id ||= Scan.generate_id(now)
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      scan = Scan.create!(scan_id: scan_id, status: "running", started_at: now)

      records = []
      errors = []

      sweeps(now).each do |name, runner|
        result = run_sweep(name, runner, scan_id, now)
        records.concat(result.values)
        errors.concat(result.errors.map { |e| e.merge(sweep: name) })
      end

      persist(scan, records)

      duration_ms = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round
      scan.update!(
        finished_at: Time.now.utc,
        duration_ms: duration_ms,
        resource_count: records.size,
        sweep_errors: errors
      )

      Rails.logger.info(
        "scan #{scan_id} swept #{records.size} resources in #{duration_ms}ms " \
        "(#{errors.size} sweep errors)"
      )

      Outcome.new(scan: scan, records: records, errors: errors)
    end

    private

    def sweeps(_now)
      list = {
        "key_vault" => -> {
          KeyVault.new(subscription_id: @subscription_id, concurrency: @concurrency)
        },
        "app_config" => -> {
          AppConfig.new(subscription_id: @subscription_id, endpoint: @app_config_endpoint)
        }
      }
      list["entra"] = -> { EntraCredentials.new } if @graph_enabled
      list
    end

    def run_sweep(name, runner, scan_id, now)
      runner.call.sweep(scan_id: scan_id, now: now)
    rescue StandardError => e
      Rails.logger.error("#{name} sweep failed: #{e.class}: #{e.message}")
      Pool::Result.new(values: [], errors: [{ item: name, error: "#{e.class}: #{e.message}" }])
    end

    def persist(scan, records)
      # Two sweeps can legitimately surface the same logical resource (an
      # App Configuration Key Vault reference and the referenced secret
      # share nothing, but a vault listed twice across resource groups
      # would). Last write wins on resource_id within a scan.
      rows = records
             .map { |r| SecretRecord.attributes_from_sweep(r) }
             .index_by { |r| r[:resource_id] }
             .values
             .map { |r| r.merge(scan_id: scan.id, created_at: Time.now.utc, updated_at: Time.now.utc) }

      return if rows.empty?

      SecretRecord.insert_all!(rows)
    end
  end
end
