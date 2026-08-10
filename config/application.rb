require_relative "boot"

require "rails"
require "active_model/railtie"
require "active_job/railtie"
require "active_record/railtie"
require "action_controller/railtie"
require "action_view/railtie"

Bundler.require(*Rails.groups)

module AzureSecretsLifecycle
  class Application < Rails::Application
    config.load_defaults 8.0

    # app/services is the whole platform: scanner, analyzer, evidence layer.
    config.autoload_lib(ignore: %w[tasks])
    config.autoload_paths << Rails.root.join("app/services")
    config.eager_load_paths << Rails.root.join("app/services")

    # The pipeline is a scheduled batch job, not a queue. The three stages
    # run back to back inside one Container Apps Job execution, so an
    # inline adapter is the whole scheduler: no broker, no worker process,
    # no second database, and the job's exit code is the pipeline's exit
    # code. ActiveJob still earns its place for the retry and discard
    # policy in ApplicationJob and for keeping the stages independently
    # testable.
    config.active_job.queue_adapter = :inline

    config.time_zone = "UTC"
    config.active_record.default_timezone = :utc

    # No cookies, no sessions, no forms. The dashboard is read only and
    # fronted by the Container App ingress.
    config.session_store :disabled

    config.x.secops = ActiveSupport::OrderedOptions.new
    config.x.secops.lookback_days       = ENV.fetch("LOOKBACK_DAYS", "90").to_i
    config.x.secops.max_runbooks        = ENV.fetch("MAX_RUNBOOKS", "5").to_i
    config.x.secops.subscription_id     = ENV["AZURE_SUBSCRIPTION_ID"]
    config.x.secops.workspace_id        = ENV["LOG_ANALYTICS_WORKSPACE_ID"]
    config.x.secops.evidence_account    = ENV["EVIDENCE_STORAGE_ACCOUNT"]
    config.x.secops.evidence_container  = ENV.fetch("EVIDENCE_CONTAINER", "evidence")
    config.x.secops.sentinel_enabled    = ENV.fetch("SENTINEL_ENABLED", "false") == "true"
    config.x.secops.dce_endpoint        = ENV["DCE_ENDPOINT"]
    config.x.secops.dcr_immutable_id    = ENV["DCR_IMMUTABLE_ID"]
    config.x.secops.dcr_stream          = ENV.fetch("DCR_STREAM", "Custom-SecOpsFindings_CL")
    config.x.secops.openai_endpoint     = ENV["AZURE_OPENAI_ENDPOINT"]
    config.x.secops.openai_deployment   = ENV.fetch("AZURE_OPENAI_DEPLOYMENT", "gpt-4o-mini")
    config.x.secops.graph_enabled       = ENV.fetch("GRAPH_ENABLED", "true") == "true"
    config.x.secops.app_config_endpoint = ENV["APP_CONFIG_ENDPOINT"]
    config.x.secops.scan_concurrency    = ENV.fetch("SCAN_CONCURRENCY", "8").to_i
  end
end
