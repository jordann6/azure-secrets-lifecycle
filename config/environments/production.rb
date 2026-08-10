Rails.application.configure do
  config.enable_reloading = false
  config.eager_load = true
  config.consider_all_requests_local = false

  config.public_file_server.enabled = true
  config.assets.compile = false

  config.log_level = ENV.fetch("RAILS_LOG_LEVEL", "info").to_sym
  config.logger = ActiveSupport::TaggedLogging.new(Logger.new($stdout))
  config.log_tags = [:request_id]

  # Container Apps terminates TLS at the ingress and forwards over http.
  config.force_ssl = false
  config.assume_ssl = true

  config.active_record.dump_schema_after_migration = false
  config.active_support.report_deprecations = false

  config.hosts.clear
end
