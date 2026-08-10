threads_count = ENV.fetch("RAILS_MAX_THREADS", 5).to_i
threads threads_count, threads_count

port ENV.fetch("PORT", 3000)
environment ENV.fetch("RAILS_ENV", "development")

plugin :tmp_restart

# The Container App runs one replica for the web role, and it serves the
# dashboard only. Pipeline execution lives in the scheduled Container Apps
# Job, so nothing here spawns a worker.
