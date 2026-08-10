# frozen_string_literal: true

# Operator tasks. Everything here except secops:scan and secops:analyze
# runs as the human operator through the az CLI, not as the platform's
# managed identity. That split is deliberate: the platform identity can
# only read metadata, so it could not create this test estate even if the
# code asked it to.

namespace :secops do
  desc "Run one full pipeline: sweep, analyze, publish"
  task scan: :environment do
    # The inline queue adapter runs each perform_later synchronously, so
    # this one call drains the whole chain and the task's exit code is the
    # pipeline's.
    scan = ScanJob.perform_now
    abort "scan failed" if scan.nil? || scan.reload.status == "failed"
    puts "scan #{scan.scan_id}: #{scan.resource_count} resources, " \
         "#{scan.metrics['finding_count']} findings, " \
         "#{scan.metrics['runbooks_generated']} runbooks, " \
         "#{scan.duration_seconds}s"
    puts "evidence: #{scan.evidence_blob || 'not written (no evidence account configured)'}"
    puts "sentinel rows: #{scan.sentinel_rows || 0}"
  end

  desc "Re-analyze the latest scan without re-sweeping"
  task analyze: :environment do
    scan = Scan.recent.first
    abort "no scans found" if scan.nil?

    Analyzer::Run.new.call(scan)
    puts "re-analyzed #{scan.scan_id}"
  end

  desc "Prove the least-privilege posture against the live cloud"
  task verify_posture: :environment do
    checks = Posture::Verify.new.call
    width = checks.map { |c| c.name.length }.max

    puts
    puts format("%-#{width}s  %-6s  %-18s  %s", "CHECK", "RESULT", "EXPECTATION", "DETAIL")
    checks.each do |c|
      puts format("%-#{width}s  %-6s  %-18s  %s", c.name, c.status, c.expectation, c.detail)
    end

    failed = checks.reject(&:passed)
    puts
    puts "#{checks.size - failed.size}/#{checks.size} checks passed"

    # Non-zero exit so this can gate a pipeline. A platform that claims it
    # cannot read secret values should fail its own build the moment that
    # stops being true.
    abort "posture verification failed: #{failed.map(&:name).join(', ')}" if failed.any?
  end

  desc "Print the latest scan metrics as JSON"
  task metrics: :environment do
    scan = Scan.latest_complete
    abort "no completed scans" if scan.nil?

    puts JSON.pretty_generate(scan.metrics)
  end

  # Seeding and teardown live in scripts/seed.sh and run on the operator's
  # workstation under their az CLI session. They are not rake tasks
  # because they must not run as the platform identity, which holds
  # metadata-read roles only and cannot write to any of these services.
  # See `make seed`, `make traffic`, and `make destroy`.
end
