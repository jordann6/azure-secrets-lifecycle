# frozen_string_literal: true

# Stage two. Builds consumer maps, scores readiness, synthesizes runbooks,
# derives findings, writes evidence, and exports to Sentinel.
class AnalyzeJob < ApplicationJob
  queue_as :default

  def perform(scan_id = nil)
    scan = scan_id ? Scan.find_by!(scan_id: scan_id) : Scan.recent.first
    raise ActiveRecord::RecordNotFound, "no scans to analyze" if scan.nil?

    Analyzer::Run.new.call(scan)
    PublishJob.perform_later(scan.scan_id)
    scan
  rescue StandardError => e
    scan&.update(status: "failed")
    raise e
  end
end
