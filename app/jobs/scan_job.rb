# frozen_string_literal: true

# Stage one of the pipeline. Sweeps the subscription and hands the scan id
# to the analyzer.
#
# The AWS design chained Lambdas with on-success destinations. Here the
# chain is Solid Queue enqueuing the next job inside the same transaction
# as the scan write, which is a stronger guarantee: a scan that committed
# always has an analysis enqueued, and one that rolled back has neither.
class ScanJob < ApplicationJob
  queue_as :default

  def perform
    outcome = Scanner::Sweep.new.call

    if outcome.records.empty? && outcome.errors.any?
      outcome.scan.update!(status: "failed")
      Rails.logger.error("scan #{outcome.scan.scan_id} swept nothing; not analyzing")
      return outcome.scan
    end

    AnalyzeJob.perform_later(outcome.scan.scan_id)
    outcome.scan
  end
end
