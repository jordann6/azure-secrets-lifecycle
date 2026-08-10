# frozen_string_literal: true

class DashboardController < ApplicationController
  def show
    @scan = Scan.latest_complete

    return render "dashboard/empty" if @scan.nil?

    load_scan
    render "scans/show"
  end

  private

  def load_scan
    @metrics = @scan.metrics
    @analyses = @scan.analyses
                     .includes(:secret_record)
                     .by_risk
    @top_risk = @analyses.reject { |a| a.secret_record.credential? }.first(8)
    @findings = @scan.findings.by_severity.includes(:secret_record)
    @previous = Scan.complete.where(started_at: ...@scan.started_at).recent.first
  end
end
