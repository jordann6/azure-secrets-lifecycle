# frozen_string_literal: true

class ScansController < ApplicationController
  before_action :set_scan, only: %i[show evidence]

  def index
    @scans = Scan.recent.limit(50)
  end

  def show
    @metrics = @scan.metrics
    @analyses = @scan.analyses.includes(:secret_record).by_risk
    @top_risk = @analyses.reject { |a| a.secret_record.credential? }.first(8)
    @findings = @scan.findings.by_severity.includes(:secret_record)
    @previous = Scan.complete.where(started_at: ...@scan.started_at).recent.first
  end

  # Serves the evidence artifact for this scan straight out of Postgres
  # rather than proxying the immutable blob. The blob is the record of
  # authority; this is the convenience copy, and it says so.
  def evidence
    findings = @scan.findings.map do |f|
      {
        finding_id: f.finding_id, finding_type: f.finding_type, title: f.title,
        severity: f.severity, control_ids: f.control_ids, resource_id: f.resource_id,
        evidence_timestamp: f.evidence_timestamp, remediation_status: f.remediation_status,
        owner_tag: f.owner_tag, readiness_score: f.readiness_score
      }
    end

    artifact = Evidence::BlobWriter.new.artifact(@scan, findings, @scan.metrics)
    artifact["source"] = "application database copy; the container blob is the record of authority"
    artifact["blob_path"] = @scan.evidence_blob

    render json: artifact
  end

  private

  def set_scan
    @scan = Scan.find_by!(scan_id: params[:id])
  end
end
