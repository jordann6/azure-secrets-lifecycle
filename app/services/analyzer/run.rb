# frozen_string_literal: true

module Analyzer
  # Analyzes one scan end to end: consumer maps, readiness scores,
  # runbooks for the highest risk resources, control mapped findings,
  # metrics, and the evidence artifact.
  class Run
    def initialize(max_runbooks: Rails.configuration.x.secops.max_runbooks,
                   log_analytics: nil,
                   consumer_map: nil,
                   runbook: nil,
                   blob_writer: nil,
                   sentinel: nil)
      @max_runbooks = max_runbooks
      @log_analytics = log_analytics
      @consumer_map = consumer_map
      @runbook = runbook
      @blob_writer = blob_writer
      @sentinel = sentinel
    end

    def call(scan)
      records = scan.secret_records.to_a
      Rails.logger.info("analyzing scan #{scan.scan_id}: #{records.size} resources")

      maps = build_maps
      analyses = score_all(scan, records, maps)
      attach_runbooks(analyses)

      findings = derive_findings(scan, analyses)
      metrics = Metrics.new(scan, analyses, findings).call

      persist(scan, analyses, findings)

      scan.update!(status: "analyzed", metrics: metrics)

      scan.update!(evidence_blob: blob_writer.write(scan, findings, metrics))
      scan.update!(sentinel_rows: sentinel.push(scan, findings))

      Rails.logger.info(
        "scan #{scan.scan_id} analyzed: #{analyses.size} resources, " \
        "#{findings.size} findings, " \
        "#{analyses.count { |a| a[:runbook] }} runbooks"
      )

      scan
    end

    private

    def build_maps
      rows = log_analytics.access_events
      maps = consumer_map.build(rows)
      Rails.logger.info("consumer maps built for #{maps.size} resources from #{rows.size} access rows")
      maps
    rescue StandardError => e
      # A workspace that is not receiving diagnostic logs yet is a common
      # state on day one, and the run is still worth completing: every
      # resource simply comes back orphaned, which is exactly what the
      # evidence should say when there is no access telemetry.
      Rails.logger.error("consumer map build failed: #{e.class}: #{e.message}")
      {}
    end

    def score_all(scan, records, maps)
      records.map do |record|
        cmap = consumer_map.match(record, maps)
        score = Scoring.readiness_score(record, cmap)

        {
          record: record,
          scan_id: scan.id,
          secret_record_id: record.id,
          consumer_map: cmap,
          readiness_score: score,
          risk_tier: Scoring.risk_tier(score),
          runbook: nil
        }
      end
    end

    # Runbooks cost a model call each, so they go to the resources where a
    # rotation plan actually changes a decision: the high risk tier,
    # worst readiness first, bounded by MAX_RUNBOOKS.
    def attach_runbooks(analyses)
      targets = analyses
                .select { |a| a[:risk_tier] == "high" }
                .sort_by { |a| a[:readiness_score] }
                .first(@max_runbooks)

      targets.each do |a|
        a[:runbook] = runbook.generate(a[:record], a[:consumer_map])
      end
    end

    def derive_findings(scan, analyses)
      mapper = Evidence::Mapper.new
      analyses.flat_map do |a|
        # Mapper reads through the Analysis interface, so it gets an
        # unsaved instance rather than a second shape to keep in sync.
        analysis = Analysis.new(
          scan_id: scan.id,
          secret_record: a[:record],
          consumer_map: a[:consumer_map],
          readiness_score: a[:readiness_score],
          risk_tier: a[:risk_tier]
        )
        mapper.derive(a[:record], analysis).map do |f|
          f.merge(scan_id: scan.id, secret_record_id: a[:record].id)
        end
      end
    end

    def persist(scan, analyses, findings)
      now = Time.now.utc

      Scan.transaction do
        scan.analyses.delete_all
        scan.findings.delete_all

        analysis_rows = analyses.map do |a|
          {
            scan_id: a[:scan_id],
            secret_record_id: a[:secret_record_id],
            readiness_score: a[:readiness_score],
            risk_tier: a[:risk_tier],
            consumer_map: Redact.call(a[:consumer_map]),
            runbook: a[:runbook] && Redact.call(a[:runbook]),
            created_at: now,
            updated_at: now
          }
        end
        Analysis.insert_all!(analysis_rows) if analysis_rows.any?

        finding_rows = findings.map { |f| f.merge(created_at: now, updated_at: now) }
        Finding.insert_all!(finding_rows) if finding_rows.any?
      end
    end

    def log_analytics = @log_analytics ||= LogAnalytics.new
    def consumer_map = @consumer_map ||= ConsumerMap.new
    def runbook = @runbook ||= Runbook.new
    def blob_writer = @blob_writer ||= Evidence::BlobWriter.new
    def sentinel = @sentinel ||= Evidence::Sentinel.new
  end
end
