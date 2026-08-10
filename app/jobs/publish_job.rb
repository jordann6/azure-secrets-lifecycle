# frozen_string_literal: true

# Stage three. Marks the scan current and enforces scan retention.
#
# The AWS version needed a reporter Lambda here to render a static HTML
# file into an S3 website bucket, because nothing in that pipeline could
# serve a page. Rails can, so the dashboard reads live from Postgres and
# this stage collapses to the two things that still need doing: flipping
# the scan to reported, and keeping the database from growing forever on
# a daily schedule.
#
# Evidence artifacts are deliberately not pruned here. They live in an
# immutable container with their own retention policy, which is the whole
# point of writing them somewhere other than the application database.
class PublishJob < ApplicationJob
  queue_as :default

  RETAINED_SCANS = ENV.fetch("RETAINED_SCANS", "30").to_i

  def perform(scan_id)
    scan = Scan.find_by!(scan_id: scan_id)
    scan.update!(status: "reported")

    prune
    scan
  end

  private

  def prune
    keep = Scan.recent.limit(RETAINED_SCANS).pluck(:id)
    stale = Scan.where.not(id: keep)
    count = stale.count
    return if count.zero?

    stale.find_each(&:destroy)
    Rails.logger.info("pruned #{count} scans beyond the #{RETAINED_SCANS} scan retention window")
  end
end
