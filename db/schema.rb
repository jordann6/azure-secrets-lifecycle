# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[8.0].define(version: 2026_08_10_000004) do
  # These are extensions that must be enabled in order to support this database
  enable_extension "pg_catalog.plpgsql"

  create_table "analyses", force: :cascade do |t|
    t.bigint "scan_id", null: false
    t.bigint "secret_record_id", null: false
    t.integer "readiness_score", default: 0, null: false
    t.string "risk_tier", default: "low", null: false
    t.jsonb "consumer_map", default: {}, null: false
    t.jsonb "runbook"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["risk_tier"], name: "index_analyses_on_risk_tier"
    t.index ["scan_id", "readiness_score"], name: "index_analyses_on_scan_id_and_readiness_score"
    t.index ["scan_id", "secret_record_id"], name: "index_analyses_on_scan_id_and_secret_record_id", unique: true
    t.index ["scan_id"], name: "index_analyses_on_scan_id"
    t.index ["secret_record_id"], name: "index_analyses_on_secret_record_id"
  end

  create_table "findings", force: :cascade do |t|
    t.bigint "scan_id", null: false
    t.bigint "secret_record_id", null: false
    t.string "finding_id", null: false
    t.string "finding_type", null: false
    t.string "title", null: false
    t.string "severity", null: false
    t.jsonb "control_ids", default: [], null: false
    t.string "resource_id", null: false
    t.datetime "evidence_timestamp", null: false
    t.string "remediation_status", default: "OPEN", null: false
    t.string "owner_tag", default: "unassigned", null: false
    t.integer "readiness_score", default: 0, null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["finding_id"], name: "index_findings_on_finding_id", unique: true
    t.index ["scan_id", "finding_type"], name: "index_findings_on_scan_id_and_finding_type"
    t.index ["scan_id"], name: "index_findings_on_scan_id"
    t.index ["secret_record_id"], name: "index_findings_on_secret_record_id"
    t.index ["severity"], name: "index_findings_on_severity"
  end

  create_table "scans", force: :cascade do |t|
    t.string "scan_id", null: false
    t.string "status", default: "running", null: false
    t.datetime "started_at", null: false
    t.datetime "finished_at"
    t.integer "duration_ms"
    t.integer "resource_count", default: 0, null: false
    t.jsonb "metrics", default: {}, null: false
    t.jsonb "sweep_errors", default: [], null: false
    t.string "evidence_blob"
    t.integer "sentinel_rows"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["scan_id"], name: "index_scans_on_scan_id", unique: true
    t.index ["started_at"], name: "index_scans_on_started_at"
  end

  create_table "secret_records", force: :cascade do |t|
    t.bigint "scan_id", null: false
    t.string "resource_id", null: false
    t.string "name", null: false
    t.string "kind", null: false
    t.string "subscription_id"
    t.string "resource_group"
    t.string "vault_name"
    t.string "location"
    t.datetime "source_created_at"
    t.datetime "source_updated_at"
    t.datetime "expires_at"
    t.datetime "scanned_at", null: false
    t.boolean "enabled", default: true, null: false
    t.boolean "rotation_enabled", default: false, null: false
    t.integer "rotation_days", default: 0, null: false
    t.integer "age_days", default: 0, null: false
    t.boolean "age_simulated", default: false, null: false
    t.jsonb "tags", default: {}, null: false
    t.jsonb "access_model", default: {}, null: false
    t.jsonb "details", default: {}, null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["kind"], name: "index_secret_records_on_kind"
    t.index ["scan_id", "resource_id"], name: "index_secret_records_on_scan_id_and_resource_id", unique: true
    t.index ["scan_id"], name: "index_secret_records_on_scan_id"
    t.index ["tags"], name: "index_secret_records_on_tags", using: :gin
  end

  add_foreign_key "analyses", "scans"
  add_foreign_key "analyses", "secret_records"
  add_foreign_key "findings", "scans"
  add_foreign_key "findings", "secret_records"
  add_foreign_key "secret_records", "scans"
end
