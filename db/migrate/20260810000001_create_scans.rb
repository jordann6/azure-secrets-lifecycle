class CreateScans < ActiveRecord::Migration[8.0]
  def change
    create_table :scans do |t|
      t.string   :scan_id, null: false
      t.string   :status, null: false, default: "running"
      t.datetime :started_at, null: false
      t.datetime :finished_at
      t.integer  :duration_ms
      t.integer  :resource_count, null: false, default: 0
      t.jsonb    :metrics, null: false, default: {}
      t.jsonb    :sweep_errors, null: false, default: []
      t.string   :evidence_blob
      t.integer  :sentinel_rows
      t.timestamps
    end

    add_index :scans, :scan_id, unique: true
    add_index :scans, :started_at
  end
end
