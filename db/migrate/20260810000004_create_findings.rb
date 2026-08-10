class CreateFindings < ActiveRecord::Migration[8.0]
  def change
    create_table :findings do |t|
      t.references :scan, null: false, foreign_key: true, index: true
      t.references :secret_record, null: false, foreign_key: true, index: true

      t.string   :finding_id, null: false
      t.string   :finding_type, null: false
      t.string   :title, null: false
      t.string   :severity, null: false
      t.jsonb    :control_ids, null: false, default: []
      t.string   :resource_id, null: false
      t.datetime :evidence_timestamp, null: false
      t.string   :remediation_status, null: false, default: "OPEN"
      t.string   :owner_tag, null: false, default: "unassigned"
      t.integer  :readiness_score, null: false, default: 0

      t.timestamps
    end

    add_index :findings, :finding_id, unique: true
    add_index :findings, [:scan_id, :finding_type]
    add_index :findings, :severity
  end
end
