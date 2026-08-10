class CreateAnalyses < ActiveRecord::Migration[8.0]
  def change
    create_table :analyses do |t|
      t.references :scan, null: false, foreign_key: true, index: true
      t.references :secret_record, null: false, foreign_key: true, index: true

      t.integer :readiness_score, null: false, default: 0
      t.string  :risk_tier, null: false, default: "low"
      t.jsonb   :consumer_map, null: false, default: {}
      t.jsonb   :runbook

      t.timestamps
    end

    add_index :analyses, [:scan_id, :readiness_score]
    add_index :analyses, :risk_tier
    add_index :analyses, [:scan_id, :secret_record_id], unique: true
  end
end
