class CreateSecretRecords < ActiveRecord::Migration[8.0]
  def change
    create_table :secret_records do |t|
      t.references :scan, null: false, foreign_key: true, index: true

      t.string   :resource_id, null: false
      t.string   :name, null: false
      t.string   :kind, null: false
      t.string   :subscription_id
      t.string   :resource_group
      t.string   :vault_name
      t.string   :location

      t.datetime :source_created_at
      t.datetime :source_updated_at
      t.datetime :expires_at
      t.datetime :scanned_at, null: false

      t.boolean  :enabled, null: false, default: true
      t.boolean  :rotation_enabled, null: false, default: false
      t.integer  :rotation_days, null: false, default: 0
      t.integer  :age_days, null: false, default: 0
      t.boolean  :age_simulated, null: false, default: false

      t.jsonb    :tags, null: false, default: {}
      t.jsonb    :access_model, null: false, default: {}
      t.jsonb    :details, null: false, default: {}

      t.timestamps
    end

    add_index :secret_records, [:scan_id, :resource_id], unique: true
    add_index :secret_records, :kind
    add_index :secret_records, :tags, using: :gin
  end
end
