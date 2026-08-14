package server

import "database/sql"

// ensureSchema creates the SQLite tables and indexes backing the server, then
// applies forward migrations for older databases. It is idempotent.
func ensureSchema(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS registered_dids (
			did TEXT PRIMARY KEY, doc_json TEXT NOT NULL, registered_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS messages (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			message_id TEXT NOT NULL UNIQUE,
			sender_did TEXT NOT NULL,
			recipient_did TEXT,
			group_did TEXT,
			type TEXT NOT NULL DEFAULT 'text',
			text TEXT,
			secure INTEGER NOT NULL DEFAULT 0,
			sent_at TEXT NOT NULL,
			wire_meta TEXT,
			wire_body TEXT
		);`,
		`CREATE INDEX IF NOT EXISTS idx_msg_recipient ON messages(recipient_did);`,
		`CREATE INDEX IF NOT EXISTS idx_msg_sender ON messages(sender_did);`,
		`CREATE INDEX IF NOT EXISTS idx_msg_group ON messages(group_did);`,
		`CREATE TABLE IF NOT EXISTS handles (
			handle TEXT PRIMARY KEY, did TEXT NOT NULL, phone TEXT, email TEXT, recovery_otp TEXT, registered_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS groups (
			group_did TEXT PRIMARY KEY,
			group_policy TEXT NOT NULL,
			group_profile TEXT,
			owner_did TEXT NOT NULL,
			group_state_version INTEGER NOT NULL DEFAULT 0,
			group_event_seq INTEGER NOT NULL DEFAULT 0,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS group_members (
			group_did TEXT NOT NULL,
			member_did TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'member',
			status TEXT NOT NULL DEFAULT 'active',
			joined_at TEXT NOT NULL,
			PRIMARY KEY (group_did, member_did)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_group_members_member ON group_members(member_did);`,
		`CREATE TABLE IF NOT EXISTS prekey_bundles (
			owner_did TEXT PRIMARY KEY, bundle_json TEXT NOT NULL, published_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS one_time_prekeys (
			owner_did TEXT NOT NULL, prekey_json TEXT NOT NULL, created_at TEXT NOT NULL
		);`,
		// P6: group E2EE — the server only stores and forwards opaque MLS
		// objects (key packages, crypto group state). No MLS computation.
		`CREATE TABLE IF NOT EXISTS group_key_packages (
			owner_did TEXT PRIMARY KEY, key_package_json TEXT NOT NULL,
			key_package_id TEXT NOT NULL, published_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS group_e2ee_states (
			group_did TEXT NOT NULL, crypto_group_id TEXT NOT NULL,
			epoch TEXT NOT NULL, state_json TEXT NOT NULL, updated_at TEXT NOT NULL,
			PRIMARY KEY (group_did, crypto_group_id)
		);`,
		`CREATE INDEX IF NOT EXISTS idx_group_e2ee_states_group ON group_e2ee_states(group_did);`,
		// P7: attachments — control-plane slots, object bytes (BLOB), and
		// download tickets.
		`CREATE TABLE IF NOT EXISTS attachment_slots (
			slot_id TEXT PRIMARY KEY,
			attachment_id TEXT NOT NULL,
			object_id TEXT NOT NULL,
			upload_uri TEXT NOT NULL,
			object_uri TEXT NOT NULL,
			commit_token TEXT NOT NULL,
			status TEXT NOT NULL DEFAULT 'created',
			object_encryption_mode TEXT NOT NULL,
			expected_size TEXT,
			mime_type TEXT,
			filename TEXT,
			expected_digest TEXT,
			actual_size INTEGER,
			actual_digest TEXT,
			expires_at TEXT NOT NULL,
			created_at TEXT NOT NULL,
			owner_did TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_attachment_slots_attachment ON attachment_slots(attachment_id);`,
		`CREATE TABLE IF NOT EXISTS attachment_objects (
			object_id TEXT PRIMARY KEY,
			data BLOB,
			size INTEGER NOT NULL DEFAULT 0,
			digest TEXT,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS attachment_tickets (
			ticket_b64u TEXT PRIMARY KEY,
			binding_json TEXT NOT NULL,
			expires_at TEXT NOT NULL
		);`,
		// P8: operation_id idempotency cache.
		`CREATE TABLE IF NOT EXISTS idempotency (
			key TEXT PRIMARY KEY, response_json TEXT NOT NULL, created_at TEXT NOT NULL
		);`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	// Migrate older databases that predate the phone/email/recovery_otp columns
	// on handles. ALTER TABLE ADD COLUMN errors if the column already exists,
	// so ignore.
	for _, col := range []string{"phone TEXT", "email TEXT", "recovery_otp TEXT"} {
		_, _ = db.Exec(`ALTER TABLE handles ADD COLUMN ` + col)
	}
	return nil
}
