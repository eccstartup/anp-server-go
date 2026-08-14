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
		`CREATE TABLE IF NOT EXISTS handles (
			handle TEXT PRIMARY KEY, did TEXT NOT NULL, phone TEXT, email TEXT, recovery_otp TEXT, registered_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS prekey_bundles (
			owner_did TEXT PRIMARY KEY, bundle_json TEXT NOT NULL, published_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS one_time_prekeys (
			owner_did TEXT NOT NULL, prekey_json TEXT NOT NULL, created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS groups (
			group_did TEXT PRIMARY KEY, name TEXT, owner_did TEXT,
			members_json TEXT, created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS group_members (
			group_did TEXT NOT NULL, member_did TEXT NOT NULL,
			PRIMARY KEY (group_did, member_did)
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
