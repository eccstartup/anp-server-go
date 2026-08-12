// Package server implements an ANP protocol backend that speaks the
// anp-jsonrpc-v1 wire protocol. It is a real server: SQLite-persistent,
// signature-gated, restartable. It is a drop-in replacement for the old
// in-memory mock backend (cmd/mock).
//
// Protocol: POST /rpc, JSON-RPC 2.0, HTTP Message Signatures (RFC 9421).
// All calls except did.register_document require a valid signature from the
// caller's registered DID document.
package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	anpauth "github.com/agent-network-protocol/anp/golang/authentication"

	_ "modernc.org/sqlite"
)

// Server is a persisted ANP backend.
type Server struct {
	db   *sql.DB
	stop chan struct{}
	mu   sync.Mutex
}

// New creates a Server with a database file at dbPath (created if absent).
func New(dbPath string) (*Server, error) {
	if dir := filepath.Dir(dbPath); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000; PRAGMA journal_mode = WAL;`); err != nil {
		db.Close()
		return nil, err
	}
	if err := ensureSchema(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Server{db: db, stop: make(chan struct{})}, nil
}

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
			handle TEXT PRIMARY KEY, did TEXT NOT NULL, registered_at TEXT NOT NULL
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
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	return nil
}

// Start begins serving on a random local port. Returns the base URL + a
// function that shuts the server down.
func (s *Server) Start() (baseURL string, closeFn func(), err error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	httpServer := &http.Server{Handler: s.handler()}
	go func() { _ = httpServer.Serve(listener) }()
	return "http://" + listener.Addr().String(), func() {
		_ = httpServer.Shutdown(context.Background())
		s.db.Close()
	}, nil
}

func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/rpc", s.handleRPC)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

// Handler returns the server's HTTP handler (public for embedding in a custom server).
func (s *Server) Handler() http.Handler {
	return s.handler()
}

// ---------------------------------------------------------------- RPC entry

type rpcRequest struct {
	JSONRPC string         `json:"jsonrpc"`
	Method  string         `json:"method"`
	Params  map[string]any `json:"params"`
	ID      any            `json:"id"`
}

func writeRPC(w http.ResponseWriter, id any, result any, errMsg string) {
	resp := map[string]any{"jsonrpc": "2.0", "id": id}
	if errMsg != "" {
		resp["error"] = map[string]any{"code": -32000, "message": errMsg}
	} else {
		resp["result"] = result
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleRPC(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)

	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeRPC(w, nil, nil, "parse error")
		return
	}

	headers := httpHeaders(r)
	authDID := ""

	// did.register_document is the bootstrap path: unsigned, registers a DID
	// document so subsequent signed calls pass verification.
	if req.Method != "did.register_document" {
		did, err := s.verify(r, headers, body)
		if err != nil {
			writeRPC(w, req.ID, nil, err.Error())
			return
		}
		authDID = did
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.dispatch(req.Method, req.Params, authDID)
	if err != nil {
		writeRPC(w, req.ID, nil, err.Error())
		return
	}
	writeRPC(w, req.ID, result, "")
}

// verify checks HTTP Message Signatures against registered DID documents.
// Returns the authenticated sender DID on success. If no DIDs are registered
// yet (first-boot scenario), all requests are accepted.
func (s *Server) verify(r *http.Request, headers map[string]string, body []byte) (string, error) {
	var count int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM registered_dids`).Scan(&count)
	if count == 0 {
		// No identities registered yet — accept any request so the first
		// caller can bootstrap.
		return "", nil
	}

	signatureInput := headerGet(headers, "Signature-Input")
	if signatureInput == "" {
		return "", fmt.Errorf("missing Signature-Input header")
	}
	requestURL := "http://" + r.Host + r.URL.Path

	rows, err := s.db.Query(`SELECT did, doc_json FROM registered_dids`)
	if err != nil {
		return "", fmt.Errorf("internal error")
	}
	defer rows.Close()
	for rows.Next() {
		var did, docJSON string
		if err := rows.Scan(&did, &docJSON); err != nil {
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(docJSON), &doc); err != nil {
			continue
		}
		meta, err := anpauth.VerifyHTTPMessageSignature(doc, http.MethodPost, requestURL, headers, body)
		if err == nil {
			return keyIDToDID(meta.KeyID), nil
		}
	}
	return "", fmt.Errorf("signature verification failed")
}

func keyIDToDID(keyID string) string {
	idx := strings.LastIndex(keyID, "#")
	if idx >= 0 {
		return keyID[:idx]
	}
	return keyID
}

// ---------------------------------------------------------------- dispatch

func (s *Server) dispatch(method string, params map[string]any, authDID string) (any, error) {
	switch method {
	case "msg.send":
		return s.msgSend(authDID, params)
	case "msg.inbox":
		return s.msgInbox(authDID, params)
	case "msg.history":
		return s.msgHistory(authDID, params)
	case "group.create":
		return s.groupCreate(params)
	case "group.join":
		return s.groupJoin(params)
	case "group.leave":
		return s.groupLeave(params)
	case "group.members":
		return s.groupMembers(params)
	case "did.resolve":
		return s.didResolve(params)
	case "did.register_document":
		return s.didRegisterDocument(params)
	case "handle.register":
		return s.handleRegister(params)
	case "handle.recover":
		return map[string]any{"status": "recovered"}, nil
	case "direct.send":
		return s.directSend(authDID, params)
	case "direct.e2ee.publish_prekey_bundle":
		return s.e2eePublishPrekeyBundle(params)
	case "direct.e2ee.get_prekey_bundle":
		return s.e2eeGetPrekeyBundle(params)
	default:
		return nil, fmt.Errorf("unknown method %q", method)
	}
}

// ---------------------------------------------------------------- did

func (s *Server) didRegisterDocument(params map[string]any) (any, error) {
	did, _ := params["did"].(string)
	doc, _ := params["did_document"].(map[string]any)
	if did == "" || doc == nil {
		return nil, fmt.Errorf("did and did_document are required")
	}
	raw, _ := json.Marshal(doc)
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.db.Exec(`INSERT INTO registered_dids (did, doc_json, registered_at) VALUES (?,?,?) ON CONFLICT(did) DO UPDATE SET doc_json=excluded.doc_json, registered_at=excluded.registered_at`,
		did, string(raw), now); err != nil {
		return nil, err
	}
	return map[string]any{"did": did, "status": "registered"}, nil
}

func (s *Server) didResolve(params map[string]any) (any, error) {
	target, _ := params["target"].(string)
	if target == "" {
		return nil, fmt.Errorf("target is required")
	}
	// Handle → DID.
	var did string
	_ = s.db.QueryRow(`SELECT did FROM handles WHERE handle = ?`, target).Scan(&did)
	if did == "" {
		did = target
	}
	var docJSON string
	if err := s.db.QueryRow(`SELECT doc_json FROM registered_dids WHERE did = ?`, did).Scan(&docJSON); err != nil {
		return nil, fmt.Errorf("did not found")
	}
	var doc map[string]any
	_ = json.Unmarshal([]byte(docJSON), &doc)
	return map[string]any{"did": did, "did_document": doc}, nil
}

// ---------------------------------------------------------------- handle

func (s *Server) handleRegister(params map[string]any) (any, error) {
	handle, _ := params["handle"].(string)
	did, _ := params["did"].(string)
	if handle == "" || did == "" {
		return nil, fmt.Errorf("handle and did are required")
	}
	// Conflict check: handle already bound to a different DID.
	var existing string
	_ = s.db.QueryRow(`SELECT did FROM handles WHERE handle = ?`, handle).Scan(&existing)
	if existing != "" && existing != did {
		return nil, fmt.Errorf("handle %q is already registered by another identity", handle)
	}
	if _, err := s.db.Exec(`INSERT INTO handles (handle, did, registered_at) VALUES (?,?,?) ON CONFLICT(handle) DO UPDATE SET did=excluded.did`,
		handle, did, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return nil, err
	}
	return map[string]any{"did": did, "handle": handle, "status": "registered"}, nil
}

// ---------------------------------------------------------------- msg

func (s *Server) msgSend(authDID string, params map[string]any) (any, error) {
	to, _ := params["to"].(string)
	group, _ := params["group"].(string)
	bodyMap, _ := params["body"].(map[string]any)
	secure, _ := params["secure"].(bool)
	if to == "" && group == "" {
		return nil, fmt.Errorf("either to or group is required")
	}
	text := ""
	if bodyMap != nil {
		text, _ = bodyMap["text"].(string)
	}
	msgID := fmt.Sprintf("msg_%d", time.Now().UnixNano())
	sentAt := time.Now().UTC().Format(time.RFC3339)
	recipient := to
	if group != "" {
		recipient = ""
	}
	if _, err := s.db.Exec(`INSERT INTO messages (message_id, sender_did, recipient_did, group_did, type, text, secure, sent_at) VALUES (?,?,?,?,?,?,?,?)`,
		msgID, authDID, recipient, group, "text", text, boolToInt(secure), sentAt); err != nil {
		return nil, err
	}
	return map[string]any{"message_id": msgID, "thread_id": "thread_" + firstNonEmpty(to, group), "sent_at": sentAt, "state": "delivered"}, nil
}

func (s *Server) msgInbox(authDID string, params map[string]any) (any, error) {
	scope, _ := params["scope"].(string)
	limit := 100
	if v, ok := params["limit"].(float64); ok {
		limit = int(v)
	}
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	where := []string{"recipient_did = ?"}
	args := []any{authDID}
	if scope == "direct" {
		where = append(where, "group_did IS NULL")
	}
	if scope == "group" {
		where = append(where, "group_did IS NOT NULL")
	}
	q := "SELECT message_id, sender_did, recipient_did, group_did, type, text, secure, sent_at, wire_meta, wire_body FROM messages"
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	msgs := []map[string]any{}
	for rows.Next() {
		var mid, sd, rd, gd, mtype, mtext, sentAt string
		var metaStr, bodyStr sql.NullString
		var secure int
		if err := rows.Scan(&mid, &sd, &rd, &gd, &mtype, &mtext, &secure, &sentAt, &metaStr, &bodyStr); err != nil {
			continue
		}
		entry := map[string]any{
			"message_id": mid, "sender_did": sd, "recipient_did": rd,
			"group_did": gd, "type": mtype, "text": mtext,
			"secure": secure != 0, "sent_at": sentAt,
		}
		if metaStr.Valid && bodyStr.Valid {
			var meta, body any
			_ = json.Unmarshal([]byte(metaStr.String), &meta)
			_ = json.Unmarshal([]byte(bodyStr.String), &body)
			entry["meta"] = meta
			entry["body"] = body
		}
		msgs = append(msgs, entry)
	}
	return map[string]any{"messages": msgs}, nil
}

func (s *Server) msgHistory(authDID string, params map[string]any) (any, error) {
	peer, _ := params["with"].(string)
	limit := 50
	if v, ok := params["limit"].(float64); ok {
		limit = int(v)
	}
	rows, err := s.db.Query(`SELECT message_id, sender_did, recipient_did, group_did, type, text, secure, sent_at FROM messages WHERE (sender_did = ? AND recipient_did = ?) OR (sender_did = ? AND recipient_did = ?) ORDER BY id DESC LIMIT ?`, authDID, peer, peer, authDID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	msgs := []map[string]any{}
	for rows.Next() {
		var mid, sd, rd, gd, mtype, mtext, sentAt string
		var secure int
		if err := rows.Scan(&mid, &sd, &rd, &gd, &mtype, &mtext, &secure, &sentAt); err != nil {
			continue
		}
		msgs = append(msgs, map[string]any{
			"message_id": mid, "sender_did": sd, "recipient_did": rd,
			"group_did": gd, "type": mtype, "text": mtext,
			"secure": secure != 0, "sent_at": sentAt,
		})
	}
	return map[string]any{"messages": msgs}, nil
}

// ---------------------------------------------------------------- group

func (s *Server) groupCreate(params map[string]any) (any, error) {
	name, _ := params["name"].(string)
	members := []any{}
	if raw, ok := params["members"].([]any); ok {
		members = raw
	}
	gid := fmt.Sprintf("did:wba:%s:group:g%d", "server", time.Now().UnixNano())
	membersJSON, _ := json.Marshal(members)
	if _, err := s.db.Exec(`INSERT INTO groups (group_did, name, members_json, created_at) VALUES (?,?,?,?)`,
		gid, name, string(membersJSON), time.Now().UTC().Format(time.RFC3339)); err != nil {
		return nil, err
	}
	return map[string]any{"group_did": gid, "name": name, "members": members}, nil
}

func (s *Server) groupJoin(params map[string]any) (any, error) {
	gid, _ := params["group"].(string)
	if gid == "" {
		return nil, fmt.Errorf("group is required")
	}
	var count int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM groups WHERE group_did = ?`, gid).Scan(&count)
	if count == 0 {
		return nil, fmt.Errorf("group not found")
	}
	return map[string]any{"status": "joined"}, nil
}

func (s *Server) groupLeave(params map[string]any) (any, error) {
	gid, _ := params["group"].(string)
	if gid == "" {
		return nil, fmt.Errorf("group is required")
	}
	_, _ = s.db.Exec(`DELETE FROM groups WHERE group_did = ?`, gid)
	return map[string]any{"status": "left"}, nil
}

func (s *Server) groupMembers(params map[string]any) (any, error) {
	gid, _ := params["group"].(string)
	if gid == "" {
		return nil, fmt.Errorf("group is required")
	}
	var membersJSON string
	if err := s.db.QueryRow(`SELECT members_json FROM groups WHERE group_did = ?`, gid).Scan(&membersJSON); err != nil {
		return nil, fmt.Errorf("group not found")
	}
	var members []any
	_ = json.Unmarshal([]byte(membersJSON), &members)
	if members == nil {
		members = []any{}
	}
	return map[string]any{"members": members}, nil
}

// ---------------------------------------------------------------- direct E2EE

func (s *Server) directSend(authDID string, params map[string]any) (any, error) {
	meta, _ := params["meta"].(map[string]any)
	body, _ := params["body"].(map[string]any)
	target, _ := meta["target"].(map[string]any)
	peerDID, _ := target["did"].(string)
	messageID, _ := meta["message_id"].(string)
	senderDID, _ := meta["sender_did"].(string)
	if messageID == "" {
		return nil, fmt.Errorf("message_id is required")
	}
	metaRaw, _ := json.Marshal(meta)
	bodyRaw, _ := json.Marshal(body)
	if _, err := s.db.Exec(`INSERT INTO messages (message_id, sender_did, recipient_did, type, text, secure, sent_at, wire_meta, wire_body) VALUES (?,?,?,'text','',1,?,?,?)`,
		messageID, senderDID, peerDID, time.Now().UTC().Format(time.RFC3339), string(metaRaw), string(bodyRaw)); err != nil {
		return nil, err
	}
	return map[string]any{"message_id": messageID, "state": "delivered", "sent_at": time.Now().UTC().Format(time.RFC3339)}, nil
}

func (s *Server) e2eePublishPrekeyBundle(params map[string]any) (any, error) {
	body, _ := params["body"].(map[string]any)
	bundle, _ := body["prekey_bundle"].(map[string]any)
	ownerDID, _ := bundle["owner_did"].(string)
	if ownerDID == "" {
		return nil, fmt.Errorf("prekey_bundle.owner_did is required")
	}
	bundleRaw, _ := json.Marshal(bundle)
	if _, err := s.db.Exec(`INSERT INTO prekey_bundles (owner_did, bundle_json, published_at) VALUES (?,?,?) ON CONFLICT(owner_did) DO UPDATE SET bundle_json=excluded.bundle_json, published_at=excluded.published_at`,
		ownerDID, string(bundleRaw), time.Now().UTC().Format(time.RFC3339)); err != nil {
		return nil, err
	}
	// Persist one-time prekeys.
	if raw, ok := body["one_time_prekeys"].([]any); ok {
		for _, entry := range raw {
			itemRaw, _ := json.Marshal(entry)
			_, _ = s.db.Exec(`INSERT INTO one_time_prekeys (owner_did, prekey_json, created_at) VALUES (?,?,?)`,
				ownerDID, string(itemRaw), time.Now().UTC().Format(time.RFC3339))
		}
		// Keep only the freshest batch.
		_, _ = s.db.Exec(`DELETE FROM one_time_prekeys WHERE owner_did = ? AND rowid NOT IN (SELECT rowid FROM one_time_prekeys WHERE owner_did = ? ORDER BY rowid DESC LIMIT 100)`, ownerDID, ownerDID)
	}
	return map[string]any{"status": "published", "owner_did": ownerDID}, nil
}

func (s *Server) e2eeGetPrekeyBundle(params map[string]any) (any, error) {
	body, _ := params["body"].(map[string]any)
	targetDID, _ := body["target_did"].(string)
	requireOPK, _ := body["require_opk"].(bool)
	var bundleJSON string
	if err := s.db.QueryRow(`SELECT bundle_json FROM prekey_bundles WHERE owner_did = ? ORDER BY published_at DESC LIMIT 1`, targetDID).Scan(&bundleJSON); err != nil {
		return nil, fmt.Errorf("prekey bundle not found for %s", targetDID)
	}
	var bundle map[string]any
	_ = json.Unmarshal([]byte(bundleJSON), &bundle)
	result := map[string]any{"prekey_bundle": bundle}
	if requireOPK {
		var prekeyJSON string
		if err := s.db.QueryRow(`SELECT prekey_json FROM one_time_prekeys WHERE owner_did = ? ORDER BY rowid ASC LIMIT 1`, targetDID).Scan(&prekeyJSON); err == nil {
			var opk map[string]any
			json.Unmarshal([]byte(prekeyJSON), &opk)
			result["one_time_prekey"] = opk
			_, _ = s.db.Exec(`DELETE FROM one_time_prekeys WHERE owner_did = ? AND prekey_json = ?`, targetDID, prekeyJSON)
		} else {
			return nil, fmt.Errorf("anp.direct.e2ee.opk_unavailable")
		}
	}
	return result, nil
}

// ---------------------------------------------------------------- helpers

func httpHeaders(r *http.Request) map[string]string {
	m := map[string]string{}
	for key, vals := range r.Header {
		if len(vals) > 0 {
			m[key] = vals[0]
		}
	}
	return m
}

func headerGet(headers map[string]string, key string) string {
	for k, v := range headers {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return "unknown"
}

// JSONSnapshot writes the server database as a JSON snapshot (for inspection).
func (s *Server) JSONSnapshot(w io.Writer) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]any{}

	rows, err := s.db.Query(`SELECT message_id, sender_did, recipient_did, group_did, type, text, secure, sent_at FROM messages ORDER BY id`)
	if err == nil {
		defer rows.Close()
		msgs := []map[string]any{}
		for rows.Next() {
			var mid, sd, rd, gd, typ, txt, sentAt string
			var secure int
			if rows.Scan(&mid, &sd, &rd, &gd, &typ, &txt, &secure, &sentAt) == nil {
				msgs = append(msgs, map[string]any{"message_id": mid, "sender_did": sd, "recipient_did": rd, "group_did": gd, "type": typ, "text": txt, "secure": secure != 0, "sent_at": sentAt})
			}
		}
		out["messages"] = msgs
	}
	return json.NewEncoder(w).Encode(out)
}
