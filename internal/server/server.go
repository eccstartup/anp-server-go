// Package server implements an ANP protocol backend that speaks the
// anp-jsonrpc-v1 wire protocol. It is a real server: SQLite-persistent,
// signature-gated, restartable. It is a drop-in replacement for the old
// in-memory mock backend (cmd/mock).
//
// Protocol: POST /rpc, JSON-RPC 2.0, HTTP Message Signatures (RFC 9421).
// All calls except did.register_document require a valid signature from the
// caller's registered DID document.
//
// Source layout (single package, split by domain):
//
//	server.go   — Server type, lifecycle (New/Close/Start/Handler), JSON snapshot
//	schema.go   — SQLite schema + migrations
//	rpc.go      — JSON-RPC entry point, error codes, dispatch
//	auth.go     — HTTP Message Signature verification
//	did.go      — DID document registration/resolution + SSRF guard
//	handle.go   — handle register/recover
//	msg.go      — msg.send / msg.inbox / msg.history
//	group.go    — group lifecycle
//	e2ee.go     — direct.send + prekey bundle + origin proof
//	helpers.go  — small shared utilities
package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	_ "modernc.org/sqlite"
)

// Server is a persisted ANP backend.
type Server struct {
	db      *sql.DB
	mu      sync.Mutex
	nextMsg int64
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
	// Restore the message counter from the highest existing message id so a
	// restart does not collide on the UNIQUE(message_id) constraint. Message ids
	// look like "msg_<n>"; SUBSTR drops the "msg_" prefix.
	var nextMsg int64
	if err := db.QueryRow(`SELECT COALESCE(MAX(CAST(SUBSTR(message_id, 5) AS INTEGER)), 0) FROM messages`).Scan(&nextMsg); err != nil {
		nextMsg = 0
	}
	return &Server{db: db, nextMsg: nextMsg}, nil
}

// Close releases the underlying database connection. It is not safe to use the
// server after Close.
func (s *Server) Close() error {
	return s.db.Close()
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
			var mid, sd, typ, sentAt string
			var rd, gd, txt sql.NullString
			var secure int
			if rows.Scan(&mid, &sd, &rd, &gd, &typ, &txt, &secure, &sentAt) == nil {
				msgs = append(msgs, map[string]any{"message_id": mid, "sender_did": sd, "recipient_did": rd.String, "group_did": gd.String, "type": typ, "text": txt.String, "secure": secure != 0, "sent_at": sentAt})
			}
		}
		out["messages"] = msgs
	}
	return json.NewEncoder(w).Encode(out)
}
