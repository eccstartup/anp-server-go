package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestServerFirstBoot(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	srv, err := New(dbPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	baseURL, closeFn, err := srv.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer closeFn()

	post := func(body string) map[string]any {
		t.Helper()
		resp, err := http.Post(baseURL+"/rpc", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var r map[string]any
		json.Unmarshal(raw, &r)
		return r
	}

	// First-boot: no DIDs registered, all requests accepted.
	r := post(`{"jsonrpc":"2.0","method":"msg.send","params":{"to":"did:wba:ex:bob","body":{"text":"hello"}},"id":1}`)
	if r["result"] == nil {
		t.Fatalf("msg.send (first-boot): %v", r)
	}

	r = post(`{"jsonrpc":"2.0","method":"handle.register","params":{"handle":"alice.agent","did":"did:wba:ex:alice"},"id":2}`)
	if r["result"] == nil {
		t.Fatalf("handle.register (first-boot): %v", r)
	}

	r = post(`{"jsonrpc":"2.0","method":"group.create","params":{"name":"team"},"id":3}`)
	result, _ := r["result"].(map[string]any)
	if result["group_did"] == nil {
		t.Fatalf("group.create: %v", r)
	}
	t.Logf("group: %s", result["group_did"])

	// Inbox.
	r = post(`{"jsonrpc":"2.0","method":"msg.inbox","params":{},"id":4}`)
	t.Logf("inbox: %v", r)

	// Health.
	resp, err := http.Get(baseURL + "/healthz")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("healthz: %v/%d", err, resp.StatusCode)
	}
	resp.Body.Close()
}

func TestServerSquatting(t *testing.T) {
	dbPath := t.TempDir() + "/test.db"
	srv, err := New(dbPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	baseURL, closeFn, err := srv.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer closeFn()

	post := func(body string) map[string]any {
		t.Helper()
		resp, err := http.Post(baseURL+"/rpc", "application/json", strings.NewReader(body))
		if err != nil { t.Fatalf("POST: %v", err) }
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var r map[string]any
		json.Unmarshal(raw, &r)
		return r
	}

	// First claim.
	r := post(`{"jsonrpc":"2.0","method":"handle.register","params":{"handle":"x","did":"did:a"},"id":1}`)
	if r["result"] == nil {
		t.Fatalf("first claim: %v", r)
	}
	// Squatting (different DID, same handle).
	r = post(`{"jsonrpc":"2.0","method":"handle.register","params":{"handle":"x","did":"did:b"},"id":2}`)
	if r["error"] == nil {
		t.Fatalf("expected squatting error: %v", r)
	}
	errMap, _ := r["error"].(map[string]any)
	if errMap["message"] == nil || !strings.Contains(errMap["message"].(string), "already registered") {
		t.Fatalf("unexpected error: %v", r)
	}
	t.Logf("squatting blocked: %v", errMap["message"])
}

func TestServerPersistence(t *testing.T) {
	dbPath := t.TempDir() + "/persist.db"
	srv, err := New(dbPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv.mu.Lock()
	srv.didRegisterDocument(map[string]any{"did": "did:wba:x", "did_document": map[string]any{"id": "did:wba:x"}})
	srv.handleRegister(map[string]any{"handle": "x.agent", "did": "did:wba:x"})
	srv.msgSend("", map[string]any{"to": "did:wba:y", "body": map[string]any{"text": "hello"}})
	srv.mu.Unlock()
	_ = srv.db.Close()

	srv2, err := New(dbPath)
	if err != nil {
		t.Fatalf("New(2): %v", err)
	}
	defer srv2.db.Close()
	srv2.mu.Lock()
	defer srv2.mu.Unlock()

	var handleDID string
	_ = srv2.db.QueryRow(`SELECT did FROM handles WHERE handle = ?`, "x.agent").Scan(&handleDID)
	if handleDID == "" {
		t.Fatalf("handle not persisted")
	}
	t.Logf("handle persisted: x.agent -> %s", handleDID)

	var msgCount int
	_ = srv2.db.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&msgCount)
	if msgCount != 1 {
		t.Fatalf("messages not persisted: got %d", msgCount)
	}
}
