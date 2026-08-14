package server

import (
	"encoding/json"
	"errors"
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
	r := post(`{"jsonrpc":"2.0","method":"handle.register","params":{"handle":"alice.example.com","did":"did:wba:ex:alice"},"id":2}`)
	if r["result"] == nil {
		t.Fatalf("handle.register (first-boot): %v", r)
	}

	// Direct E2EE send (first-boot): sender DID falls back to meta.sender_did.
	r = post(`{"jsonrpc":"2.0","method":"direct.send","params":{"meta":{"message_id":"msg_test1","sender_did":"did:wba:ex:alice","target":{"did":"did:wba:ex:bob"},"operation_id":"msg_test1","content_type":"application/anp-direct-init+json"},"body":{"session_id":"s1"}},"id":3}`)
	if r["result"] == nil {
		t.Fatalf("direct.send (first-boot): %v", r)
	}

	// Inbox (empty at first boot since no DID is authenticated).
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
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var r map[string]any
		json.Unmarshal(raw, &r)
		return r
	}

	// First claim.
	r := post(`{"jsonrpc":"2.0","method":"handle.register","params":{"handle":"x.example.com","did":"did:a"},"id":1}`)
	if r["result"] == nil {
		t.Fatalf("first claim: %v", r)
	}
	// Squatting (different DID, same handle).
	r = post(`{"jsonrpc":"2.0","method":"handle.register","params":{"handle":"x.example.com","did":"did:b"},"id":2}`)
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
	srv.handleRegister("", map[string]any{"handle": "x.example.com", "did": "did:wba:x"})
	srv.directSend("did:wba:x", map[string]any{
		"meta": map[string]any{"message_id": "msg_persist1", "sender_did": "did:wba:x", "target": map[string]any{"did": "did:wba:y"}, "operation_id": "msg_persist1"},
		"body": map[string]any{},
	})
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
	_ = srv2.db.QueryRow(`SELECT did FROM handles WHERE handle = ?`, "x.example.com").Scan(&handleDID)
	if handleDID == "" {
		t.Fatalf("handle not persisted")
	}
	t.Logf("handle persisted: x.example.com -> %s", handleDID)

	var msgCount int
	_ = srv2.db.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&msgCount)
	if msgCount != 1 {
		t.Fatalf("messages not persisted: got %d", msgCount)
	}
}

func TestServerBodyLimit(t *testing.T) {
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

	big := strings.Repeat("a", maxBodyBytes+100)
	resp, err := http.Post(baseURL+"/rpc", "application/json", strings.NewReader(big))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var r map[string]any
	json.Unmarshal(raw, &r)
	errMap, _ := r["error"].(map[string]any)
	if errMap == nil || errMap["message"] != "request too large" {
		t.Fatalf("expected request-too-large, got %v", r)
	}
}

func TestServerRegistrationSecurity(t *testing.T) {
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

	// 1. A new DID may register unsigned (bootstrap).
	r := post(`{"jsonrpc":"2.0","method":"did.register_document","params":{"did":"did:a","did_document":{"id":"did:a"}},"id":1}`)
	if r["error"] != nil {
		t.Fatalf("first registration should succeed: %v", r)
	}

	// 2. A second, different DID may also register (no deadlock for new peers).
	r = post(`{"jsonrpc":"2.0","method":"did.register_document","params":{"did":"did:b","did_document":{"id":"did:b"}},"id":2}`)
	if r["error"] != nil {
		t.Fatalf("second registration should succeed: %v", r)
	}

	// 3. Re-registering an EXISTING did without the owner's signature is rejected.
	r = post(`{"jsonrpc":"2.0","method":"did.register_document","params":{"did":"did:a","did_document":{"id":"did:a"}},"id":3}`)
	if r["error"] == nil {
		t.Fatalf("expected overwrite to be rejected: %v", r)
	}

	// 4. doc.id must match the registered did.
	r = post(`{"jsonrpc":"2.0","method":"did.register_document","params":{"did":"did:c","did_document":{"id":"did:evil"}},"id":4}`)
	if r["error"] == nil {
		t.Fatalf("expected doc.id mismatch to be rejected: %v", r)
	}
}

func TestServerHandleRecover(t *testing.T) {
	dbPath := t.TempDir() + "/recover.db"
	srv, err := New(dbPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.db.Close()

	// Register a handle bound to alice (no email — binding is by signature).
	srv.mu.Lock()
	_, err = srv.handleRegister("did:wba:alice", map[string]any{
		"handle": "alice.example.com",
	})
	srv.mu.Unlock()
	if err != nil {
		t.Fatalf("register: %v", err)
	}

	// 1. Recover by the current owner (matching DID) → success (idempotent).
	srv.mu.Lock()
	res, err := srv.handleRecover("did:wba:alice", map[string]any{
		"handle": "alice.example.com",
	})
	srv.mu.Unlock()
	if err != nil {
		t.Fatalf("recover by owner: %v", err)
	}
	if rm, _ := res.(map[string]any); rm["did"] != "did:wba:alice" {
		t.Fatalf("expected did:wba:alice, got %v", rm["did"])
	}

	// 2. Recover by a different DID → rejected (no cross-DID recovery channel).
	srv.mu.Lock()
	_, err = srv.handleRecover("did:wba:evil", map[string]any{
		"handle": "alice.example.com",
	})
	srv.mu.Unlock()
	if err == nil {
		t.Fatalf("recover by another DID must be rejected")
	}

	// 3. Unknown handle → did-not-found error code.
	srv.mu.Lock()
	_, err = srv.handleRecover("did:wba:x", map[string]any{"handle": "nobody.agent"})
	srv.mu.Unlock()
	assertRPCErrorCode(t, err, codeDidNotFound)
}

func TestServerErrorCodes(t *testing.T) {
	dbPath := t.TempDir() + "/codes.db"
	srv, err := New(dbPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.db.Close()

	// handle_taken → codeHandleTaken.
	srv.mu.Lock()
	_, _ = srv.handleRegister("did:a", map[string]any{"handle": "x.example.com", "did": "did:a"})
	_, err = srv.handleRegister("did:b", map[string]any{"handle": "x.example.com", "did": "did:b"})
	srv.mu.Unlock()
	assertRPCErrorCode(t, err, codeHandleTaken)

	// did not found (unsupported DID method, no remote fallback) → codeDidNotFound.
	srv.mu.Lock()
	_, err = srv.didResolve(map[string]any{"target": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"})
	srv.mu.Unlock()
	assertRPCErrorCode(t, err, codeDidNotFound)

	// opk_unavailable: publish a bundle with no OPKs, then request an OPK.
	srv.mu.Lock()
	_, _ = srv.e2eePublishPrekeyBundle("did:wba:x", map[string]any{
		"body": map[string]any{
			"prekey_bundle":    map[string]any{"owner_did": "did:wba:x"},
			"one_time_prekeys": []any{},
		},
	})
	_, err = srv.e2eeGetPrekeyBundle(map[string]any{
		"body": map[string]any{"target_did": "did:wba:x", "require_opk": true},
	})
	srv.mu.Unlock()
	assertRPCErrorCode(t, err, codeOPKUnavailable)
}

func assertRPCErrorCode(t *testing.T, err error, wantCode int) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error with code %d, got nil", wantCode)
	}
	var rerr *rpcError
	if !errors.As(err, &rerr) {
		t.Fatalf("expected *rpcError, got %T: %v", err, err)
	}
	if rerr.code != wantCode {
		t.Fatalf("expected code %d, got %d (%s)", wantCode, rerr.code, rerr.msg)
	}
}

func TestServerDidResolveSSRF(t *testing.T) {
	dbPath := t.TempDir() + "/ssrf.db"
	srv, err := New(dbPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.db.Close()

	// Resolving a DID against loopback / private / link-local / metadata
	// addresses must be refused (no outbound fetch to internal networks).
	for _, did := range []string{
		"did:wba:127.0.0.1:user:alice",
		"did:wba:localhost:user:alice",
		"did:wba:169.254.169.254:latest:meta-data", // cloud metadata link-local
		"did:wba:10.0.0.1:user:alice",              // private
		"did:web:127.0.0.1",
	} {
		srv.mu.Lock()
		_, err := srv.didResolve(map[string]any{"target": did})
		srv.mu.Unlock()
		var rerr *rpcError
		if !errors.As(err, &rerr) || rerr.code != codeDidNotFound {
			t.Fatalf("expected SSRF-blocked did-not-found for %q, got %v", did, err)
		}
	}

	// A public domain must NOT be blocked at the host pre-check stage (it will
	// fail on the actual network fetch, which is expected in a test).
	if isBlockedHost("example.com") {
		t.Fatalf("example.com must not be treated as blocked")
	}
	if !isBlockedHost("192.168.1.1") {
		t.Fatalf("private IP must be blocked")
	}
}
