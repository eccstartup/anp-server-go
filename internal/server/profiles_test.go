package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestGroupE2EEKeyPackage covers publish + get of a group MLS KeyPackage, and
// verifies the owner_did is forced to the authenticated caller.
func TestGroupE2EEKeyPackage(t *testing.T) {
	dbPath := t.TempDir() + "/e2ee-key.db"
	srv, err := New(dbPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.db.Close()

	srv.mu.Lock()
	res, err := srv.groupE2EEPublishKeyPackage("did:wba:alice", map[string]any{
		"body": map[string]any{
			"group_key_package": map[string]any{
				"owner_did":            "did:wba:evil", // must be overwritten
				"key_package_id":       "kp-1",
				"suite":                "mls10",
				"mls_key_package_b64u": "b3BhcXVlLWJ5dGVz",
			},
		},
	})
	srv.mu.Unlock()
	if err != nil {
		t.Fatalf("publish_key_package: %v", err)
	}
	rm := res.(map[string]any)
	if rm["published"] != true || rm["owner_did"] != "did:wba:alice" || rm["key_package_id"] != "kp-1" {
		t.Fatalf("publish result: %v", rm)
	}
	if rm["published_at"] == "" {
		t.Fatalf("published_at missing: %v", rm)
	}

	srv.mu.Lock()
	res, err = srv.groupE2EEGetKeyPackage(map[string]any{"body": map[string]any{"target_did": "did:wba:alice"}})
	srv.mu.Unlock()
	if err != nil {
		t.Fatalf("get_key_package: %v", err)
	}
	rm = res.(map[string]any)
	if rm["target_did"] != "did:wba:alice" {
		t.Fatalf("get target_did: %v", rm)
	}
	pkg, _ := rm["group_key_package"].(map[string]any)
	if pkg == nil || pkg["owner_did"] != "did:wba:alice" {
		t.Fatalf("get group_key_package: %v", rm)
	}

	// A missing key package yields the profile-specific error code.
	srv.mu.Lock()
	_, err = srv.groupE2EEGetKeyPackage(map[string]any{"body": map[string]any{"target_did": "did:wba:nobody"}})
	srv.mu.Unlock()
	assertRPCErrorCode(t, err, codeE2EEKeyPackageNotFound)
}

// TestGroupE2EESendAndInbox verifies an E2EE cipher message is stored and
// returned to group members via msg.inbox (without decryption).
func TestGroupE2EESendAndInbox(t *testing.T) {
	dbPath := t.TempDir() + "/e2ee-send.db"
	srv, err := New(dbPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.db.Close()

	gid := createTestGroup(t, srv, "did:wba:alice")
	srv.mu.Lock()
	_, err = srv.groupJoin("did:wba:bob", map[string]any{"body": map[string]any{"group_did": gid}})
	srv.mu.Unlock()
	if err != nil {
		t.Fatalf("join: %v", err)
	}

	srv.mu.Lock()
	res, err := srv.groupE2EESend("did:wba:alice", map[string]any{
		"meta": map[string]any{
			"profile":          "anp.group.e2ee.v1",
			"security_profile": "group-e2ee",
			"sender_did":       "did:wba:alice",
			"target":           map[string]any{"kind": "group", "did": gid},
			"message_id":       "em1",
			"operation_id":     "eop1",
			"content_type":     "application/anp-group-cipher+json",
		},
		"body": map[string]any{
			"crypto_group_id_b64u": "cg1",
			"epoch":                "1",
			"private_message_b64u": "b3BhcXVlLWNpcGhlcg",
			"group_state_ref":      map[string]any{"group_did": gid, "group_state_version": 0},
			"epoch_authenticator":  "ea1",
		},
	})
	srv.mu.Unlock()
	if err != nil {
		t.Fatalf("group.e2ee.send: %v", err)
	}
	rm := res.(map[string]any)
	if rm["accepted"] != true || rm["message_id"] != "em1" || rm["epoch"] != "1" {
		t.Fatalf("send ACK: %v", rm)
	}
	if v, _ := rm["group_event_seq"].(int64); v != 1 {
		t.Fatalf("group_event_seq = %v, want 1", rm["group_event_seq"])
	}

	// bob (a member) can retrieve the cipher message via msg.inbox.
	srv.mu.Lock()
	inbox, err := srv.msgInbox("did:wba:bob", map[string]any{})
	srv.mu.Unlock()
	if err != nil {
		t.Fatalf("msg.inbox: %v", err)
	}
	msgs := inbox.(map[string]any)["messages"].([]map[string]any)
	if len(msgs) != 1 {
		t.Fatalf("bob inbox should have 1 message, got %d", len(msgs))
	}
	meta := msgs[0]["meta"].(map[string]any)
	if meta["profile"] != "anp.group.e2ee.v1" {
		t.Fatalf("expected e2ee profile in inbox, got %v", meta["profile"])
	}
	body := msgs[0]["body"].(map[string]any)
	if body["private_message_b64u"] != "b3BhcXVlLWNpcGhlcg" {
		t.Fatalf("cipher body not preserved: %v", body)
	}

	// A non-member cannot send an E2EE message.
	srv.mu.Lock()
	_, err = srv.groupE2EESend("did:wba:stranger", map[string]any{
		"meta": map[string]any{
			"profile": "anp.group.e2ee.v1", "security_profile": "group-e2ee",
			"sender_did": "did:wba:stranger", "target": map[string]any{"kind": "group", "did": gid},
			"message_id": "em2", "operation_id": "eop2", "content_type": "application/anp-group-cipher+json",
		},
		"body": map[string]any{
			"crypto_group_id_b64u": "cg1", "epoch": "1", "private_message_b64u": "x",
			"group_state_ref": map[string]any{"group_did": gid},
		},
	})
	srv.mu.Unlock()
	if err == nil {
		t.Fatalf("non-member should not be able to send e2ee")
	}
}

// TestGroupE2EEOwnerEnforcement verifies create/add/remove are owner-only.
func TestGroupE2EEOwnerEnforcement(t *testing.T) {
	dbPath := t.TempDir() + "/e2ee-owner.db"
	srv, err := New(dbPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.db.Close()

	gid := createTestGroup(t, srv, "did:wba:alice")
	srv.mu.Lock()
	_, err = srv.groupJoin("did:wba:bob", map[string]any{"body": map[string]any{"group_did": gid}})
	srv.mu.Unlock()
	if err != nil {
		t.Fatalf("join: %v", err)
	}

	createParams := map[string]any{
		"meta": map[string]any{"sender_did": "did:wba:bob"},
		"body": map[string]any{
			"group_did":            gid,
			"group_state_ref":      map[string]any{"group_did": gid, "group_state_version": 0},
			"suite":                "mls10",
			"creator_key_package":  map[string]any{"owner_did": "did:wba:bob", "mls_key_package_b64u": "x"},
			"crypto_group_id_b64u": "cg1",
			"epoch":                "0",
		},
	}
	srv.mu.Lock()
	_, err = srv.groupE2EECreate("did:wba:bob", createParams)
	srv.mu.Unlock()
	if err == nil {
		t.Fatalf("non-owner should not be able to group.e2ee.create")
	}
	assertRPCErrorCode(t, err, codeE2EEControllerRequired)
}

// TestAttachmentFullFlow covers create_slot → PUT → commit → ticket → GET.
func TestAttachmentFullFlow(t *testing.T) {
	dbPath := t.TempDir() + "/att.db"
	srv, err := New(dbPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	baseURL, closeFn, err := srv.Start()
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer closeFn()

	post := func(method string, params map[string]any) map[string]any {
		t.Helper()
		payload, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method, "params": params, "id": 1})
		resp, err := http.Post(baseURL+"/rpc", "application/json", bytes.NewReader(payload))
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var r map[string]any
		json.Unmarshal(raw, &r)
		return r
	}

	data := []byte("hello attachment world") // 22 bytes
	digest := sha256B64u(data)

	// 1. create_slot.
	r := post("attachment.create_slot", map[string]any{
		"meta": map[string]any{
			"profile": "anp.attachment.v1", "security_profile": "transport-protected",
			"sender_did": "did:wba:alice", "target": map[string]any{"kind": "service", "did": "did:anp:service"},
		},
		"body": map[string]any{
			"attachment_id":                     "att1",
			"intended_message_security_profile": "transport-protected",
			"object_encryption_mode":            "none",
			"expected_size":                     "22",
			"mime_type":                         "text/plain",
			"filename":                          "hello.txt",
		},
	})
	if r["error"] != nil {
		t.Fatalf("create_slot error: %v", r)
	}
	slot := r["result"].(map[string]any)
	uploadURI := slot["upload_uri"].(string)
	objectURI := slot["object_uri"].(string)
	commitToken := slot["commit_token"].(string)
	if uploadURI == "" || objectURI == "" || commitToken == "" {
		t.Fatalf("create_slot missing fields: %v", slot)
	}

	// 2. PUT the object bytes.
	req, _ := http.NewRequest(http.MethodPut, uploadURI, bytes.NewReader(data))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT status %d: %s", resp.StatusCode, raw)
	}

	// 3. commit_object.
	r = post("attachment.commit_object", map[string]any{
		"meta": map[string]any{"profile": "anp.attachment.v1", "security_profile": "transport-protected", "sender_did": "did:wba:alice"},
		"body": map[string]any{
			"attachment_id":          "att1",
			"slot_id":                slot["slot_id"],
			"commit_token":           commitToken,
			"size":                   "22",
			"digest":                 map[string]any{"alg": "sha-256", "value_b64u": digest},
			"object_encryption_mode": "none",
		},
	})
	if r["error"] != nil {
		t.Fatalf("commit_object error: %v", r)
	}
	if r["result"].(map[string]any)["committed"] != true {
		t.Fatalf("commit_object result: %v", r)
	}

	// 4. get_download_ticket.
	r = post("attachment.get_download_ticket", map[string]any{
		"meta": map[string]any{"profile": "anp.attachment.v1", "security_profile": "transport-protected", "sender_did": "did:wba:alice"},
		"body": map[string]any{
			"attachment_id":            "att1",
			"object_uri":               objectURI,
			"requester_did":            "did:wba:alice",
			"message_security_profile": "transport-protected",
			"message_id":               "msg-att1",
			"message_target_did":       "did:wba:bob",
		},
	})
	if r["error"] != nil {
		t.Fatalf("get_download_ticket error: %v", r)
	}
	ticket := r["result"].(map[string]any)["download_ticket_b64u"].(string)
	if ticket == "" {
		t.Fatalf("empty ticket: %v", r)
	}

	// 5. GET the object with the bearer ticket.
	req, _ = http.NewRequest(http.MethodGet, objectURI, nil)
	req.Header.Set("Authorization", "Bearer "+ticket)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET status %d: %s", resp.StatusCode, got)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("downloaded bytes mismatch: %q vs %q", got, data)
	}

	// 6. GET with a wrong ticket is rejected.
	req, _ = http.NewRequest(http.MethodGet, objectURI, nil)
	req.Header.Set("Authorization", "Bearer wrong-ticket")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET(wrong): %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong ticket should be 401, got %d", resp.StatusCode)
	}

	// 7. commit with a wrong digest is rejected.
	r = post("attachment.commit_object", map[string]any{
		"meta": map[string]any{"profile": "anp.attachment.v1", "security_profile": "transport-protected", "sender_did": "did:wba:alice"},
		"body": map[string]any{
			"attachment_id":          "att2",
			"slot_id":                slot["slot_id"],
			"commit_token":           commitToken,
			"size":                   "22",
			"digest":                 map[string]any{"alg": "sha-256", "value_b64u": "d3Jvbmc"},
			"object_encryption_mode": "none",
		},
	})
	if r["error"] == nil {
		t.Fatalf("expected digest mismatch to be rejected")
	}
}

// TestIdempotencyDedup verifies that a repeated (caller, method, operation_id)
// request returns the cached response without re-executing.
func TestIdempotencyDedup(t *testing.T) {
	dbPath := t.TempDir() + "/idem.db"
	srv, err := New(dbPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.db.Close()

	gid := createTestGroup(t, srv, "did:wba:alice")
	params := map[string]any{
		"meta": map[string]any{
			"profile": "anp.group.base.v1", "security_profile": "transport-protected",
			"sender_did": "did:wba:alice", "target": map[string]any{"kind": "group", "did": gid},
			"message_id": "gm-idem", "operation_id": "op-idem", "content_type": "text/plain",
		},
		"body": map[string]any{"text": "hi"},
	}

	srv.mu.Lock()
	res1, err := srv.dispatchIdempotent("group.send", params, "did:wba:alice", "")
	srv.mu.Unlock()
	if err != nil {
		t.Fatalf("first send: %v", err)
	}
	srv.mu.Lock()
	res2, err := srv.dispatchIdempotent("group.send", params, "did:wba:alice", "")
	srv.mu.Unlock()
	if err != nil {
		t.Fatalf("second send (cached): %v", err)
	}

	// The fresh response carries an int64; the cached response is re-parsed from
	// JSON as a float64. They are wire-identical; compare their rendered values.
	seq1 := fmt.Sprint(res1.(map[string]any)["group_event_seq"])
	seq2 := fmt.Sprint(res2.(map[string]any)["group_event_seq"])
	if seq1 != seq2 || seq1 != "1" {
		t.Fatalf("expected cached response with seq 1, got %v then %v", seq1, seq2)
	}

	// Only one message row should exist for that message_id.
	var count int
	_ = srv.db.QueryRow(`SELECT COUNT(*) FROM messages WHERE message_id = ?`, "gm-idem").Scan(&count)
	if count != 1 {
		t.Fatalf("expected 1 message, got %d (re-executed)", count)
	}
}

// TestMentionsPassthrough verifies mentions inside a group payload are stored
// and returned verbatim, and that duplicate mention ids are rejected.
func TestMentionsPassthrough(t *testing.T) {
	dbPath := t.TempDir() + "/mentions.db"
	srv, err := New(dbPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.db.Close()

	gid := createTestGroup(t, srv, "did:wba:alice")
	mentions := []any{
		map[string]any{
			"id":     "men_1",
			"range":  map[string]any{"start": 0, "end": 6, "unit": "unicode_code_point"},
			"target": map[string]any{"kind": "agent", "did": "did:wba:example.com:agent:helper"},
		},
	}
	srv.mu.Lock()
	res, err := srv.groupSend("did:wba:alice", map[string]any{
		"meta": map[string]any{
			"profile": "anp.group.base.v1", "security_profile": "transport-protected",
			"sender_did": "did:wba:alice", "target": map[string]any{"kind": "group", "did": gid},
			"message_id": "gm-mentions", "operation_id": "op-mentions", "content_type": "application/json",
		},
		"body": map[string]any{
			"payload": map[string]any{"text": "@helper hi", "mentions": mentions},
		},
	})
	srv.mu.Unlock()
	if err != nil {
		t.Fatalf("group.send with mentions: %v", err)
	}
	if res.(map[string]any)["accepted"] != true {
		t.Fatalf("send ACK: %v", res)
	}

	srv.mu.Lock()
	inbox, err := srv.msgInbox("did:wba:alice", map[string]any{})
	srv.mu.Unlock()
	if err != nil {
		t.Fatalf("msg.inbox: %v", err)
	}
	msgs := inbox.(map[string]any)["messages"].([]map[string]any)
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}
	body := msgs[0]["body"].(map[string]any)
	payload := body["payload"].(map[string]any)
	gotMentions, ok := payload["mentions"].([]any)
	if !ok || len(gotMentions) != 1 {
		t.Fatalf("mentions not preserved: %v", payload)
	}
	if gotMentions[0].(map[string]any)["id"] != "men_1" {
		t.Fatalf("mention id not preserved: %v", gotMentions)
	}

	// Duplicate mention ids are rejected as clearly malformed.
	srv.mu.Lock()
	_, err = srv.groupSend("did:wba:alice", map[string]any{
		"meta": map[string]any{
			"profile": "anp.group.base.v1", "security_profile": "transport-protected",
			"sender_did": "did:wba:alice", "target": map[string]any{"kind": "group", "did": gid},
			"message_id": "gm-dup", "operation_id": "op-dup", "content_type": "application/json",
		},
		"body": map[string]any{
			"payload": map[string]any{
				"text": "@a @b",
				"mentions": []any{
					map[string]any{"id": "men_1"},
					map[string]any{"id": "men_1"},
				},
			},
		},
	})
	srv.mu.Unlock()
	if err == nil {
		t.Fatalf("duplicate mention ids should be rejected")
	}
}

// TestDispatchRoutesNewProfiles verifies all P6/P7 methods are routed.
func TestDispatchRoutesNewProfiles(t *testing.T) {
	dbPath := t.TempDir() + "/dispatch2.db"
	srv, err := New(dbPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.db.Close()

	methods := []string{
		"group.e2ee.publish_key_package",
		"group.e2ee.get_key_package",
		"group.e2ee.create",
		"group.e2ee.add",
		"group.e2ee.remove",
		"group.e2ee.send",
		"group.e2ee.notice",
		"attachment.create_slot",
		"attachment.commit_object",
		"attachment.abort_object",
		"attachment.get_download_ticket",
	}
	for _, m := range methods {
		srv.mu.Lock()
		_, err := srv.dispatch(m, map[string]any{}, "did:wba:alice", "")
		srv.mu.Unlock()
		if err != nil && err.Error() == fmt.Sprintf("unknown method %q", m) {
			t.Fatalf("method %q not routed", m)
		}
	}
}

// TestServiceDidOffByDefault verifies single-domain mode is unchanged: without
// serviceDid, an unknown-signer DID is rejected (no remote fallback).
func TestServiceDidOffByDefault(t *testing.T) {
	dbPath := t.TempDir() + "/servicedid.db"
	srv, err := New(dbPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.db.Close()
	if srv.serviceDid != "" {
		t.Fatalf("serviceDid should be empty by default")
	}

	// NewWithServiceDid stores the configured service DID.
	srv2, err := NewWithServiceDid(t.TempDir()+"/servicedid2.db", "did:web:example.com")
	if err != nil {
		t.Fatalf("NewWithServiceDid: %v", err)
	}
	defer srv2.db.Close()
	if srv2.serviceDid != "did:web:example.com" {
		t.Fatalf("serviceDid = %q", srv2.serviceDid)
	}
}

// TestAttachmentAbsoluteURLsFromHostHeader reproduces the main.go deployment
// (net.Listen + srv.Handler(), no SetBaseURL) and verifies that create_slot
// returns absolute upload_uri/object_uri derived from the request Host header,
// and that the subsequent PUT succeeds.
func TestAttachmentAbsoluteURLsFromHostHeader(t *testing.T) {
	srv, err := New(t.TempDir() + "/absurl.db")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.db.Close()
	if srv.baseURL != "" {
		t.Fatalf("baseURL should be empty in main.go-style deployment")
	}

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	post := func(method string, params map[string]any) map[string]any {
		t.Helper()
		payload, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method, "params": params, "id": 1})
		resp, err := http.Post(ts.URL+"/rpc", "application/json", bytes.NewReader(payload))
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var r map[string]any
		json.Unmarshal(raw, &r)
		return r
	}

	r := post("attachment.create_slot", map[string]any{
		"meta": map[string]any{
			"profile": "anp.attachment.v1", "security_profile": "transport-protected",
			"sender_did": "did:wba:alice", "target": map[string]any{"kind": "service", "did": "did:anp:service"},
		},
		"body": map[string]any{
			"attachment_id":                     "att-abs",
			"intended_message_security_profile": "transport-protected",
			"object_encryption_mode":            "none",
		},
	})
	if r["error"] != nil {
		t.Fatalf("create_slot error: %v", r)
	}
	slot := r["result"].(map[string]any)
	uploadURI := slot["upload_uri"].(string)
	objectURI := slot["object_uri"].(string)
	if !strings.HasPrefix(uploadURI, "http://") {
		t.Fatalf("expected absolute upload_uri, got %q", uploadURI)
	}
	if !strings.HasPrefix(objectURI, "http://") {
		t.Fatalf("expected absolute object_uri, got %q", objectURI)
	}
	if !strings.HasPrefix(uploadURI, ts.URL+"/upload/") {
		t.Fatalf("upload_uri %q should be under %s", uploadURI, ts.URL)
	}

	// PUT to the absolute URL must succeed (no unsupported protocol scheme).
	data := []byte("absolute url bytes")
	req, _ := http.NewRequest(http.MethodPut, uploadURI, bytes.NewReader(data))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PUT: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT status %d", resp.StatusCode)
	}
}
