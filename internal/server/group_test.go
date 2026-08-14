package server

import (
	"testing"

	anp "github.com/agent-network-protocol/anp/golang"
	"github.com/agent-network-protocol/anp/golang/authentication"
	"github.com/agent-network-protocol/anp/golang/proof"
)

func createTestGroup(t *testing.T, srv *Server, owner string) string {
	t.Helper()
	srv.mu.Lock()
	res, err := srv.groupCreate(owner, map[string]any{
		"meta": map[string]any{"sender_did": owner},
		"body": map[string]any{
			"group_policy": map[string]any{
				"admission_mode":             "open-join",
				"message_security_profile":   "transport-protected",
				"bootstrap_security_profile": "transport-protected",
				"permissions": map[string]any{
					"send":           "member",
					"add":            "admin",
					"remove":         "admin",
					"update_profile": "admin",
					"update_policy":  "owner",
				},
			},
			"group_profile": map[string]any{"display_name": "Test Group"},
		},
	})
	srv.mu.Unlock()
	if err != nil {
		t.Fatalf("group.create: %v", err)
	}
	rm := res.(map[string]any)
	if rm["group_did"] == "" {
		t.Fatalf("group.create missing group_did: %v", rm)
	}
	if rm["creator_did"] != owner {
		t.Fatalf("creator_did = %v, want %s", rm["creator_did"], owner)
	}
	if v, _ := rm["group_state_version"].(int64); v != 0 {
		t.Fatalf("initial group_state_version = %v, want 0", rm["group_state_version"])
	}
	return rm["group_did"].(string)
}

func TestGroupLifecycle(t *testing.T) {
	dbPath := t.TempDir() + "/group.db"
	srv, err := New(dbPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.db.Close()

	gid := createTestGroup(t, srv, "did:wba:alice")

	// group.get_info.
	srv.mu.Lock()
	res, err := srv.groupGetInfo(map[string]any{"body": map[string]any{"group_did": gid, "include_policy": true, "include_member_list": true}})
	srv.mu.Unlock()
	if err != nil {
		t.Fatalf("group.get_info: %v", err)
	}
	rm := res.(map[string]any)
	if rm["group_did"] != gid {
		t.Fatalf("get_info group_did = %v, want %s", rm["group_did"], gid)
	}
	if rm["group_policy"] == nil {
		t.Fatalf("get_info missing group_policy")
	}
	if rm["member_list"] == nil {
		t.Fatalf("get_info missing member_list")
	}

	// group.join (open-join, bob).
	srv.mu.Lock()
	res, err = srv.groupJoin("did:wba:bob", map[string]any{"body": map[string]any{"group_did": gid}})
	srv.mu.Unlock()
	if err != nil {
		t.Fatalf("group.join: %v", err)
	}
	rm = res.(map[string]any)
	if rm["member_did"] != "did:wba:bob" || rm["membership_status"] != "active" {
		t.Fatalf("group.join result: %v", rm)
	}
	if v, _ := rm["group_state_version"].(int64); v != 1 {
		t.Fatalf("group_state_version after join = %v, want 1", rm["group_state_version"])
	}

	// group.send by alice; bob should see it in the inbox.
	srv.mu.Lock()
	res, err = srv.groupSend("did:wba:alice", map[string]any{
		"meta": map[string]any{
			"profile":          "anp.group.base.v1",
			"security_profile": "transport-protected",
			"sender_did":       "did:wba:alice",
			"target":           map[string]any{"kind": "group", "did": gid},
			"message_id":       "gm1",
			"operation_id":     "op1",
			"content_type":     "text/plain",
		},
		"body": map[string]any{"text": "hello group"},
	})
	srv.mu.Unlock()
	if err != nil {
		t.Fatalf("group.send: %v", err)
	}
	rm = res.(map[string]any)
	if rm["accepted"] != true {
		t.Fatalf("group.send accepted = %v", rm["accepted"])
	}
	if v, _ := rm["group_event_seq"].(int64); v != 1 {
		t.Fatalf("group_event_seq = %v, want 1", rm["group_event_seq"])
	}

	// bob's inbox contains the group message.
	srv.mu.Lock()
	inbox, err := srv.msgInbox("did:wba:bob", map[string]any{})
	srv.mu.Unlock()
	if err != nil {
		t.Fatalf("msg.inbox: %v", err)
	}
	msgs := inbox.(map[string]any)["messages"].([]map[string]any)
	if len(msgs) != 1 {
		t.Fatalf("bob inbox should have 1 group message, got %d", len(msgs))
	}

	// group.add (admin alice adds carol via DID).
	srv.mu.Lock()
	res, err = srv.groupAdd("did:wba:alice", map[string]any{
		"body": map[string]any{"group_did": gid, "member_did": "did:wba:carol"},
	})
	srv.mu.Unlock()
	if err != nil {
		t.Fatalf("group.add: %v", err)
	}
	rm = res.(map[string]any)
	if rm["member_did"] != "did:wba:carol" || rm["membership_status"] != "active" {
		t.Fatalf("group.add result: %v", rm)
	}

	// group.remove (admin alice removes carol).
	srv.mu.Lock()
	_, err = srv.groupRemove("did:wba:alice", map[string]any{
		"body": map[string]any{"group_did": gid, "member_did": "did:wba:carol"},
	})
	srv.mu.Unlock()
	if err != nil {
		t.Fatalf("group.remove: %v", err)
	}

	// group.update_profile (admin alice).
	srv.mu.Lock()
	res, err = srv.groupUpdateProfile("did:wba:alice", map[string]any{
		"body": map[string]any{"group_did": gid, "group_profile": map[string]any{"display_name": "Renamed"}},
	})
	srv.mu.Unlock()
	if err != nil {
		t.Fatalf("group.update_profile: %v", err)
	}
	if p := res.(map[string]any)["group_profile"].(map[string]any); p["display_name"] != "Renamed" {
		t.Fatalf("update_profile result: %v", res)
	}

	// group.update_policy (owner alice).
	srv.mu.Lock()
	res, err = srv.groupUpdatePolicy("did:wba:alice", map[string]any{
		"body": map[string]any{"group_did": gid, "group_policy_patch": map[string]any{"max_members": "1000"}},
	})
	srv.mu.Unlock()
	if err != nil {
		t.Fatalf("group.update_policy: %v", err)
	}
	if p := res.(map[string]any)["group_policy"].(map[string]any); p["max_members"] != "1000" {
		t.Fatalf("update_policy result: %v", res)
	}

	// group.rebind_member (bob → bob2).
	srv.mu.Lock()
	res, err = srv.groupRebindMember("did:wba:bob2", map[string]any{
		"body": map[string]any{
			"group_did":                 gid,
			"member_handle":             "bob.example.com",
			"previous_member_did":       "did:wba:bob",
			"new_member_did":            "did:wba:bob2",
			"handle_binding_generation": 2,
		},
	})
	srv.mu.Unlock()
	if err != nil {
		t.Fatalf("group.rebind_member: %v", err)
	}
	rm = res.(map[string]any)
	if rm["member_did"] != "did:wba:bob2" || rm["membership_status"] != "active" {
		t.Fatalf("group.rebind_member result: %v", rm)
	}

	// group.leave (bob2 leaves).
	srv.mu.Lock()
	res, err = srv.groupLeave("did:wba:bob2", map[string]any{"body": map[string]any{"group_did": gid}})
	srv.mu.Unlock()
	if err != nil {
		t.Fatalf("group.leave: %v", err)
	}
	if res.(map[string]any)["leaver_did"] != "did:wba:bob2" {
		t.Fatalf("group.leave result: %v", res)
	}
}

func TestGroupPermissionEnforcement(t *testing.T) {
	dbPath := t.TempDir() + "/perm.db"
	srv, err := New(dbPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.db.Close()

	gid := createTestGroup(t, srv, "did:wba:alice")
	// bob joins.
	srv.mu.Lock()
	_, err = srv.groupJoin("did:wba:bob", map[string]any{"body": map[string]any{"group_did": gid}})
	srv.mu.Unlock()
	if err != nil {
		t.Fatalf("join: %v", err)
	}

	// bob (member) may NOT add or update policy.
	srv.mu.Lock()
	_, err = srv.groupAdd("did:wba:bob", map[string]any{
		"body": map[string]any{"group_did": gid, "member_did": "did:wba:carol"},
	})
	srv.mu.Unlock()
	if err == nil {
		t.Fatalf("member should not be able to add")
	}

	srv.mu.Lock()
	_, err = srv.groupUpdatePolicy("did:wba:bob", map[string]any{
		"body": map[string]any{"group_did": gid, "group_policy": map[string]any{"admission_mode": "admin-add"}},
	})
	srv.mu.Unlock()
	if err == nil {
		t.Fatalf("member should not be able to update policy")
	}
}

func TestGroupSendRequiresMembership(t *testing.T) {
	dbPath := t.TempDir() + "/send.db"
	srv, err := New(dbPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.db.Close()

	gid := createTestGroup(t, srv, "did:wba:alice")
	srv.mu.Lock()
	_, err = srv.groupSend("did:wba:stranger", map[string]any{
		"meta": map[string]any{
			"profile": "anp.group.base.v1", "security_profile": "transport-protected",
			"sender_did": "did:wba:stranger", "target": map[string]any{"kind": "group", "did": gid},
			"message_id": "gm2", "operation_id": "op2", "content_type": "text/plain",
		},
		"body": map[string]any{"text": "hi"},
	})
	srv.mu.Unlock()
	if err == nil {
		t.Fatalf("non-member should not be able to send")
	}
}

func TestDirectSendPlaintext(t *testing.T) {
	dbPath := t.TempDir() + "/direct.db"
	srv, err := New(dbPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.db.Close()

	// Generate a real did:wba identity so a valid origin proof can be produced.
	bundle, err := authentication.CreateDidWBADocument("example.com", authentication.DidDocumentOptions{PathSegments: []string{"user", "alice"}})
	if err != nil {
		t.Fatalf("CreateDidWBADocument: %v", err)
	}
	privateKey, err := anp.PrivateKeyFromPEM(bundle.Keys[authentication.VMKeyAuth].PrivateKeyPEM)
	if err != nil {
		t.Fatalf("PrivateKeyFromPEM: %v", err)
	}
	did := bundle.DidDocument["id"].(string)

	// Register the DID document so origin proof verification can resolve it.
	srv.mu.Lock()
	_, err = srv.didRegisterDocument(map[string]any{"did": did, "did_document": bundle.DidDocument})
	srv.mu.Unlock()
	if err != nil {
		t.Fatalf("didRegisterDocument: %v", err)
	}

	meta := map[string]any{
		"profile":          "anp.direct.base.v1",
		"security_profile": "transport-protected",
		"sender_did":       did,
		"target":           map[string]any{"kind": "agent", "did": "did:wba:example.com:user:bob:e1_bob"},
		"operation_id":     "op-plain",
		"message_id":       "msg-plain",
		"content_type":     "text/plain",
	}
	body := map[string]any{"text": "hello plaintext"}
	op, err := proof.GenerateRFC9421OriginProof("direct.send", meta, body, privateKey, did+"#"+authentication.VMKeyAuth, proof.RFC9421OriginProofGenerationOptions{})
	if err != nil {
		t.Fatalf("GenerateRFC9421OriginProof: %v", err)
	}

	srv.mu.Lock()
	res, err := srv.directSend(did, map[string]any{
		"meta": meta,
		"body": body,
		"auth": map[string]any{
			"scheme": "anp-rfc9421-origin-proof-v1",
			"origin_proof": map[string]any{
				"contentDigest":  op.ContentDigest,
				"signatureInput": op.SignatureInput,
				"signature":      op.Signature,
			},
		},
	})
	srv.mu.Unlock()
	if err != nil {
		t.Fatalf("directSend plaintext: %v", err)
	}
	rm := res.(map[string]any)
	if rm["accepted"] != true || rm["message_id"] != "msg-plain" || rm["operation_id"] != "op-plain" {
		t.Fatalf("directSend plaintext ACK: %v", rm)
	}
	if rm["target_did"] != "did:wba:example.com:user:bob:e1_bob" {
		t.Fatalf("target_did: %v", rm["target_did"])
	}
	if rm["accepted_at"] == "" {
		t.Fatalf("accepted_at missing: %v", rm)
	}

	// Plaintext direct without origin proof must be rejected.
	srv.mu.Lock()
	_, err = srv.directSend(did, map[string]any{"meta": meta, "body": body})
	srv.mu.Unlock()
	if err == nil {
		t.Fatalf("plaintext direct.send without origin proof must fail")
	}
}

func TestDispatchRoutesAllMethods(t *testing.T) {
	dbPath := t.TempDir() + "/dispatch.db"
	srv, err := New(dbPath)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer srv.db.Close()

	gid := createTestGroup(t, srv, "did:wba:alice")

	cases := []struct {
		method string
		params map[string]any
	}{
		{"group.get_info", map[string]any{"body": map[string]any{"group_did": gid}}},
		{"group.join", map[string]any{"body": map[string]any{"group_did": gid}}},
		{"group.add", map[string]any{"body": map[string]any{"group_did": gid, "member_did": "did:wba:carol"}}},
		{"group.remove", map[string]any{"body": map[string]any{"group_did": gid, "member_did": "did:wba:carol"}}},
		{"group.leave", map[string]any{"body": map[string]any{"group_did": gid}}},
		{"group.update_profile", map[string]any{"body": map[string]any{"group_did": gid, "group_profile": map[string]any{"display_name": "x"}}}},
		{"group.update_policy", map[string]any{"body": map[string]any{"group_did": gid, "group_policy": map[string]any{"admission_mode": "open-join"}}}},
		{"group.send", map[string]any{
			"meta": map[string]any{"profile": "anp.group.base.v1", "security_profile": "transport-protected",
				"sender_did": "did:wba:alice", "target": map[string]any{"kind": "group", "did": gid},
				"message_id": "gmx", "operation_id": "opx", "content_type": "text/plain"},
			"body": map[string]any{"text": "hi"},
		}},
		{"group.incoming", map[string]any{}},
		{"group.state_changed", map[string]any{}},
		{"direct.incoming", map[string]any{}},
		{"group.rebind_member", map[string]any{
			"body": map[string]any{
				"group_did":                 gid,
				"member_handle":             "bob.example.com",
				"previous_member_did":       "did:wba:carol",
				"new_member_did":            "did:wba:carol2",
				"handle_binding_generation": 1,
			},
		}},
	}

	for _, c := range cases {
		srv.mu.Lock()
		_, err := srv.dispatch(c.method, c.params, "did:wba:alice", "")
		srv.mu.Unlock()
		if err != nil && err.Error() == "unknown method \""+c.method+"\"" {
			t.Fatalf("method %q not routed", c.method)
		}
		// Note: some methods may return permission/membership errors depending
		// on prior state; routing correctness is what matters here.
	}

	// The 12 group methods must all be present as distinct routes.
	for _, m := range []string{"group.create", "group.get_info", "group.join", "group.add", "group.remove", "group.leave", "group.update_profile", "group.update_policy", "group.send", "group.incoming", "group.state_changed", "group.rebind_member"} {
		srv.mu.Lock()
		_, err := srv.dispatch(m, map[string]any{"body": map[string]any{"group_did": gid}}, "did:wba:alice", "")
		srv.mu.Unlock()
		if err != nil && err.Error() == "unknown method \""+m+"\"" {
			t.Fatalf("method %q not routed", m)
		}
	}
}
