package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// group_e2ee.go implements the ANP P6 group end-to-end encryption profile
// (profile "anp.group.e2ee.v1", security_profile "group-e2ee"). The server is
// MLS-unaware: every MLS object (key_package, commit, welcome, ratchet_tree,
// private_message) is an opaque base64url string that is validated only for
// presence, stored, and forwarded. All MLS computation (KeyPackage/commit/
// welcome/encryption) happens on the agent side (owner and members).

// requiredBodyString validates that a MUST field is present and non-empty.
func requiredBodyString(body map[string]any, field string) (string, error) {
	v, _ := body[field].(string)
	if v == "" {
		return "", &rpcError{code: codeInvalidParams, msg: fmt.Sprintf("%s is required", field)}
	}
	return v, nil
}

// groupE2EEGroupDID extracts the target group DID for group.e2ee methods,
// preferring body.group_did and falling back to group_state_ref.group_did.
func groupE2EEGroupDID(body map[string]any) string {
	if gid, _ := body["group_did"].(string); gid != "" {
		return gid
	}
	if ref := asMap(body["group_state_ref"]); ref != nil {
		if gid, _ := ref["group_did"].(string); gid != "" {
			return gid
		}
	}
	return ""
}

// groupE2EERequireOwner enforces that the caller is the group owner (P6 add /
// remove / create are owner-only operations).
func (s *Server) groupE2EERequireOwner(gid, authDID string) error {
	if authDID == "" {
		return fmt.Errorf("caller identity is required")
	}
	if s.groupMemberRole(gid, authDID) != "owner" {
		return &rpcError{code: codeE2EEControllerRequired, msg: "group.e2ee.controller_required"}
	}
	return nil
}

// storeE2EEState upserts the crypto group state for (group_did, crypto_group_id).
func (s *Server) storeE2EEState(gid, cryptoGroupID, epoch string, state map[string]any) error {
	stateRaw, _ := json.Marshal(state)
	_, err := s.db.Exec(`INSERT INTO group_e2ee_states (group_did, crypto_group_id, epoch, state_json, updated_at) VALUES (?,?,?,?,?)
		ON CONFLICT(group_did, crypto_group_id) DO UPDATE SET epoch=excluded.epoch, state_json=excluded.state_json, updated_at=excluded.updated_at`,
		gid, cryptoGroupID, epoch, string(stateRaw), time.Now().UTC().Format(time.RFC3339))
	return err
}

// groupE2EEPublishKeyPackage handles group.e2ee.publish_key_package: an agent
// publishes its own MLS KeyPackage. The owner_did is forced to the
// authenticated caller so an agent cannot overwrite another's package.
func (s *Server) groupE2EEPublishKeyPackage(authDID string, params map[string]any) (any, error) {
	body := asMap(params["body"])
	if body == nil {
		return nil, &rpcError{code: codeInvalidParams, msg: "body is required"}
	}
	pkg := asMap(body["group_key_package"])
	if pkg == nil {
		return nil, &rpcError{code: codeInvalidParams, msg: "group_key_package is required"}
	}
	ownerDID, _ := pkg["owner_did"].(string)
	if authDID != "" {
		ownerDID = authDID
	}
	if ownerDID == "" {
		return nil, &rpcError{code: codeInvalidParams, msg: "group_key_package.owner_did is required"}
	}
	keyPackageID, err := requiredBodyString(pkg, "key_package_id")
	if err != nil {
		return nil, err
	}
	if _, err := requiredBodyString(pkg, "mls_key_package_b64u"); err != nil {
		return nil, err
	}
	// Normalize the package so the stored owner_did matches the caller.
	pkg["owner_did"] = ownerDID
	pkgRaw, _ := json.Marshal(pkg)
	publishedAt := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.db.Exec(`INSERT INTO group_key_packages (owner_did, key_package_json, key_package_id, published_at) VALUES (?,?,?,?)
		ON CONFLICT(owner_did) DO UPDATE SET key_package_json=excluded.key_package_json, key_package_id=excluded.key_package_id, published_at=excluded.published_at`,
		ownerDID, string(pkgRaw), keyPackageID, publishedAt); err != nil {
		return nil, err
	}
	return map[string]any{
		"published":      true,
		"owner_did":      ownerDID,
		"key_package_id": keyPackageID,
		"published_at":   publishedAt,
	}, nil
}

// groupE2EEGetKeyPackage handles group.e2ee.get_key_package: fetch an agent's
// published MLS KeyPackage.
func (s *Server) groupE2EEGetKeyPackage(params map[string]any) (any, error) {
	body := asMap(params["body"])
	targetDID, err := requiredBodyString(body, "target_did")
	if err != nil {
		return nil, err
	}
	var pkgJSON string
	if err := s.db.QueryRow(`SELECT key_package_json FROM group_key_packages WHERE owner_did = ? ORDER BY published_at DESC LIMIT 1`, targetDID).Scan(&pkgJSON); err != nil {
		if err == sql.ErrNoRows {
			return nil, &rpcError{code: codeE2EEKeyPackageNotFound, msg: "group.e2ee.key_package_not_found"}
		}
		return nil, err
	}
	var pkg map[string]any
	_ = json.Unmarshal([]byte(pkgJSON), &pkg)
	return map[string]any{"target_did": targetDID, "group_key_package": pkg}, nil
}

// groupE2EECreate handles group.e2ee.create: the owner initializes the crypto
// group state. All MLS objects are stored verbatim.
func (s *Server) groupE2EECreate(authDID string, params map[string]any) (any, error) {
	body := asMap(params["body"])
	if body == nil {
		return nil, &rpcError{code: codeInvalidParams, msg: "body is required"}
	}
	gid := groupE2EEGroupDID(body)
	if gid == "" {
		return nil, &rpcError{code: codeInvalidParams, msg: "group_did is required"}
	}
	if err := s.groupE2EERequireOwner(gid, authDID); err != nil {
		return nil, err
	}
	groupStateRef := asMap(body["group_state_ref"])
	if groupStateRef == nil {
		return nil, &rpcError{code: codeInvalidParams, msg: "group_state_ref is required"}
	}
	if _, err := requiredBodyString(body, "suite"); err != nil {
		return nil, err
	}
	creatorKP := asMap(body["creator_key_package"])
	if creatorKP == nil {
		return nil, &rpcError{code: codeInvalidParams, msg: "creator_key_package is required"}
	}
	cryptoGroupID, err := requiredBodyString(body, "crypto_group_id_b64u")
	if err != nil {
		return nil, err
	}
	epoch, err := requiredBodyString(body, "epoch")
	if err != nil {
		return nil, err
	}
	// creator_key_package.owner_did must match the caller (spec: MUST).
	if creatorOwner, _ := creatorKP["owner_did"].(string); creatorOwner != "" && authDID != "" && creatorOwner != authDID {
		return nil, &rpcError{code: codeE2EEInvalidKeyPackage, msg: "creator_key_package.owner_did does not match sender"}
	}
	state := map[string]any{
		"group_did":            gid,
		"crypto_group_id_b64u": cryptoGroupID,
		"epoch":                epoch,
		"group_state_ref":      groupStateRef,
		"creator_key_package":  creatorKP,
		"suite":                body["suite"],
	}
	if err := s.storeE2EEState(gid, cryptoGroupID, epoch, state); err != nil {
		return nil, err
	}
	return map[string]any{
		"created":              true,
		"group_did":            gid,
		"group_state_ref":      groupStateRef,
		"crypto_group_id_b64u": cryptoGroupID,
		"epoch":                epoch,
		"accepted_at":          time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// groupE2EEAdd handles group.e2ee.add: the owner commits an MLS add. The
// commit/welcome/ratchet_tree are opaque bytes, stored and forwarded.
func (s *Server) groupE2EEAdd(authDID string, params map[string]any) (any, error) {
	body := asMap(params["body"])
	if body == nil {
		return nil, &rpcError{code: codeInvalidParams, msg: "body is required"}
	}
	gid := groupE2EEGroupDID(body)
	if gid == "" {
		return nil, &rpcError{code: codeInvalidParams, msg: "group_did is required"}
	}
	if err := s.groupE2EERequireOwner(gid, authDID); err != nil {
		return nil, err
	}
	memberDID, err := requiredBodyString(body, "member_did")
	if err != nil {
		return nil, err
	}
	groupStateRef := asMap(body["group_state_ref"])
	if groupStateRef == nil {
		return nil, &rpcError{code: codeInvalidParams, msg: "group_state_ref is required"}
	}
	cryptoGroupID, err := requiredBodyString(body, "crypto_group_id_b64u")
	if err != nil {
		return nil, err
	}
	epoch, err := requiredBodyString(body, "epoch")
	if err != nil {
		return nil, err
	}
	for _, f := range []string{"commit_b64u", "welcome_b64u", "ratchet_tree_b64u"} {
		if _, err := requiredBodyString(body, f); err != nil {
			return nil, err
		}
	}
	if _, err := requiredBodyString(asMap(body["group_key_package"]), "mls_key_package_b64u"); err != nil {
		return nil, err
	}
	state := map[string]any{
		"group_did":            gid,
		"crypto_group_id_b64u": cryptoGroupID,
		"epoch":                epoch,
		"group_state_ref":      groupStateRef,
		"member_did":           memberDID,
		"commit_b64u":          body["commit_b64u"],
		"welcome_b64u":         body["welcome_b64u"],
		"ratchet_tree_b64u":    body["ratchet_tree_b64u"],
		"group_key_package":    body["group_key_package"],
	}
	if err := s.storeE2EEState(gid, cryptoGroupID, epoch, state); err != nil {
		return nil, err
	}
	return map[string]any{
		"accepted":             true,
		"group_did":            gid,
		"member_did":           memberDID,
		"group_state_ref":      groupStateRef,
		"crypto_group_id_b64u": cryptoGroupID,
		"epoch":                epoch,
		"accepted_at":          time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// groupE2EERemove handles group.e2ee.remove: the owner commits an MLS remove.
func (s *Server) groupE2EERemove(authDID string, params map[string]any) (any, error) {
	body := asMap(params["body"])
	if body == nil {
		return nil, &rpcError{code: codeInvalidParams, msg: "body is required"}
	}
	gid := groupE2EEGroupDID(body)
	if gid == "" {
		return nil, &rpcError{code: codeInvalidParams, msg: "group_did is required"}
	}
	if err := s.groupE2EERequireOwner(gid, authDID); err != nil {
		return nil, err
	}
	memberDID, err := requiredBodyString(body, "member_did")
	if err != nil {
		return nil, err
	}
	groupStateRef := asMap(body["group_state_ref"])
	if groupStateRef == nil {
		return nil, &rpcError{code: codeInvalidParams, msg: "group_state_ref is required"}
	}
	cryptoGroupID, err := requiredBodyString(body, "crypto_group_id_b64u")
	if err != nil {
		return nil, err
	}
	epoch, err := requiredBodyString(body, "epoch")
	if err != nil {
		return nil, err
	}
	if _, err := requiredBodyString(body, "commit_b64u"); err != nil {
		return nil, err
	}
	state := map[string]any{
		"group_did":            gid,
		"crypto_group_id_b64u": cryptoGroupID,
		"epoch":                epoch,
		"group_state_ref":      groupStateRef,
		"member_did":           memberDID,
		"commit_b64u":          body["commit_b64u"],
	}
	if err := s.storeE2EEState(gid, cryptoGroupID, epoch, state); err != nil {
		return nil, err
	}
	return map[string]any{
		"accepted":             true,
		"group_did":            gid,
		"member_did":           memberDID,
		"group_state_ref":      groupStateRef,
		"crypto_group_id_b64u": cryptoGroupID,
		"epoch":                epoch,
		"accepted_at":          time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// groupE2EESend handles group.e2ee.send: an active member posts an MLS-encrypted
// group cipher message. The server stores the cipher object verbatim (no
// decryption) so that other members can retrieve it via msg.inbox.
func (s *Server) groupE2EESend(authDID string, params map[string]any) (any, error) {
	meta := asMap(params["meta"])
	body := asMap(params["body"])
	if body == nil {
		return nil, &rpcError{code: codeInvalidParams, msg: "body is required"}
	}
	target := asMap(meta["target"])
	gid, _ := target["did"].(string)
	if gid == "" {
		gid = groupE2EEGroupDID(body)
	}
	if gid == "" {
		return nil, &rpcError{code: codeInvalidParams, msg: "target.did (group_did) is required"}
	}
	messageID, _ := meta["message_id"].(string)
	operationID, _ := meta["operation_id"].(string)
	contentType, _ := meta["content_type"].(string)
	if messageID == "" {
		return nil, &rpcError{code: codeInvalidParams, msg: "message_id is required"}
	}
	if operationID == "" {
		return nil, &rpcError{code: codeInvalidParams, msg: "operation_id is required"}
	}
	if contentType != "application/anp-group-cipher+json" {
		return nil, &rpcError{code: codeInvalidParams, msg: "content_type must be application/anp-group-cipher+json"}
	}
	senderDID := authDID
	if senderDID == "" {
		senderDID, _ = meta["sender_did"].(string)
	}
	if !s.isGroupMember(gid, senderDID) {
		return nil, fmt.Errorf("sender %q is not an active member of group %q", senderDID, gid)
	}
	// group_cipher_object fields (all opaque, presence-checked only).
	for _, f := range []string{"crypto_group_id_b64u", "epoch", "private_message_b64u"} {
		if _, err := requiredBodyString(body, f); err != nil {
			return nil, err
		}
	}
	if asMap(body["group_state_ref"]) == nil {
		return nil, &rpcError{code: codeInvalidParams, msg: "group_state_ref is required"}
	}
	if auth, ok := params["auth"].(map[string]any); ok {
		if err := s.verifyOriginProof(senderDID, "group.e2ee.send", meta, body, auth); err != nil {
			return nil, err
		}
	}
	metaRaw, _ := json.Marshal(meta)
	bodyRaw, _ := json.Marshal(body)
	seq, err := s.nextGroupEventSeq(gid)
	if err != nil {
		return nil, err
	}
	version, err := s.groupStateVersion(gid)
	if err != nil {
		return nil, err
	}
	epoch, _ := body["epoch"].(string)
	acceptedAt := time.Now().UTC().Format(time.RFC3339)
	// Store as a group message with secure=1 (cipher), distinguished from base
	// plaintext by the stored meta.profile == "anp.group.e2ee.v1".
	if _, err := s.db.Exec(`INSERT INTO messages (message_id, sender_did, recipient_did, group_did, type, text, secure, sent_at, wire_meta, wire_body) VALUES (?,?,NULL,?,?,?,1,?,?,?)`,
		messageID, senderDID, gid, "cipher", "", acceptedAt, string(metaRaw), string(bodyRaw)); err != nil {
		return nil, err
	}
	return map[string]any{
		"accepted":            true,
		"group_did":           gid,
		"message_id":          messageID,
		"operation_id":        operationID,
		"group_event_seq":     seq,
		"group_state_version": version,
		"accepted_at":         acceptedAt,
		"epoch":               epoch,
		"group_receipt": map[string]any{
			"group_did":       gid,
			"group_event_seq": seq,
			"message_id":      messageID,
			"accepted_at":     acceptedAt,
		},
	}, nil
}

// groupE2EENotice handles group.e2ee.notice: the group host distributes a
// commit-delivery or welcome-delivery notice. The server validates the notice
// type and stores/forwards it as an acknowledgment.
func (s *Server) groupE2EENotice(params map[string]any) (any, error) {
	body := asMap(params["body"])
	if body == nil {
		return nil, &rpcError{code: codeInvalidParams, msg: "body is required"}
	}
	noticeType, err := requiredBodyString(body, "notice_type")
	if err != nil {
		return nil, err
	}
	if noticeType != "commit-delivery" && noticeType != "welcome-delivery" {
		return nil, &rpcError{code: codeE2EENoticeUnsupported, msg: "group.e2ee.notice_type_unsupported"}
	}
	// Presence-check the conditionally-required opaque fields.
	if noticeType == "commit-delivery" {
		if _, err := requiredBodyString(body, "commit_b64u"); err != nil {
			return nil, err
		}
	} else {
		if _, err := requiredBodyString(body, "welcome_b64u"); err != nil {
			return nil, err
		}
		if _, err := requiredBodyString(body, "ratchet_tree_b64u"); err != nil {
			return nil, err
		}
	}
	// The notice is stored as an inbound message for the target agent so it can
	// be retrieved via msg.inbox.
	meta := asMap(params["meta"])
	target := asMap(meta["target"])
	targetDID, _ := target["did"].(string)
	senderDID, _ := meta["sender_did"].(string)
	groupDID, _ := body["group_did"].(string)
	metaRaw, _ := json.Marshal(meta)
	bodyRaw, _ := json.Marshal(body)
	acceptedAt := time.Now().UTC().Format(time.RFC3339)
	if targetDID != "" {
		noticeID := fmt.Sprintf("notice-%d", time.Now().UTC().UnixNano())
		_, _ = s.db.Exec(`INSERT INTO messages (message_id, sender_did, recipient_did, group_did, type, text, secure, sent_at, wire_meta, wire_body) VALUES (?,?,?,?,?,?,0,?,?,?)`,
			noticeID, senderDID, targetDID, groupDID, "notice", "", acceptedAt, string(metaRaw), string(bodyRaw))
	}
	return map[string]any{"accepted": true}, nil
}
