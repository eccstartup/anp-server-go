package server

import (
	"encoding/json"
	"fmt"
	"time"

	anpproof "github.com/agent-network-protocol/anp/golang/proof"
)

func (s *Server) directSend(authDID string, params map[string]any) (any, error) {
	meta, _ := params["meta"].(map[string]any)
	body, _ := params["body"].(map[string]any)
	target, _ := meta["target"].(map[string]any)
	peerDID, _ := target["did"].(string)
	messageID, _ := meta["message_id"].(string)
	operationID, _ := meta["operation_id"].(string)
	profile, _ := meta["profile"].(string)
	securityProfile, _ := meta["security_profile"].(string)
	// The sender is the authenticated identity, never the client-supplied
	// meta.sender_did (which would allow impersonation of another DID).
	senderDID := authDID
	if senderDID == "" {
		senderDID, _ = meta["sender_did"].(string) // first-boot fallback
	}
	if messageID == "" {
		return nil, fmt.Errorf("message_id is required")
	}
	// Plaintext base profile (anp.direct.base.v1 / transport-protected): the
	// body carries a plaintext payload (exactly one of text/payload/payload_b64u)
	// and an origin proof is mandatory (P3). Everything else is treated as an
	// E2EE envelope, which keeps the existing direct.e2ee behavior intact.
	plaintext := profile == "anp.direct.base.v1" && securityProfile == "transport-protected"
	secure := 1
	kind, text := "text", ""
	if plaintext {
		secure = 0
		var ok bool
		kind, text, ok = classifyPayload(body)
		if !ok {
			return nil, &rpcError{code: codeInvalidParams, msg: "body must contain exactly one of text, payload, or payload_b64u"}
		}
		// P3: an origin proof is REQUIRED for plaintext direct messages.
		auth, hasAuth := params["auth"].(map[string]any)
		if !hasAuth {
			return nil, fmt.Errorf("auth.origin_proof is required for anp.direct.base.v1")
		}
		if err := s.verifyOriginProof(senderDID, "direct.send", meta, body, auth); err != nil {
			return nil, err
		}
	} else {
		// E2EE envelope: verify the application-layer origin proof when the
		// client attached one (ANP P1 Appendix A). Only meaningful once the
		// signer DID is known.
		if senderDID != "" {
			if auth, ok := params["auth"].(map[string]any); ok {
				if err := s.verifyOriginProof(senderDID, "direct.send", meta, body, auth); err != nil {
					return nil, err
				}
			}
		}
	}
	metaRaw, _ := json.Marshal(meta)
	bodyRaw, _ := json.Marshal(body)
	acceptedAt := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.db.Exec(`INSERT INTO messages (message_id, sender_did, recipient_did, type, text, secure, sent_at, wire_meta, wire_body) VALUES (?,?,?,?,?,?,?,?,?)`,
		messageID, senderDID, peerDID, kind, text, secure, acceptedAt, string(metaRaw), string(bodyRaw)); err != nil {
		return nil, err
	}
	// Standard direct.send acknowledgment shape (shared by E2EE and plaintext).
	return map[string]any{
		"accepted":     true,
		"message_id":   messageID,
		"operation_id": operationID,
		"target_did":   peerDID,
		"accepted_at":  acceptedAt,
	}, nil
}

// directIncoming handles the OPTIONAL direct.incoming push notification. Real
// delivery requires a WebSocket/long-connection transport, out of scope here;
// the server accepts the notification and returns a placeholder ACK.
func (s *Server) directIncoming(params map[string]any) (any, error) {
	return map[string]any{"accepted": true}, nil
}

func (s *Server) e2eePublishPrekeyBundle(authDID string, params map[string]any) (any, error) {
	body, _ := params["body"].(map[string]any)
	bundle, _ := body["prekey_bundle"].(map[string]any)
	ownerDID, _ := bundle["owner_did"].(string)
	bundleID, _ := bundle["bundle_id"].(string)
	// A prekey bundle may only be published by its owner; otherwise an attacker
	// could overwrite a victim's bundle and decrypt their E2EE messages.
	if authDID != "" {
		ownerDID = authDID
	}
	if ownerDID == "" {
		return nil, fmt.Errorf("prekey_bundle.owner_did is required")
	}
	bundleRaw, _ := json.Marshal(bundle)
	publishedAt := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.db.Exec(`INSERT INTO prekey_bundles (owner_did, bundle_json, published_at) VALUES (?,?,?) ON CONFLICT(owner_did) DO UPDATE SET bundle_json=excluded.bundle_json, published_at=excluded.published_at`,
		ownerDID, string(bundleRaw), publishedAt); err != nil {
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
	// Standard anp.direct.e2ee.v1 publish acknowledgment shape.
	return map[string]any{
		"published":    true,
		"owner_did":    ownerDID,
		"bundle_id":    bundleID,
		"published_at": publishedAt,
	}, nil
}

func (s *Server) e2eeGetPrekeyBundle(params map[string]any) (any, error) {
	body, _ := params["body"].(map[string]any)
	targetDID, _ := body["target_did"].(string)
	requireOPK, _ := body["require_opk"].(bool)
	var bundleJSON string
	if err := s.db.QueryRow(`SELECT bundle_json FROM prekey_bundles WHERE owner_did = ? ORDER BY published_at DESC LIMIT 1`, targetDID).Scan(&bundleJSON); err != nil {
		return nil, &rpcError{code: codeDidNotFound, msg: "anp.direct.e2ee.bundle_not_found"}
	}
	var bundle map[string]any
	_ = json.Unmarshal([]byte(bundleJSON), &bundle)
	// Standard anp.direct.e2ee.v1 get-bundle response shape.
	result := map[string]any{"target_did": targetDID, "prekey_bundle": bundle}
	if requireOPK {
		var prekeyJSON string
		if err := s.db.QueryRow(`SELECT prekey_json FROM one_time_prekeys WHERE owner_did = ? ORDER BY rowid ASC LIMIT 1`, targetDID).Scan(&prekeyJSON); err == nil {
			var opk map[string]any
			json.Unmarshal([]byte(prekeyJSON), &opk)
			result["one_time_prekey"] = opk
			_, _ = s.db.Exec(`DELETE FROM one_time_prekeys WHERE owner_did = ? AND prekey_json = ?`, targetDID, prekeyJSON)
		} else {
			return nil, &rpcError{code: codeOPKUnavailable, msg: "anp.direct.e2ee.opk_unavailable"}
		}
	}
	return result, nil
}

// verifyOriginProof validates the application-layer origin proof attached to a
// message (P1 Appendix A), binding the sender DID to the message content.
func (s *Server) verifyOriginProof(senderDID, method string, meta, body map[string]any, auth map[string]any) error {
	opRaw, ok := auth["origin_proof"].(map[string]any)
	if !ok {
		return fmt.Errorf("auth.origin_proof is missing")
	}
	contentDigest, _ := opRaw["contentDigest"].(string)
	signatureInput, _ := opRaw["signatureInput"].(string)
	signature, _ := opRaw["signature"].(string)
	if contentDigest == "" || signatureInput == "" || signature == "" {
		return fmt.Errorf("auth.origin_proof fields are incomplete")
	}
	var docJSON string
	if err := s.db.QueryRow(`SELECT doc_json FROM registered_dids WHERE did = ?`, senderDID).Scan(&docJSON); err != nil {
		return fmt.Errorf("signer DID not registered")
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(docJSON), &doc); err != nil {
		return fmt.Errorf("internal error")
	}
	originProof := anpproof.RFC9421OriginProof{
		ContentDigest:  contentDigest,
		SignatureInput: signatureInput,
		Signature:      signature,
	}
	if _, err := anpproof.VerifyRFC9421OriginProof(originProof, method, meta, body, anpproof.RFC9421OriginProofVerificationOptions{DidDocument: doc, ExpectedSignerDID: senderDID}); err != nil {
		return fmt.Errorf("origin proof verification failed: %w", err)
	}
	return nil
}
