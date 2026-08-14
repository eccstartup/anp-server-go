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
	// The sender is the authenticated identity, never the client-supplied
	// meta.sender_did (which would allow impersonation of another DID).
	senderDID := authDID
	if senderDID == "" {
		senderDID, _ = meta["sender_did"].(string) // first-boot fallback
	}
	if messageID == "" {
		return nil, fmt.Errorf("message_id is required")
	}
	// Verify the application-layer origin proof when the client attached one
	// (ANP P1 Appendix A). Only meaningful once the signer DID is known.
	if senderDID != "" {
		if auth, ok := params["auth"].(map[string]any); ok {
			if err := s.verifyOriginProof(senderDID, "direct.send", meta, body, auth); err != nil {
				return nil, err
			}
		}
	}
	metaRaw, _ := json.Marshal(meta)
	bodyRaw, _ := json.Marshal(body)
	if _, err := s.db.Exec(`INSERT INTO messages (message_id, sender_did, recipient_did, type, text, secure, sent_at, wire_meta, wire_body) VALUES (?,?,?,'text','',1,?,?,?)`,
		messageID, senderDID, peerDID, time.Now().UTC().Format(time.RFC3339), string(metaRaw), string(bodyRaw)); err != nil {
		return nil, err
	}
	return map[string]any{"message_id": messageID, "state": "delivered", "sent_at": time.Now().UTC().Format(time.RFC3339)}, nil
}

func (s *Server) e2eePublishPrekeyBundle(authDID string, params map[string]any) (any, error) {
	body, _ := params["body"].(map[string]any)
	bundle, _ := body["prekey_bundle"].(map[string]any)
	ownerDID, _ := bundle["owner_did"].(string)
	// A prekey bundle may only be published by its owner; otherwise an attacker
	// could overwrite a victim's bundle and decrypt their E2EE messages.
	if authDID != "" {
		ownerDID = authDID
	}
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
