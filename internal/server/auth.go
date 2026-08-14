package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	anpauth "github.com/agent-network-protocol/anp/golang/authentication"
)

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
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	requestURL := scheme + "://" + r.Host + r.URL.Path

	// Locate the DID via the keyid in Signature-Input instead of brute-forcing
	// every registered document (which is O(n) and ambiguous when keyids differ).
	keyID := extractKeyID(signatureInput)
	did := keyIDToDID(keyID)
	if did == "" {
		return "", fmt.Errorf("signature keyid not found")
	}
	var docJSON string
	if err := s.db.QueryRow(`SELECT doc_json FROM registered_dids WHERE did = ?`, did).Scan(&docJSON); err != nil {
		return "", fmt.Errorf("signature verification failed")
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(docJSON), &doc); err != nil {
		return "", fmt.Errorf("internal error")
	}
	meta, err := anpauth.VerifyHTTPMessageSignature(doc, http.MethodPost, requestURL, headers, body)
	if err != nil {
		return "", fmt.Errorf("signature verification failed")
	}
	return keyIDToDID(meta.KeyID), nil
}

func keyIDToDID(keyID string) string {
	idx := strings.LastIndex(keyID, "#")
	if idx >= 0 {
		return keyID[:idx]
	}
	return keyID
}

// extractKeyID pulls the keyid parameter out of a Signature-Input header so the
// server can locate the signer's DID document in O(1) instead of trying every
// registered document. The keyid value looks like did:wba:...#key-1 and may be
// quoted per RFC 9421.
func extractKeyID(signatureInput string) string {
	const marker = "keyid"
	idx := strings.Index(signatureInput, marker)
	if idx < 0 {
		return ""
	}
	rest := strings.TrimSpace(signatureInput[idx+len(marker):])
	if strings.HasPrefix(rest, "=") {
		rest = strings.TrimSpace(rest[1:])
	}
	if strings.HasPrefix(rest, `"`) {
		rest = rest[1:]
		if end := strings.Index(rest, `"`); end >= 0 {
			return rest[:end]
		}
	}
	if semi := strings.Index(rest, ";"); semi >= 0 {
		rest = rest[:semi]
	}
	return strings.TrimSpace(rest)
}

// verifyRegistration authenticates a did.register_document call. A brand-new
// DID may register unsigned (the bootstrap path); an already-registered DID
// must prove ownership by signing with its currently stored document. This
// lets new identities join after the first boot without opening the door to
// overwriting someone else's document.
func (s *Server) verifyRegistration(params map[string]any, r *http.Request, headers map[string]string, body []byte) (string, error) {
	did, _ := params["did"].(string)
	if did == "" {
		return "", fmt.Errorf("did is required")
	}
	var docJSON string
	err := s.db.QueryRow(`SELECT doc_json FROM registered_dids WHERE did = ?`, did).Scan(&docJSON)
	if err == sql.ErrNoRows {
		// New DID: allow unsigned registration (bootstrap).
		return did, nil
	}
	if err != nil {
		return "", fmt.Errorf("internal error")
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(docJSON), &doc); err != nil {
		return "", fmt.Errorf("internal error")
	}
	if headerGet(headers, "Signature-Input") == "" {
		return "", fmt.Errorf("missing Signature-Input header")
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	requestURL := scheme + "://" + r.Host + r.URL.Path
	meta, err := anpauth.VerifyHTTPMessageSignature(doc, http.MethodPost, requestURL, headers, body)
	if err != nil {
		return "", fmt.Errorf("signature verification failed")
	}
	if keyIDToDID(meta.KeyID) != did {
		return "", fmt.Errorf("signature does not match DID %q", did)
	}
	return did, nil
}
