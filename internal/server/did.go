package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	anpauth "github.com/agent-network-protocol/anp/golang/authentication"
)

func (s *Server) didRegisterDocument(params map[string]any) (any, error) {
	did, _ := params["did"].(string)
	doc, _ := params["did_document"].(map[string]any)
	if did == "" || doc == nil {
		return nil, fmt.Errorf("did and did_document are required")
	}
	if docID, _ := doc["id"].(string); docID != "" && docID != did {
		return nil, fmt.Errorf("did_document.id %q does not match did %q", docID, did)
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
	// Handle → DID (local binding).
	did := target
	var boundDID string
	if err := s.db.QueryRow(`SELECT did FROM handles WHERE handle = ?`, target).Scan(&boundDID); err == nil && boundDID != "" {
		did = boundDID
	}
	// Local registered document first.
	var docJSON string
	if err := s.db.QueryRow(`SELECT doc_json FROM registered_dids WHERE did = ?`, did).Scan(&docJSON); err == nil {
		var doc map[string]any
		_ = json.Unmarshal([]byte(docJSON), &doc)
		return map[string]any{"did": did, "did_document": doc}, nil
	}
	// Remote resolution for did:wba / did:web (spec: .well-known/did.json).
	if strings.HasPrefix(did, "did:wba:") || strings.HasPrefix(did, "did:web:") {
		// SSRF guard: refuse to resolve DIDs whose domain is an IP literal,
		// loopback, private, link-local, or cloud-metadata address.
		if host := didHost(did); host != "" && isBlockedHost(host) {
			return nil, &rpcError{code: codeDidNotFound, msg: "did not found"}
		}
		doc, err := anpauth.ResolveDidDocument(context.Background(), did, false)
		if err != nil {
			return nil, &rpcError{code: codeDidNotFound, msg: "did not found"}
		}
		return map[string]any{"did": did, "did_document": doc}, nil
	}
	return nil, &rpcError{code: codeDidNotFound, msg: "did not found"}
}

// didHost extracts the hostname from a did:wba or did:web identifier for SSRF
// pre-checks. Returns "" if the DID is malformed or not a resolvable method.
func didHost(did string) string {
	parts := strings.SplitN(did, ":", 4)
	if len(parts) < 3 || parts[0] != "did" || (parts[1] != "wba" && parts[1] != "web") {
		return ""
	}
	domain, err := url.PathUnescape(parts[2])
	if err != nil {
		return ""
	}
	return domain
}

// isBlockedHost guards against SSRF in DID resolution: it must never fetch
// from IP literals, loopback, private, link-local, or cloud-metadata addresses.
func isBlockedHost(hostport string) bool {
	host := strings.ToLower(strings.TrimSpace(hostport))
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(host, ".")
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
	}
	return host == "localhost" || host == "metadata.google.internal"
}
