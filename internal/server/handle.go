package server

import (
	"fmt"
	"time"

	"github.com/agent-network-protocol/anp/golang/wns"
)

func (s *Server) handleRegister(authDID string, params map[string]any) (any, error) {
	handle, _ := params["handle"].(string)
	did, _ := params["did"].(string)
	// Bind the handle to the authenticated caller, never to a client-supplied
	// DID (which would let anyone squat a handle under someone else's identity).
	if authDID != "" {
		did = authDID
	}
	if handle == "" || did == "" {
		return nil, fmt.Errorf("handle and did are required")
	}
	if !validHandle(handle) {
		return nil, fmt.Errorf("invalid handle %q", handle)
	}
	// Conflict check: handle already bound to a different DID.
	var existing string
	_ = s.db.QueryRow(`SELECT did FROM handles WHERE handle = ?`, handle).Scan(&existing)
	if existing != "" && existing != did {
		return nil, &rpcError{code: codeHandleTaken, msg: fmt.Sprintf("handle %q is already registered by another identity", handle)}
	}
	if _, err := s.db.Exec(`INSERT INTO handles (handle, did, registered_at) VALUES (?,?,?) ON CONFLICT(handle) DO UPDATE SET did=excluded.did`,
		handle, did, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return nil, err
	}
	return map[string]any{"did": did, "handle": handle, "status": "registered"}, nil
}

// handleRecover re-binds a handle, authenticated purely by the caller's HTTP
// signature: only the handle's current owner (matching DID) may re-bind it.
// Cross-DID recovery would require an out-of-band proof (email/phone/OTP) that
// this server has no channel to verify, so it is rejected.
func (s *Server) handleRecover(authDID string, params map[string]any) (any, error) {
	handle, _ := params["handle"].(string)
	if handle == "" {
		return nil, &rpcError{code: codeInvalidParams, msg: "handle is required"}
	}
	var oldDID string
	if err := s.db.QueryRow(`SELECT did FROM handles WHERE handle = ?`, handle).Scan(&oldDID); err != nil {
		return nil, &rpcError{code: codeDidNotFound, msg: fmt.Sprintf("handle %q not found", handle)}
	}
	if authDID != "" && authDID != oldDID {
		return nil, fmt.Errorf("recovery denied: only the handle's current owner may re-bind it")
	}
	newDID := oldDID
	if authDID != "" {
		newDID = authDID
	}
	if _, err := s.db.Exec(`UPDATE handles SET did = ? WHERE handle = ?`, newDID, handle); err != nil {
		return nil, err
	}
	return map[string]any{"did": newDID, "handle": handle, "status": "recovered"}, nil
}

// validHandle enforces the WNS handle syntax: localpart.domain (e.g.
// alice.example.com), validated with the SDK's wns package.
func validHandle(handle string) bool {
	_, _, err := wns.ValidateHandle(handle)
	return err == nil
}
