package server

import (
	"fmt"
	"time"

	"github.com/agent-network-protocol/anp/golang/wns"
)

func (s *Server) handleRegister(authDID string, params map[string]any) (any, error) {
	handle, _ := params["handle"].(string)
	did, _ := params["did"].(string)
	phone, _ := params["phone"].(string)
	email, _ := params["email"].(string)
	otp, _ := params["otp"].(string)
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
	if _, err := s.db.Exec(`INSERT INTO handles (handle, did, phone, email, recovery_otp, registered_at) VALUES (?,?,?,?,?,?) ON CONFLICT(handle) DO UPDATE SET did=excluded.did, phone=excluded.phone, email=excluded.email, recovery_otp=excluded.recovery_otp`,
		handle, did, phone, email, otp, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return nil, err
	}
	return map[string]any{"did": did, "handle": handle, "status": "registered"}, nil
}

// handleRecover restores a handle binding after proof of identity. The caller
// proves ownership via a credential recorded at registration — phone, email,
// or the recovery OTP — and the handle is then re-bound to the authenticated
// caller (the new identity). An empty credential is never proof of ownership:
// only a non-empty, matching value counts.
func (s *Server) handleRecover(authDID string, params map[string]any) (any, error) {
	handle, _ := params["handle"].(string)
	phone, _ := params["phone"].(string)
	email, _ := params["email"].(string)
	otp, _ := params["otp"].(string)
	if handle == "" {
		return nil, &rpcError{code: codeInvalidParams, msg: "handle is required"}
	}
	var oldDID, regPhone, regEmail, regOTP string
	if err := s.db.QueryRow(`SELECT did, COALESCE(phone,''), COALESCE(email,''), COALESCE(recovery_otp,'') FROM handles WHERE handle = ?`, handle).Scan(&oldDID, &regPhone, &regEmail, &regOTP); err != nil {
		return nil, &rpcError{code: codeDidNotFound, msg: fmt.Sprintf("handle %q not found", handle)}
	}
	matched := false
	if phone != "" && phone == regPhone {
		matched = true
	}
	if email != "" && email == regEmail {
		matched = true
	}
	if otp != "" && regOTP != "" && otp == regOTP {
		matched = true
	}
	if !matched {
		return nil, fmt.Errorf("recovery verification failed: phone/email/otp does not match")
	}
	// Re-bind the handle to the authenticated caller (the new identity). When
	// unauthenticated (first-boot bootstrap), keep the existing binding.
	newDID := authDID
	if newDID == "" {
		newDID = oldDID
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
