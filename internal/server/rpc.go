package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// maxBodyBytes caps the in-memory size of an inbound JSON-RPC body, so an
// oversized or malicious request cannot exhaust server memory.
const maxBodyBytes = 1 << 20 // 1 MiB

type rpcRequest struct {
	JSONRPC string         `json:"jsonrpc"`
	Method  string         `json:"method"`
	Params  map[string]any `json:"params"`
	ID      any            `json:"id"`
}

// Application-level JSON-RPC error codes (negative, in the -32000 range).
const (
	codeHandleTaken    = -32001
	codeDidNotFound    = -32002
	codeOPKUnavailable = -32003
	codeInvalidParams  = -32004
)

// rpcError carries an application-level JSON-RPC error code alongside its
// message so dispatch can surface protocol-specific codes instead of a
// blanket -32000.
type rpcError struct {
	code int
	msg  string
}

func (e *rpcError) Error() string { return e.msg }

func writeRPCResult(w http.ResponseWriter, id any, result any) {
	resp := map[string]any{"jsonrpc": "2.0", "id": id, "result": result}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func writeRPCError(w http.ResponseWriter, id any, code int, errMsg string) {
	resp := map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": errMsg}}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// handleRPC is the JSON-RPC 2.0 entry point: parse, authenticate, dispatch.
func (s *Server) handleRPC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeRPCError(w, nil, -32600, "method not allowed")
		return
	}

	// Bound the read: ignore the client-supplied Content-Length (which may be
	// -1 for chunked bodies) and cap at maxBodyBytes to avoid a huge or
	// negative allocation.
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		writeRPCError(w, nil, -32700, "read error")
		return
	}
	if len(body) > maxBodyBytes {
		writeRPCError(w, nil, -32600, "request too large")
		return
	}

	var req rpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeRPCError(w, nil, -32700, "parse error")
		return
	}

	headers := httpHeaders(r)

	// Authenticate. did.register_document is special: a NEW did may register
	// unsigned (that is the bootstrap path), while re-registering an EXISTING
	// did requires the owner's signature against the currently stored document.
	// Every other method uses the general signature check.
	var authDID string
	if req.Method == "did.register_document" {
		authDID, err = s.verifyRegistration(req.Params, r, headers, body)
	} else {
		authDID, err = s.verify(r, headers, body)
	}
	if err != nil {
		writeRPCError(w, req.ID, -32000, err.Error())
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.dispatch(req.Method, req.Params, authDID)
	if err != nil {
		code := -32000
		var rerr *rpcError
		if errors.As(err, &rerr) {
			code = rerr.code
		} else if strings.HasPrefix(err.Error(), "unknown method") {
			code = -32601
		}
		writeRPCError(w, req.ID, code, err.Error())
		return
	}
	writeRPCResult(w, req.ID, result)
}

// dispatch routes a JSON-RPC method to its handler.
func (s *Server) dispatch(method string, params map[string]any, authDID string) (any, error) {
	switch method {
	case "msg.send":
		return s.msgSend(authDID, params)
	case "msg.inbox":
		return s.msgInbox(authDID, params)
	case "msg.history":
		return s.msgHistory(authDID, params)
	case "group.create":
		return s.groupCreate(authDID, params)
	case "group.join":
		return s.groupJoin(authDID, params)
	case "group.leave":
		return s.groupLeave(authDID, params)
	case "group.members":
		return s.groupMembers(params)
	case "did.resolve":
		return s.didResolve(params)
	case "did.register_document":
		return s.didRegisterDocument(params)
	case "handle.register":
		return s.handleRegister(authDID, params)
	case "handle.recover":
		return s.handleRecover(authDID, params)
	case "direct.send":
		return s.directSend(authDID, params)
	case "direct.e2ee.publish_prekey_bundle":
		return s.e2eePublishPrekeyBundle(authDID, params)
	case "direct.e2ee.get_prekey_bundle":
		return s.e2eeGetPrekeyBundle(params)
	default:
		return nil, fmt.Errorf("unknown method %q", method)
	}
}
