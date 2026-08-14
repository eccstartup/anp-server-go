package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
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

// P6 group E2EE profile-specific error codes (spec §5000-5012).
const (
	codeE2EEKeyPackageNotFound = 5000
	codeE2EEInvalidKeyPackage  = 5001
	codeE2EEControllerRequired = 5003
	codeE2EEStateNotReady      = 5004
	codeE2EEEpochConflict      = 5005
	codeE2EENoticeUnsupported  = 5011
)

// P7 attachment profile-specific error codes (spec §6000-6013).
const (
	codeAttachmentSlotNotFound              = 6000
	codeAttachmentSlotExpired               = 6001
	codeAttachmentCommitTokenInvalid        = 6002
	codeAttachmentObjectTooLarge            = 6003
	codeAttachmentUnsupportedMime           = 6004
	codeAttachmentGrantNotFound             = 6005
	codeAttachmentUnauthorized              = 6006
	codeAttachmentTicketInvalid             = 6007
	codeAttachmentTicketBindingMismatch     = 6008
	codeAttachmentTicketExpired             = 6009
	codeAttachmentDigestMismatch            = 6010
	codeAttachmentDecryptFailed             = 6011
	codeAttachmentObjectUnavailable         = 6012
	codeAttachmentEncryptionPolicyViolation = 6013
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

	// Derive the public base URL from the request so data-plane URIs (attachment
	// upload_uri / object_uri) are absolute regardless of how the server is
	// deployed — srv.Start() and main.go's manual http.Server both work.
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	baseURL := scheme + "://" + r.Host

	s.mu.Lock()
	defer s.mu.Unlock()
	result, err := s.dispatchIdempotent(req.Method, req.Params, authDID, baseURL)
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

// dispatch routes a JSON-RPC method to its handler. baseURL is the request's
// public base URL (derived from the Host header) and is used by the attachment
// data-plane methods to emit absolute URIs.
func (s *Server) dispatch(method string, params map[string]any, authDID, baseURL string) (any, error) {
	switch method {
	case "msg.inbox":
		return s.msgInbox(authDID, params)
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
	case "direct.incoming":
		return s.directIncoming(params)
	case "group.create":
		return s.groupCreate(authDID, params)
	case "group.get_info":
		return s.groupGetInfo(params)
	case "group.join":
		return s.groupJoin(authDID, params)
	case "group.add":
		return s.groupAdd(authDID, params)
	case "group.remove":
		return s.groupRemove(authDID, params)
	case "group.leave":
		return s.groupLeave(authDID, params)
	case "group.update_profile":
		return s.groupUpdateProfile(authDID, params)
	case "group.update_policy":
		return s.groupUpdatePolicy(authDID, params)
	case "group.send":
		return s.groupSend(authDID, params)
	case "group.incoming":
		return s.groupIncoming(params)
	case "group.state_changed":
		return s.groupStateChanged(params)
	case "group.rebind_member":
		return s.groupRebindMember(authDID, params)
	case "group.e2ee.publish_key_package":
		return s.groupE2EEPublishKeyPackage(authDID, params)
	case "group.e2ee.get_key_package":
		return s.groupE2EEGetKeyPackage(params)
	case "group.e2ee.create":
		return s.groupE2EECreate(authDID, params)
	case "group.e2ee.add":
		return s.groupE2EEAdd(authDID, params)
	case "group.e2ee.remove":
		return s.groupE2EERemove(authDID, params)
	case "group.e2ee.send":
		return s.groupE2EESend(authDID, params)
	case "group.e2ee.notice":
		return s.groupE2EENotice(params)
	case "attachment.create_slot":
		return s.attachmentCreateSlot(authDID, baseURL, params)
	case "attachment.commit_object":
		return s.attachmentCommitObject(authDID, params)
	case "attachment.abort_object":
		return s.attachmentAbortObject(authDID, params)
	case "attachment.get_download_ticket":
		return s.attachmentGetDownloadTicket(authDID, params)
	default:
		return nil, fmt.Errorf("unknown method %q", method)
	}
}

// operationIDFromParams extracts the idempotency operation_id from a request,
// checking meta.operation_id first and a top-level operation_id second.
func operationIDFromParams(params map[string]any) string {
	if meta := asMap(params["meta"]); meta != nil {
		if id, _ := meta["operation_id"].(string); id != "" {
			return id
		}
	}
	if id, _ := params["operation_id"].(string); id != "" {
		return id
	}
	return ""
}

// dispatchIdempotent wraps dispatch with operation_id-based deduplication (P8):
// a repeated request with the same (caller, method, operation_id) returns the
// cached successful response instead of re-executing.
func (s *Server) dispatchIdempotent(method string, params map[string]any, authDID, baseURL string) (any, error) {
	opID := operationIDFromParams(params)
	if opID == "" {
		return s.dispatch(method, params, authDID, baseURL)
	}
	key := authDID + "\x00" + method + "\x00" + opID
	var cached string
	if err := s.db.QueryRow(`SELECT response_json FROM idempotency WHERE key = ?`, key).Scan(&cached); err == nil {
		var out any
		if json.Unmarshal([]byte(cached), &out) == nil {
			return out, nil
		}
	}
	result, err := s.dispatch(method, params, authDID, baseURL)
	if err != nil {
		return nil, err
	}
	resultJSON, _ := json.Marshal(result)
	_, _ = s.db.Exec(`INSERT INTO idempotency (key, response_json, created_at) VALUES (?,?,?) ON CONFLICT(key) DO NOTHING`,
		key, string(resultJSON), time.Now().UTC().Format(time.RFC3339))
	return result, nil
}
