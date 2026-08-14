package server

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// attachment.go implements the ANP P7 attachments-and-object-transfer profile
// (profile "anp.attachment.v1"). The control plane is four JSON-RPC methods;
// the data plane is PUT /upload/{slot_id} and GET /objects/{object_id}. Object
// bytes are stored as SQLite BLOBs keyed by an opaque object_id.

// maxUploadBytes caps a single uploaded object (32 MiB).
const maxUploadBytes = 32 << 20

// slotTTL is how long an upload slot stays valid before it expires.
const slotTTL = time.Hour

// ticketTTL is how long a download ticket stays valid (spec: SHOULD NOT exceed
// 5 minutes).
const ticketTTL = 5 * time.Minute

// newRandomHex returns n bytes of crypto-random entropy as hex.
func newRandomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// sha256B64u returns the unpadded base64url SHA-256 digest of data, matching
// the spec's digest.value_b64u encoding.
func sha256B64u(data []byte) string {
	h := sha256.Sum256(data)
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// sizeToInt64 parses a size value that may arrive as a decimal string or a
// JSON number.
func sizeToInt64(v any) (int64, bool) {
	switch t := v.(type) {
	case string:
		n, err := strconv.ParseInt(t, 10, 64)
		return n, err == nil
	case float64:
		return int64(t), t >= 0
	case int64:
		return t, true
	case int:
		return int64(t), true
	default:
		return 0, false
	}
}

// joinURL resolves a data-plane path against a base URL; when the base URL is
// empty it returns the path unchanged (relative).
func joinURL(base, path string) string {
	if base == "" {
		return path
	}
	return base + path
}

type attachmentSlot struct {
	slotID               string
	attachmentID         string
	objectID             string
	objectURI            string
	commitToken          string
	status               string
	objectEncryptionMode string
	expectedSize         sql.NullString
	expectedDigest       sql.NullString
	expiresAt            string
	ownerDID             string
}

func (s *Server) loadAttachmentSlot(slotID string) (*attachmentSlot, error) {
	var a attachmentSlot
	err := s.db.QueryRow(`SELECT slot_id, attachment_id, object_id, object_uri, commit_token, status, object_encryption_mode, expected_size, expected_digest, expires_at, owner_did FROM attachment_slots WHERE slot_id = ?`, slotID).
		Scan(&a.slotID, &a.attachmentID, &a.objectID, &a.objectURI, &a.commitToken, &a.status, &a.objectEncryptionMode, &a.expectedSize, &a.expectedDigest, &a.expiresAt, &a.ownerDID)
	if err == sql.ErrNoRows {
		return nil, &rpcError{code: codeAttachmentSlotNotFound, msg: "anp.attachment.slot_not_found"}
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// attachmentCreateSlot handles attachment.create_slot: allocate an upload slot
// and return the URIs + commit token needed for the upload → commit flow.
// baseURL is the request's public base URL (from the Host header); when empty
// it falls back to the server's configured base URL.
func (s *Server) attachmentCreateSlot(authDID, baseURL string, params map[string]any) (any, error) {
	body := asMap(params["body"])
	if body == nil {
		return nil, &rpcError{code: codeInvalidParams, msg: "body is required"}
	}
	attachmentID, err := requiredBodyString(body, "attachment_id")
	if err != nil {
		return nil, err
	}
	secProfile, err := requiredBodyString(body, "intended_message_security_profile")
	if err != nil {
		return nil, err
	}
	switch secProfile {
	case "transport-protected", "direct-e2ee", "group-e2ee":
	default:
		return nil, &rpcError{code: codeAttachmentEncryptionPolicyViolation, msg: "anp.attachment.encryption_policy_violation"}
	}
	mode, err := requiredBodyString(body, "object_encryption_mode")
	if err != nil {
		return nil, err
	}
	if mode != "none" && mode != "object-e2ee" {
		return nil, &rpcError{code: codeAttachmentEncryptionPolicyViolation, msg: "anp.attachment.encryption_policy_violation"}
	}

	slotID := newRandomHex(16)
	objectID := newRandomHex(16)
	commitToken := newRandomHex(24)
	now := time.Now().UTC()
	expiresAt := now.Add(slotTTL).Format(time.RFC3339)

	var expectedDigest string
	if d, ok := body["expected_digest"].(map[string]any); ok && d != nil {
		if b, err := json.Marshal(d); err == nil {
			expectedDigest = string(b)
		}
	}
	effBase := baseURL
	if effBase == "" {
		effBase = s.baseURL
	}
	uploadURI := joinURL(effBase, "/upload/"+slotID)
	objectURI := joinURL(effBase, "/objects/"+objectID)

	if _, err := s.db.Exec(`INSERT INTO attachment_slots (slot_id, attachment_id, object_id, upload_uri, object_uri, commit_token, status, object_encryption_mode, expected_size, mime_type, filename, expected_digest, expires_at, created_at, owner_did) VALUES (?,?,?,?,?,?,'created',?,?,?,?,?,?,?,?)`,
		slotID, attachmentID, objectID, uploadURI, objectURI, commitToken, mode,
		body["expected_size"], body["mime_type"], body["filename"], expectedDigest,
		expiresAt, now.Format(time.RFC3339), authDID); err != nil {
		return nil, err
	}
	result := map[string]any{
		"attachment_id": attachmentID,
		"slot_id":       slotID,
		"upload_uri":    uploadURI,
		"object_uri":    objectURI,
		"commit_token":  commitToken,
		"expires_at":    expiresAt,
	}
	if headers, ok := body["upload_headers"].(map[string]any); ok {
		result["upload_headers"] = headers
	}
	return result, nil
}

// attachmentCommitObject handles attachment.commit_object: finalize an uploaded
// object after verifying the commit token and digest.
func (s *Server) attachmentCommitObject(authDID string, params map[string]any) (any, error) {
	body := asMap(params["body"])
	if body == nil {
		return nil, &rpcError{code: codeInvalidParams, msg: "body is required"}
	}
	attachmentID, err := requiredBodyString(body, "attachment_id")
	if err != nil {
		return nil, err
	}
	slotID, err := requiredBodyString(body, "slot_id")
	if err != nil {
		return nil, err
	}
	commitToken, err := requiredBodyString(body, "commit_token")
	if err != nil {
		return nil, err
	}
	slot, err := s.loadAttachmentSlot(slotID)
	if err != nil {
		return nil, err
	}
	if slot.attachmentID != attachmentID {
		return nil, &rpcError{code: codeAttachmentSlotNotFound, msg: "anp.attachment.slot_not_found"}
	}
	if slot.commitToken != commitToken {
		return nil, &rpcError{code: codeAttachmentCommitTokenInvalid, msg: "anp.attachment.commit_token_invalid"}
	}
	if slot.status != "created" {
		return nil, &rpcError{code: codeAttachmentObjectUnavailable, msg: "anp.attachment.object_unavailable"}
	}
	if t, err := time.Parse(time.RFC3339, slot.expiresAt); err == nil && time.Now().UTC().After(t) {
		return nil, &rpcError{code: codeAttachmentSlotExpired, msg: "anp.attachment.slot_expired"}
	}
	// The object must already be uploaded via PUT /upload/{slot_id}.
	obj, err := s.loadAttachmentObject(slot.objectID)
	if err != nil {
		return nil, &rpcError{code: codeAttachmentObjectUnavailable, msg: "anp.attachment.object_unavailable"}
	}
	// Verify the declared size matches the actually uploaded bytes.
	if declared, ok := sizeToInt64(body["size"]); ok && declared != obj.size {
		return nil, &rpcError{code: codeAttachmentDigestMismatch, msg: "anp.attachment.digest_mismatch"}
	}
	// Verify the digest (sha-256) against the uploaded bytes when provided.
	if d, ok := body["digest"].(map[string]any); ok && d != nil {
		alg, _ := d["alg"].(string)
		valueB64u, _ := d["value_b64u"].(string)
		if alg != "" && alg != "sha-256" {
			return nil, &rpcError{code: codeAttachmentDigestMismatch, msg: "anp.attachment.digest_mismatch"}
		}
		if valueB64u != "" && valueB64u != sha256B64u(obj.data) {
			return nil, &rpcError{code: codeAttachmentDigestMismatch, msg: "anp.attachment.digest_mismatch"}
		}
	}
	if _, err := s.db.Exec(`UPDATE attachment_slots SET status = 'committed', actual_size = ?, actual_digest = ? WHERE slot_id = ?`,
		obj.size, obj.digest, slotID); err != nil {
		return nil, err
	}
	return map[string]any{
		"committed":     true,
		"attachment_id": attachmentID,
		"object_uri":    slot.objectURI,
		"committed_at":  time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// attachmentAbortObject handles attachment.abort_object: discard an upload slot.
func (s *Server) attachmentAbortObject(authDID string, params map[string]any) (any, error) {
	body := asMap(params["body"])
	if body == nil {
		return nil, &rpcError{code: codeInvalidParams, msg: "body is required"}
	}
	attachmentID, err := requiredBodyString(body, "attachment_id")
	if err != nil {
		return nil, err
	}
	slotID, err := requiredBodyString(body, "slot_id")
	if err != nil {
		return nil, err
	}
	slot, err := s.loadAttachmentSlot(slotID)
	if err != nil {
		return nil, err
	}
	if slot.attachmentID != attachmentID {
		return nil, &rpcError{code: codeAttachmentSlotNotFound, msg: "anp.attachment.slot_not_found"}
	}
	if _, err := s.db.Exec(`UPDATE attachment_slots SET status = 'aborted' WHERE slot_id = ?`, slotID); err != nil {
		return nil, err
	}
	return map[string]any{
		"aborted":       true,
		"attachment_id": attachmentID,
		"aborted_at":    time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// attachmentGetDownloadTicket handles attachment.get_download_ticket: issue a
// time-limited bearer ticket bound to the requester + message + object.
func (s *Server) attachmentGetDownloadTicket(authDID string, params map[string]any) (any, error) {
	meta := asMap(params["meta"])
	body := asMap(params["body"])
	if body == nil {
		return nil, &rpcError{code: codeInvalidParams, msg: "body is required"}
	}
	attachmentID, err := requiredBodyString(body, "attachment_id")
	if err != nil {
		return nil, err
	}
	objectURI, err := requiredBodyString(body, "object_uri")
	if err != nil {
		return nil, err
	}
	requesterDID, err := requiredBodyString(body, "requester_did")
	if err != nil {
		return nil, err
	}
	// requester_did MUST equal meta.sender_did (and the authenticated caller).
	senderDID, _ := meta["sender_did"].(string)
	if senderDID != "" && requesterDID != senderDID {
		return nil, &rpcError{code: codeAttachmentUnauthorized, msg: "anp.attachment.unauthorized_requester"}
	}
	if authDID != "" && requesterDID != authDID {
		return nil, &rpcError{code: codeAttachmentUnauthorized, msg: "anp.attachment.unauthorized_requester"}
	}
	messageID, err := requiredBodyString(body, "message_id")
	if err != nil {
		return nil, err
	}
	secProfile, err := requiredBodyString(body, "message_security_profile")
	if err != nil {
		return nil, err
	}
	// The referenced object must be committed before a ticket can be issued.
	var slotID, status string
	if err := s.db.QueryRow(`SELECT slot_id, status FROM attachment_slots WHERE attachment_id = ? AND object_uri = ? ORDER BY created_at DESC LIMIT 1`, attachmentID, objectURI).Scan(&slotID, &status); err != nil {
		return nil, &rpcError{code: codeAttachmentGrantNotFound, msg: "anp.attachment.grant_not_found"}
	}
	if status != "committed" {
		return nil, &rpcError{code: codeAttachmentObjectUnavailable, msg: "anp.attachment.object_unavailable"}
	}

	ticket := newRandomHex(32)
	expiresAt := time.Now().UTC().Add(ticketTTL).Format(time.RFC3339)
	binding := map[string]any{
		"attachment_id":            attachmentID,
		"object_uri":               objectURI,
		"requester_did":            requesterDID,
		"message_id":               messageID,
		"message_security_profile": secProfile,
	}
	if v, _ := body["message_target_did"].(string); v != "" {
		binding["message_target_did"] = v
	}
	if v, _ := body["group_did"].(string); v != "" {
		binding["group_did"] = v
	}
	bindingRaw, _ := json.Marshal(binding)
	if _, err := s.db.Exec(`INSERT INTO attachment_tickets (ticket_b64u, binding_json, expires_at) VALUES (?,?,?)`,
		ticket, string(bindingRaw), expiresAt); err != nil {
		return nil, err
	}
	return map[string]any{
		"download_ticket_b64u": ticket,
		"expires_at":           expiresAt,
		"ticket_binding":       binding,
	}, nil
}

type attachmentObject struct {
	data   []byte
	size   int64
	digest string
}

func (s *Server) loadAttachmentObject(objectID string) (*attachmentObject, error) {
	var data []byte
	var size int64
	var digest sql.NullString
	if err := s.db.QueryRow(`SELECT data, size, digest FROM attachment_objects WHERE object_id = ?`, objectID).Scan(&data, &size, &digest); err != nil {
		return nil, err
	}
	return &attachmentObject{data: data, size: size, digest: digest.String}, nil
}

// writeDataError writes a data-plane error as a JSON body with an anp_code.
func writeDataError(w http.ResponseWriter, status int, anpCode string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": anpCode})
}

// handleUpload implements PUT /upload/{slot_id}: store uploaded object bytes.
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	slotID := r.PathValue("slot_id")
	slot, err := s.loadAttachmentSlot(slotID)
	if err != nil {
		writeDataError(w, http.StatusNotFound, "anp.attachment.slot_not_found")
		return
	}
	if slot.status != "created" {
		writeDataError(w, http.StatusConflict, "anp.attachment.object_unavailable")
		return
	}
	if t, err := time.Parse(time.RFC3339, slot.expiresAt); err == nil && time.Now().UTC().After(t) {
		writeDataError(w, http.StatusGone, "anp.attachment.slot_expired")
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, maxUploadBytes+1))
	if err != nil {
		writeDataError(w, http.StatusBadRequest, "anp.attachment.object_unavailable")
		return
	}
	if len(data) > maxUploadBytes {
		writeDataError(w, http.StatusRequestEntityTooLarge, "anp.attachment.object_too_large")
		return
	}
	if slot.expectedSize.Valid {
		if expected, ok := sizeToInt64(slot.expectedSize.String); ok && expected != int64(len(data)) {
			writeDataError(w, http.StatusRequestEntityTooLarge, "anp.attachment.object_too_large")
			return
		}
	}
	digest := sha256B64u(data)
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.db.Exec(`INSERT INTO attachment_objects (object_id, data, size, digest, created_at) VALUES (?,?,?,?,?)
		ON CONFLICT(object_id) DO UPDATE SET data=excluded.data, size=excluded.size, digest=excluded.digest, created_at=excluded.created_at`,
		slot.objectID, data, int64(len(data)), digest, now); err != nil {
		writeDataError(w, http.StatusInternalServerError, "anp.attachment.object_unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{"uploaded": true, "size": len(data)})
}

// handleDownload implements GET /objects/{object_id}: return object bytes after
// validating the bearer download ticket.
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	objectID := r.PathValue("object_id")
	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(authz, "Bearer ") {
		writeDataError(w, http.StatusUnauthorized, "anp.attachment.download_ticket_invalid")
		return
	}
	ticket := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
	var bindingJSON, expiresAt string
	if err := s.db.QueryRow(`SELECT binding_json, expires_at FROM attachment_tickets WHERE ticket_b64u = ?`, ticket).Scan(&bindingJSON, &expiresAt); err != nil {
		writeDataError(w, http.StatusUnauthorized, "anp.attachment.download_ticket_invalid")
		return
	}
	if t, err := time.Parse(time.RFC3339, expiresAt); err == nil && time.Now().UTC().After(t) {
		writeDataError(w, http.StatusUnauthorized, "anp.attachment.ticket_expired")
		return
	}
	var binding map[string]any
	if err := json.Unmarshal([]byte(bindingJSON), &binding); err != nil {
		writeDataError(w, http.StatusUnauthorized, "anp.attachment.download_ticket_invalid")
		return
	}
	// The ticket must be bound to this exact object.
	if uri, _ := binding["object_uri"].(string); uri == "" {
		writeDataError(w, http.StatusUnauthorized, "anp.attachment.download_ticket_invalid")
		return
	} else if !objectURIMatches(uri, objectID) {
		writeDataError(w, http.StatusForbidden, "anp.attachment.ticket_binding_mismatch")
		return
	}
	obj, err := s.loadAttachmentObject(objectID)
	if err != nil {
		writeDataError(w, http.StatusNotFound, "anp.attachment.object_unavailable")
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(obj.size, 10))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(obj.data)
}

// objectURIMatches reports whether an object_uri (which may be a full URL or a
// relative path) refers to the given object_id.
func objectURIMatches(uri, objectID string) bool {
	return uri == "/objects/"+objectID ||
		strings.HasSuffix(uri, "/objects/"+objectID) ||
		strings.HasSuffix(strings.TrimSuffix(uri, "/"), "/"+objectID)
}
