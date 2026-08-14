package server

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// group.go implements the ANP group base semantics (profile
// "anp.group.base.v1", security_profile "transport-protected"). Groups are
// SQLite-persistent; group_state_version increments on every member/profile/
// policy mutation, group_event_seq increments on every accepted group message.

// newGroupDID synthesizes a unique group DID. The server is the authority for
// group identity, so this is a local, non-resolvable identifier.
func newGroupDID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "did:anp:group:" + hex.EncodeToString(b[:])
}

// groupDIDFromParams extracts the group DID from either body.group_did or
// meta.target.did, covering both wire shapes used across group methods.
func groupDIDFromParams(params map[string]any) string {
	if body := asMap(params["body"]); body != nil {
		if gid, _ := body["group_did"].(string); gid != "" {
			return gid
		}
	}
	if meta := asMap(params["meta"]); meta != nil {
		if target := asMap(meta["target"]); target != nil {
			if gid, _ := target["did"].(string); gid != "" {
				return gid
			}
		}
	}
	return ""
}

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// groupRow is the persisted group record (policy/profile stored as JSON text).
type groupRow struct {
	groupDID          string
	groupPolicy       string
	groupProfile      sql.NullString
	ownerDID          string
	groupStateVersion int64
	groupEventSeq     int64
	createdAt         string
}

func (s *Server) loadGroup(gid string) (*groupRow, error) {
	var r groupRow
	err := s.db.QueryRow(`SELECT group_did, group_policy, group_profile, owner_did, group_state_version, group_event_seq, created_at FROM groups WHERE group_did = ?`, gid).
		Scan(&r.groupDID, &r.groupPolicy, &r.groupProfile, &r.ownerDID, &r.groupStateVersion, &r.groupEventSeq, &r.createdAt)
	if err == sql.ErrNoRows {
		return nil, &rpcError{code: codeDidNotFound, msg: "group not found"}
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// groupStateVersion returns the current group_state_version without mutating it.
func (s *Server) groupStateVersion(gid string) (int64, error) {
	var v int64
	if err := s.db.QueryRow(`SELECT group_state_version FROM groups WHERE group_did = ?`, gid).Scan(&v); err != nil {
		if err == sql.ErrNoRows {
			return 0, &rpcError{code: codeDidNotFound, msg: "group not found"}
		}
		return 0, err
	}
	return v, nil
}

// bumpGroupStateVersion increments group_state_version by one and returns the
// new value (every member/profile/policy mutation bumps the version).
func (s *Server) bumpGroupStateVersion(gid string) (int64, error) {
	if _, err := s.db.Exec(`UPDATE groups SET group_state_version = group_state_version + 1 WHERE group_did = ?`, gid); err != nil {
		return 0, err
	}
	return s.groupStateVersion(gid)
}

// nextGroupEventSeq increments group_event_seq by one and returns the new value
// (every accepted group message consumes a sequence number).
func (s *Server) nextGroupEventSeq(gid string) (int64, error) {
	if _, err := s.db.Exec(`UPDATE groups SET group_event_seq = group_event_seq + 1 WHERE group_did = ?`, gid); err != nil {
		return 0, err
	}
	var v int64
	if err := s.db.QueryRow(`SELECT group_event_seq FROM groups WHERE group_did = ?`, gid).Scan(&v); err != nil {
		return 0, err
	}
	return v, nil
}

// groupMemberRole returns the caller's role ("owner"/"admin"/"member"/"") for a
// group, considering only active memberships.
func (s *Server) groupMemberRole(gid, did string) string {
	var role string
	if err := s.db.QueryRow(`SELECT role FROM group_members WHERE group_did = ? AND member_did = ? AND status = 'active'`, gid, did).Scan(&role); err != nil {
		return ""
	}
	return role
}

func (s *Server) isGroupMember(gid, did string) bool {
	return s.groupMemberRole(gid, did) != ""
}

// defaultRequiredRole maps a policy permission action to its fallback required
// role when the group policy does not override it.
func defaultRequiredRole(action string) string {
	switch action {
	case "update_policy":
		return "owner"
	case "add", "remove", "update_profile":
		return "admin"
	default: // send, etc.
		return "member"
	}
}

// groupPermitted reports whether did may perform action in group gid, honoring
// the group policy's permissions map (owners are always permitted).
func (s *Server) groupPermitted(gid, did, action string) bool {
	role := s.groupMemberRole(gid, did)
	if role == "owner" {
		return true
	}
	if role == "" {
		return false
	}
	required := defaultRequiredRole(action)
	if r, err := s.loadGroup(gid); err == nil {
		var policy map[string]any
		if json.Unmarshal([]byte(r.groupPolicy), &policy) == nil {
			if perms := asMap(policy["permissions"]); perms != nil {
				if v, _ := perms[action].(string); v != "" {
					required = v
				}
			}
		}
	}
	switch required {
	case "owner":
		return role == "owner"
	case "admin":
		return role == "admin" || role == "owner"
	default:
		return role != ""
	}
}

// addGroupMember inserts or updates a member with an explicit role, defaulting
// to "member".
func (s *Server) addGroupMember(gid, did, role string) error {
	if role == "" {
		role = "member"
	}
	_, err := s.db.Exec(`INSERT INTO group_members (group_did, member_did, role, status, joined_at) VALUES (?,?,?,?,?)
		ON CONFLICT(group_did, member_did) DO UPDATE SET role=excluded.role, status='active'`,
		gid, did, role, "active", time.Now().UTC().Format(time.RFC3339))
	return err
}

// joinGroupMember reactivates an existing membership without changing its role
// (a caller joining a group they already belong to must not be demoted).
func (s *Server) joinGroupMember(gid, did string) error {
	_, err := s.db.Exec(`INSERT INTO group_members (group_did, member_did, role, status, joined_at) VALUES (?,?,'member','active',?)
		ON CONFLICT(group_did, member_did) DO UPDATE SET status='active'`,
		gid, did, time.Now().UTC().Format(time.RFC3339))
	return err
}

// resolveMemberDID resolves a member_did or member_handle to a DID. Handles are
// looked up in the local handles table; DIDs pass through unchanged.
func (s *Server) resolveMemberDID(v string) (string, bool) {
	if v == "" {
		return "", false
	}
	if !validHandle(v) {
		return v, true // not a handle → treat as a raw DID
	}
	var did string
	if err := s.db.QueryRow(`SELECT did FROM handles WHERE handle = ?`, v).Scan(&did); err == nil && did != "" {
		return did, true
	}
	return "", false
}

// groupMemberList returns the active members of a group as standard group_member
// objects.
func (s *Server) groupMemberList(gid string) []any {
	rows, err := s.db.Query(`SELECT member_did, role, status, joined_at FROM group_members WHERE group_did = ? AND status = 'active' ORDER BY member_did`, gid)
	if err != nil {
		return []any{}
	}
	defer rows.Close()
	members := []any{}
	for rows.Next() {
		var did, role, status, joinedAt string
		if rows.Scan(&did, &role, &status, &joinedAt) == nil {
			members = append(members, map[string]any{
				"agent_did": did, "role": role, "status": status, "joined_at": joinedAt,
			})
		}
	}
	return members
}

// groupCreate handles group.create: the creator becomes the group owner.
func (s *Server) groupCreate(authDID string, params map[string]any) (any, error) {
	meta := asMap(params["meta"])
	body := asMap(params["body"])
	groupPolicy := asMap(body["group_policy"])
	if groupPolicy == nil {
		return nil, &rpcError{code: codeInvalidParams, msg: "group_policy is required"}
	}
	creatorDID := authDID
	if creatorDID == "" {
		creatorDID, _ = meta["sender_did"].(string)
	}
	if creatorDID == "" {
		return nil, &rpcError{code: codeInvalidParams, msg: "creator_did is required"}
	}
	gid := newGroupDID()
	policyRaw, _ := json.Marshal(groupPolicy)
	var profileRaw []byte
	if gp := asMap(body["group_profile"]); gp != nil {
		profileRaw, _ = json.Marshal(gp)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.db.Exec(`INSERT INTO groups (group_did, group_policy, group_profile, owner_did, group_state_version, group_event_seq, created_at) VALUES (?,?,?,?,0,0,?)`,
		gid, string(policyRaw), string(profileRaw), creatorDID, now); err != nil {
		return nil, err
	}
	// The creator is always the owner member.
	if err := s.addGroupMember(gid, creatorDID, "owner"); err != nil {
		return nil, err
	}
	// initial_members (MAY): each entry carries member_did XOR member_handle.
	if raw, ok := body["initial_members"].([]any); ok {
		for _, entry := range raw {
			m := asMap(entry)
			did, _ := m["member_did"].(string)
			if handle, _ := m["member_handle"].(string); handle != "" {
				if resolved, ok := s.resolveMemberDID(handle); ok {
					did = resolved
				} else {
					continue // unresolvable handle is skipped
				}
			}
			if did == "" {
				continue
			}
			role, _ := m["role"].(string)
			if role == "" {
				role = "member"
			}
			_ = s.addGroupMember(gid, did, role)
		}
	}
	version, _ := s.groupStateVersion(gid)
	return map[string]any{
		"group_did":           gid,
		"group_state_version": version,
		"created_at":          now,
		"creator_did":         creatorDID,
		"group_profile":       asMap(body["group_profile"]),
		"group_policy":        groupPolicy,
	}, nil
}

// groupGetInfo handles group.get_info: read-only group metadata query.
func (s *Server) groupGetInfo(params map[string]any) (any, error) {
	gid := groupDIDFromParams(params)
	if gid == "" {
		return nil, &rpcError{code: codeInvalidParams, msg: "group_did is required"}
	}
	r, err := s.loadGroup(gid)
	if err != nil {
		return nil, err
	}
	body := asMap(params["body"])
	var profile any
	if r.groupProfile.Valid {
		_ = json.Unmarshal([]byte(r.groupProfile.String), &profile)
	}
	result := map[string]any{
		"group_did":           r.groupDID,
		"group_state_version": r.groupStateVersion,
		"group_profile":       profile,
	}
	if includePolicy, _ := body["include_policy"].(bool); includePolicy {
		var policy any
		_ = json.Unmarshal([]byte(r.groupPolicy), &policy)
		result["group_policy"] = policy
	}
	if includeMembers, _ := body["include_member_list"].(bool); includeMembers {
		members := s.groupMemberList(gid)
		result["member_list"] = members
		result["member_count"] = fmt.Sprintf("%d", len(members))
	}
	return result, nil
}

// groupJoin handles group.join: only available in open-join groups.
func (s *Server) groupJoin(authDID string, params map[string]any) (any, error) {
	gid := groupDIDFromParams(params)
	if gid == "" {
		return nil, &rpcError{code: codeInvalidParams, msg: "group_did is required"}
	}
	memberDID := authDID
	if memberDID == "" {
		memberDID, _ = asMap(params["meta"])["sender_did"].(string)
	}
	r, err := s.loadGroup(gid)
	if err != nil {
		return nil, err
	}
	var policy map[string]any
	_ = json.Unmarshal([]byte(r.groupPolicy), &policy)
	if admission, _ := policy["admission_mode"].(string); admission != "" && admission != "open-join" {
		return nil, fmt.Errorf("group %q is not open-join", gid)
	}
	// Idempotent: an already-active member re-joining is a no-op that does not
	// bump the state version.
	if s.isGroupMember(gid, memberDID) {
		version, err := s.groupStateVersion(gid)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"group_did":           gid,
			"member_did":          memberDID,
			"membership_status":   "active",
			"group_state_version": version,
		}, nil
	}
	if err := s.joinGroupMember(gid, memberDID); err != nil {
		return nil, err
	}
	version, err := s.bumpGroupStateVersion(gid)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"group_did":           gid,
		"member_did":          memberDID,
		"membership_status":   "active",
		"group_state_version": version,
	}, nil
}

// groupAdd handles group.add: admin adds a member (by DID or handle).
func (s *Server) groupAdd(authDID string, params map[string]any) (any, error) {
	gid := groupDIDFromParams(params)
	if gid == "" {
		return nil, &rpcError{code: codeInvalidParams, msg: "group_did is required"}
	}
	if !s.groupPermitted(gid, authDID, "add") {
		return nil, fmt.Errorf("caller lacks add permission for group %q", gid)
	}
	body := asMap(params["body"])
	memberDID, _ := body["member_did"].(string)
	memberHandle, _ := body["member_handle"].(string)
	if memberDID == "" && memberHandle == "" {
		return nil, &rpcError{code: codeInvalidParams, msg: "member_did or member_handle is required"}
	}
	if memberHandle != "" {
		resolved, ok := s.resolveMemberDID(memberHandle)
		if !ok {
			return nil, fmt.Errorf("member_handle %q could not be resolved", memberHandle)
		}
		memberDID = resolved
	}
	role, _ := body["role"].(string)
	if err := s.addGroupMember(gid, memberDID, role); err != nil {
		return nil, err
	}
	version, err := s.bumpGroupStateVersion(gid)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"group_did":           gid,
		"member_did":          memberDID,
		"membership_status":   "active",
		"group_state_version": version,
	}, nil
}

// groupRemove handles group.remove: admin removes a member.
func (s *Server) groupRemove(authDID string, params map[string]any) (any, error) {
	gid := groupDIDFromParams(params)
	if gid == "" {
		return nil, &rpcError{code: codeInvalidParams, msg: "group_did is required"}
	}
	body := asMap(params["body"])
	memberDID, _ := body["member_did"].(string)
	if memberDID == "" {
		return nil, &rpcError{code: codeInvalidParams, msg: "member_did is required"}
	}
	if !s.groupPermitted(gid, authDID, "remove") {
		return nil, fmt.Errorf("caller lacks remove permission for group %q", gid)
	}
	if memberDID == s.ownerDID(gid) {
		return nil, fmt.Errorf("cannot remove the group owner")
	}
	if _, err := s.db.Exec(`DELETE FROM group_members WHERE group_did = ? AND member_did = ?`, gid, memberDID); err != nil {
		return nil, err
	}
	version, err := s.bumpGroupStateVersion(gid)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"group_did":           gid,
		"member_did":          memberDID,
		"group_state_version": version,
	}, nil
}

// groupLeave handles group.leave: the caller removes themself.
func (s *Server) groupLeave(authDID string, params map[string]any) (any, error) {
	gid := groupDIDFromParams(params)
	if gid == "" {
		return nil, &rpcError{code: codeInvalidParams, msg: "group_did is required"}
	}
	leaverDID := authDID
	if leaverDID == "" {
		leaverDID, _ = asMap(params["meta"])["sender_did"].(string)
	}
	if _, err := s.db.Exec(`DELETE FROM group_members WHERE group_did = ? AND member_did = ?`, gid, leaverDID); err != nil {
		return nil, err
	}
	version, err := s.bumpGroupStateVersion(gid)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"group_did":           gid,
		"leaver_did":          leaverDID,
		"group_state_version": version,
	}, nil
}

// groupUpdateProfile handles group.update_profile: replace or merge the group
// profile, returning the resulting profile.
func (s *Server) groupUpdateProfile(authDID string, params map[string]any) (any, error) {
	gid := groupDIDFromParams(params)
	if gid == "" {
		return nil, &rpcError{code: codeInvalidParams, msg: "group_did is required"}
	}
	if !s.groupPermitted(gid, authDID, "update_profile") {
		return nil, fmt.Errorf("caller lacks update_profile permission for group %q", gid)
	}
	body := asMap(params["body"])
	var profile map[string]any
	if patch := asMap(body["group_profile_patch"]); patch != nil {
		// RFC 7386 merge patch over the stored profile (shallow merge).
		r, err := s.loadGroup(gid)
		if err != nil {
			return nil, err
		}
		profile = map[string]any{}
		if r.groupProfile.Valid {
			_ = json.Unmarshal([]byte(r.groupProfile.String), &profile)
		}
		for k, v := range patch {
			if v == nil {
				delete(profile, k)
			} else {
				profile[k] = v
			}
		}
	} else if p := asMap(body["group_profile"]); p != nil {
		profile = p
	}
	if profile == nil {
		return nil, &rpcError{code: codeInvalidParams, msg: "group_profile is required"}
	}
	profileRaw, _ := json.Marshal(profile)
	if _, err := s.db.Exec(`UPDATE groups SET group_profile = ? WHERE group_did = ?`, string(profileRaw), gid); err != nil {
		return nil, err
	}
	version, err := s.bumpGroupStateVersion(gid)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"group_did":           gid,
		"group_state_version": version,
		"group_profile":       profile,
	}, nil
}

// groupUpdatePolicy handles group.update_policy: replace or merge the group
// policy, returning the resulting policy.
func (s *Server) groupUpdatePolicy(authDID string, params map[string]any) (any, error) {
	gid := groupDIDFromParams(params)
	if gid == "" {
		return nil, &rpcError{code: codeInvalidParams, msg: "group_did is required"}
	}
	if !s.groupPermitted(gid, authDID, "update_policy") {
		return nil, fmt.Errorf("caller lacks update_policy permission for group %q", gid)
	}
	body := asMap(params["body"])
	var policy map[string]any
	if patch := asMap(body["group_policy_patch"]); patch != nil {
		r, err := s.loadGroup(gid)
		if err != nil {
			return nil, err
		}
		policy = map[string]any{}
		_ = json.Unmarshal([]byte(r.groupPolicy), &policy)
		for k, v := range patch {
			if v == nil {
				delete(policy, k)
			} else {
				policy[k] = v
			}
		}
	} else if p := asMap(body["group_policy"]); p != nil {
		policy = p
	}
	if policy == nil {
		return nil, &rpcError{code: codeInvalidParams, msg: "group_policy is required"}
	}
	policyRaw, _ := json.Marshal(policy)
	if _, err := s.db.Exec(`UPDATE groups SET group_policy = ? WHERE group_did = ?`, string(policyRaw), gid); err != nil {
		return nil, err
	}
	version, err := s.bumpGroupStateVersion(gid)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"group_did":           gid,
		"group_state_version": version,
		"group_policy":        policy,
	}, nil
}

// groupSend handles group.send: persist a plaintext group message and bump the
// group event sequence.
func (s *Server) groupSend(authDID string, params map[string]any) (any, error) {
	meta := asMap(params["meta"])
	body := asMap(params["body"])
	target := asMap(meta["target"])
	gid, _ := target["did"].(string)
	if gid == "" {
		gid = groupDIDFromParams(params)
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
	if contentType == "" {
		return nil, &rpcError{code: codeInvalidParams, msg: "content_type is required"}
	}
	senderDID := authDID
	if senderDID == "" {
		senderDID, _ = meta["sender_did"].(string)
	}
	if !s.isGroupMember(gid, senderDID) {
		return nil, fmt.Errorf("sender %q is not a member of group %q", senderDID, gid)
	}
	// body MUST carry exactly one of text / payload / payload_b64u.
	kind, text, ok := classifyPayload(body)
	if !ok {
		return nil, &rpcError{code: codeInvalidParams, msg: "body must contain exactly one of text, payload, or payload_b64u"}
	}
	// P9: light structural validation of mentions inside a json payload, then
	// pass through verbatim (see mentions.go).
	if kind == "json" {
		if err := validateMentions(asMap(body["payload"])); err != nil {
			return nil, &rpcError{code: codeInvalidParams, msg: err.Error()}
		}
	}
	if auth, ok := params["auth"].(map[string]any); ok {
		if err := s.verifyOriginProof(senderDID, "group.send", meta, body, auth); err != nil {
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
	acceptedAt := time.Now().UTC().Format(time.RFC3339)
	if _, err := s.db.Exec(`INSERT INTO messages (message_id, sender_did, recipient_did, group_did, type, text, secure, sent_at, wire_meta, wire_body) VALUES (?,?,NULL,?,?,?,0,?,?,?)`,
		messageID, senderDID, gid, kind, text, acceptedAt, string(metaRaw), string(bodyRaw)); err != nil {
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
	}, nil
}

// groupIncoming handles the OPTIONAL group.incoming push notification. Real
// delivery requires a WebSocket/long-connection transport, out of scope here;
// the server accepts the notification and returns a placeholder ACK.
func (s *Server) groupIncoming(params map[string]any) (any, error) {
	return map[string]any{"accepted": true}, nil
}

// groupStateChanged handles the OPTIONAL group.state_changed push notification
// (placeholder; see groupIncoming).
func (s *Server) groupStateChanged(params map[string]any) (any, error) {
	return map[string]any{"accepted": true}, nil
}

// groupRebindMember handles group.rebind_member: a member re-binds their
// membership to a new DID (credential rebound).
func (s *Server) groupRebindMember(authDID string, params map[string]any) (any, error) {
	body := asMap(params["body"])
	memberHandle, _ := body["member_handle"].(string)
	previousMemberDID, _ := body["previous_member_did"].(string)
	newMemberDID, _ := body["new_member_did"].(string)
	handleBindingGeneration, _ := body["handle_binding_generation"]
	if memberHandle == "" || previousMemberDID == "" || newMemberDID == "" {
		return nil, &rpcError{code: codeInvalidParams, msg: "member_handle, previous_member_did and new_member_did are required"}
	}
	gid := groupDIDFromParams(params)
	if gid == "" {
		// Locate the group by previous membership when target is omitted.
		rows, err := s.db.Query(`SELECT group_did FROM group_members WHERE member_did = ? AND status = 'active'`, previousMemberDID)
		if err != nil {
			return nil, err
		}
		var gids []string
		for rows.Next() {
			var g string
			if rows.Scan(&g) == nil {
				gids = append(gids, g)
			}
		}
		rows.Close()
		if len(gids) != 1 {
			return nil, fmt.Errorf("cannot determine target group for member %q", previousMemberDID)
		}
		gid = gids[0]
	}
	// The caller (or meta.sender_did) must be the new DID proving the rebound.
	if authDID != "" && authDID != newMemberDID {
		return nil, fmt.Errorf("caller %q does not match new_member_did %q", authDID, newMemberDID)
	}
	var existing string
	if err := s.db.QueryRow(`SELECT member_did FROM group_members WHERE group_did = ? AND member_did = ?`, gid, previousMemberDID).Scan(&existing); err != nil {
		return nil, fmt.Errorf("previous member %q not found in group", previousMemberDID)
	}
	if _, err := s.db.Exec(`UPDATE group_members SET member_did = ? WHERE group_did = ? AND member_did = ?`, newMemberDID, gid, previousMemberDID); err != nil {
		return nil, err
	}
	version, err := s.bumpGroupStateVersion(gid)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"group_did":                 gid,
		"member_handle":             memberHandle,
		"previous_member_did":       previousMemberDID,
		"member_did":                newMemberDID,
		"handle_binding_generation": handleBindingGeneration,
		"membership_status":         "active",
		"group_state_version":       version,
	}, nil
}

// ownerDID returns the owner of a group, or "" if the group does not exist.
func (s *Server) ownerDID(gid string) string {
	var owner string
	_ = s.db.QueryRow(`SELECT owner_did FROM groups WHERE group_did = ?`, gid).Scan(&owner)
	return owner
}

// classifyPayload validates the direct/group message body mutual-exclusion rule
// (exactly one of text / payload / payload_b64u) and returns the content kind
// and, for text, the text itself.
func classifyPayload(body map[string]any) (kind, text string, ok bool) {
	count := 0
	if v, _ := body["text"].(string); v != "" {
		count++
		kind, text = "text", v
	}
	if _, present := body["payload"]; present {
		count++
		kind = "json"
	}
	if v, _ := body["payload_b64u"].(string); v != "" {
		count++
		kind = "binary"
	}
	return kind, text, count == 1
}
