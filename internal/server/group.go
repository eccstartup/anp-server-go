package server

import (
	"fmt"
	"time"
)

func (s *Server) groupCreate(authDID string, params map[string]any) (any, error) {
	name, _ := params["name"].(string)
	gid := fmt.Sprintf("did:wba:%s:group:g%d", "server", time.Now().UnixNano())
	if _, err := s.db.Exec(`INSERT INTO groups (group_did, name, owner_did, created_at) VALUES (?,?,?,?)`,
		gid, name, authDID, time.Now().UTC().Format(time.RFC3339)); err != nil {
		return nil, err
	}
	// The creator is always a member.
	if _, err := s.db.Exec(`INSERT OR IGNORE INTO group_members (group_did, member_did) VALUES (?,?)`, gid, authDID); err != nil {
		return nil, err
	}
	if raw, ok := params["members"].([]any); ok {
		for _, m := range raw {
			if did, ok := m.(string); ok && did != "" {
				_, _ = s.db.Exec(`INSERT OR IGNORE INTO group_members (group_did, member_did) VALUES (?,?)`, gid, did)
			}
		}
	}
	return map[string]any{"group_did": gid, "name": name, "members": s.groupMemberList(gid)}, nil
}

func (s *Server) groupJoin(authDID string, params map[string]any) (any, error) {
	gid, _ := params["group"].(string)
	if gid == "" {
		return nil, fmt.Errorf("group is required")
	}
	var count int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM groups WHERE group_did = ?`, gid).Scan(&count)
	if count == 0 {
		return nil, fmt.Errorf("group not found")
	}
	if _, err := s.db.Exec(`INSERT OR IGNORE INTO group_members (group_did, member_did) VALUES (?,?)`, gid, authDID); err != nil {
		return nil, err
	}
	return map[string]any{"status": "joined"}, nil
}

func (s *Server) groupLeave(authDID string, params map[string]any) (any, error) {
	gid, _ := params["group"].(string)
	if gid == "" {
		return nil, fmt.Errorf("group is required")
	}
	// Remove the caller; the group persists for the remaining members, and is
	// deleted only when its last member leaves.
	if _, err := s.db.Exec(`DELETE FROM group_members WHERE group_did = ? AND member_did = ?`, gid, authDID); err != nil {
		return nil, err
	}
	var remaining int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM group_members WHERE group_did = ?`, gid).Scan(&remaining)
	if remaining == 0 {
		_, _ = s.db.Exec(`DELETE FROM groups WHERE group_did = ?`, gid)
	}
	return map[string]any{"status": "left"}, nil
}

func (s *Server) groupMembers(params map[string]any) (any, error) {
	gid, _ := params["group"].(string)
	if gid == "" {
		return nil, fmt.Errorf("group is required")
	}
	var count int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM groups WHERE group_did = ?`, gid).Scan(&count)
	if count == 0 {
		return nil, fmt.Errorf("group not found")
	}
	return map[string]any{"members": s.groupMemberList(gid)}, nil
}

func (s *Server) groupMemberList(gid string) []any {
	rows, err := s.db.Query(`SELECT member_did FROM group_members WHERE group_did = ? ORDER BY member_did`, gid)
	if err != nil {
		return []any{}
	}
	defer rows.Close()
	members := []any{}
	for rows.Next() {
		var did string
		if rows.Scan(&did) == nil && did != "" {
			members = append(members, did)
		}
	}
	return members
}

func (s *Server) isGroupMember(gid, did string) (bool, error) {
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM group_members WHERE group_did = ? AND member_did = ?`, gid, did).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}
