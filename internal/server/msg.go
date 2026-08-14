package server

import (
	"database/sql"
	"encoding/json"
)

// msgInbox returns the authenticated caller's inbound messages — both direct
// envelopes addressed to the caller and group messages for groups they are an
// active member of. The response returns the standard {server_seq, meta, body}
// shape so the receiver can order and de-duplicate.
func (s *Server) msgInbox(authDID string, params map[string]any) (any, error) {
	limit := 100
	if v, ok := params["limit"].(float64); ok {
		if v >= 1 && v <= 1000 && v == v && v <= 1<<53 {
			limit = int(v)
		}
	}
	rows, err := s.db.Query(`SELECT id, wire_meta, wire_body FROM messages
		WHERE recipient_did = ?
		   OR group_did IN (SELECT group_did FROM group_members WHERE member_did = ? AND status = 'active')
		ORDER BY id DESC LIMIT ?`, authDID, authDID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	msgs := []map[string]any{}
	for rows.Next() {
		var id int64
		var metaStr, bodyStr sql.NullString
		if err := rows.Scan(&id, &metaStr, &bodyStr); err != nil {
			continue
		}
		if !metaStr.Valid || !bodyStr.Valid {
			continue
		}
		var meta, body any
		if err := json.Unmarshal([]byte(metaStr.String), &meta); err != nil {
			continue
		}
		if err := json.Unmarshal([]byte(bodyStr.String), &body); err != nil {
			continue
		}
		msgs = append(msgs, map[string]any{
			"server_seq": id,
			"meta":       meta,
			"body":       body,
		})
	}
	return map[string]any{"messages": msgs}, nil
}
