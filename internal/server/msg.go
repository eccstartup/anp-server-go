package server

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

func (s *Server) msgSend(authDID string, params map[string]any) (any, error) {
	to, _ := params["to"].(string)
	group, _ := params["group"].(string)
	bodyMap, _ := params["body"].(map[string]any)
	secure, _ := params["secure"].(bool)
	if to == "" && group == "" {
		return nil, fmt.Errorf("either to or group is required")
	}
	if group != "" {
		member, err := s.isGroupMember(group, authDID)
		if err != nil {
			return nil, err
		}
		if !member {
			return nil, fmt.Errorf("not a member of group %q", group)
		}
	}
	text := ""
	if bodyMap != nil {
		text, _ = bodyMap["text"].(string)
	}
	s.nextMsg++
	msgID := fmt.Sprintf("msg_%d", s.nextMsg)
	sentAt := time.Now().UTC().Format(time.RFC3339)
	recipient := to
	if group != "" {
		recipient = ""
	}
	if _, err := s.db.Exec(`INSERT INTO messages (message_id, sender_did, recipient_did, group_did, type, text, secure, sent_at) VALUES (?,?,?,?,?,?,?,?)`,
		msgID, authDID, recipient, group, "text", text, boolToInt(secure), sentAt); err != nil {
		return nil, err
	}
	return map[string]any{"message_id": msgID, "thread_id": "thread_" + firstNonEmpty(to, group), "sent_at": sentAt, "state": "delivered"}, nil
}

func (s *Server) msgInbox(authDID string, params map[string]any) (any, error) {
	scope, _ := params["scope"].(string)
	limit := 100
	if v, ok := params["limit"].(float64); ok {
		if v >= 1 && v <= 1000 && v == v && v <= 1<<53 {
			limit = int(v)
		}
	}
	q := `SELECT message_id, sender_did, recipient_did, group_did, type, text, secure, sent_at, wire_meta, wire_body FROM messages WHERE `
	args := []any{}
	switch scope {
	case "direct":
		q += `recipient_did = ?`
		args = append(args, authDID)
	case "group":
		q += `group_did IN (SELECT group_did FROM group_members WHERE member_did = ?)`
		args = append(args, authDID)
	default: // "all"
		q += `(recipient_did = ? OR group_did IN (SELECT group_did FROM group_members WHERE member_did = ?))`
		args = append(args, authDID, authDID)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	msgs := []map[string]any{}
	for rows.Next() {
		var mid, sd, mtype, sentAt string
		var rd, gd, mtext sql.NullString
		var metaStr, bodyStr sql.NullString
		var secure int
		if err := rows.Scan(&mid, &sd, &rd, &gd, &mtype, &mtext, &secure, &sentAt, &metaStr, &bodyStr); err != nil {
			continue
		}
		entry := map[string]any{
			"message_id": mid, "sender_did": sd, "recipient_did": rd.String,
			"group_did": gd.String, "type": mtype, "text": mtext.String,
			"secure": secure != 0, "sent_at": sentAt,
		}
		if metaStr.Valid && bodyStr.Valid {
			var meta, body any
			_ = json.Unmarshal([]byte(metaStr.String), &meta)
			_ = json.Unmarshal([]byte(bodyStr.String), &body)
			entry["meta"] = meta
			entry["body"] = body
		}
		msgs = append(msgs, entry)
	}
	return map[string]any{"messages": msgs}, nil
}

func (s *Server) msgHistory(authDID string, params map[string]any) (any, error) {
	peer, _ := params["with"].(string)
	limit := 50
	if v, ok := params["limit"].(float64); ok {
		if v >= 1 && v <= 1000 && v == v && v <= 1<<53 {
			limit = int(v)
		}
	}
	rows, err := s.db.Query(`SELECT message_id, sender_did, recipient_did, group_did, type, text, secure, sent_at FROM messages WHERE (sender_did = ? AND recipient_did = ?) OR (sender_did = ? AND recipient_did = ?) ORDER BY id DESC LIMIT ?`, authDID, peer, peer, authDID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	msgs := []map[string]any{}
	for rows.Next() {
		var mid, sd, mtype, sentAt string
		var rd, gd, mtext sql.NullString
		var secure int
		if err := rows.Scan(&mid, &sd, &rd, &gd, &mtype, &mtext, &secure, &sentAt); err != nil {
			continue
		}
		msgs = append(msgs, map[string]any{
			"message_id": mid, "sender_did": sd, "recipient_did": rd.String,
			"group_did": gd.String, "type": mtype, "text": mtext.String,
			"secure": secure != 0, "sent_at": sentAt,
		})
	}
	return map[string]any{"messages": msgs}, nil
}
