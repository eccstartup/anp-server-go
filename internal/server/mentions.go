package server

import "fmt"

// mentions.go implements the P9 message-mentions convention. Mentions are a
// top-level field inside a group message payload; the server's only duty is to
// forward them verbatim (never drop, rewrite, or reject legitimate mentions).
// Full P9 validation (range bounds, target.kind, mention_role, …) is a
// terminal-side responsibility per the spec.

// validateMentions performs light structural validation of an optional
// "mentions" field. It only rejects clearly malformed data — a non-array
// mentions value or duplicate mention ids — and otherwise forwards the mentions
// untouched.
func validateMentions(payload map[string]any) error {
	if payload == nil {
		return nil
	}
	raw, ok := payload["mentions"]
	if !ok {
		return nil
	}
	arr, ok := raw.([]any)
	if !ok {
		return fmt.Errorf("mentions must be an array")
	}
	seen := map[string]bool{}
	for _, item := range arr {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		id, _ := m["id"].(string)
		if id == "" {
			continue
		}
		if seen[id] {
			return fmt.Errorf("duplicate mention id %q", id)
		}
		seen[id] = true
	}
	return nil
}
