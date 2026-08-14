package server

import (
	"net/http"
	"strings"
)

func httpHeaders(r *http.Request) map[string]string {
	m := map[string]string{}
	for key, vals := range r.Header {
		if len(vals) > 0 {
			m[key] = vals[0]
		}
	}
	return m
}

func headerGet(headers map[string]string, key string) string {
	for k, v := range headers {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return "unknown"
}
