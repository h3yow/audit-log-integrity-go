package audit

import "strings"

func splitTestLines(b []byte) [][]byte {
	trimmed := strings.TrimSuffix(string(b), "\n")
	if trimmed == "" {
		return nil
	}
	parts := strings.Split(trimmed, "\n")
	out := make([][]byte, len(parts))
	for i := range parts {
		out[i] = []byte(parts[i])
	}
	return out
}
