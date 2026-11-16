package cli

import "strings"

// withoutHistory drops the operation history files from a snapshot (fixture_test.go snapshot): local
// bookkeeping every finished operation appends to, never part of what a command commits.
func withoutHistory(snap string) string {
	var out []string
	for _, l := range strings.Split(snap, "\n") {
		f := strings.Fields(l)
		if len(f) > 0 && (f[0] == "journal/history.jsonl" || f[0] == "journal/history.1.jsonl") {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}
