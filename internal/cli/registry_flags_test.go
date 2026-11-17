package cli

import "testing"

// TestNoDuplicateFlags: no command registers the same option twice (a duplicate shows up twice in the
// usage line and in --help).
func TestNoDuplicateFlags(t *testing.T) {
	for _, c := range Commands() {
		seen := map[string]bool{}
		for _, f := range c.Flags {
			if seen[f.Name] {
				t.Errorf("%s: option --%s registered twice", c.Name, f.Name)
			}
			seen[f.Name] = true
		}
	}
}
