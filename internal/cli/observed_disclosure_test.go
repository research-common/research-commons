package cli

import (
	"regexp"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
)

// TestObservedDisclosuresSurfaces: an `observed` published with its single-party disclosures (a draft: `publish`
// builds only `authored` from flags) is shown with them on show, verify and explain, in text and in --json, and
// they never move `verify`'s exit. Before the fix the blob read `licence: unknown`, `replication: undeclared`.
func TestObservedDisclosuresSurfaces(t *testing.T) {
	p := newPubWorld(t)
	data := "capture one"
	d := dig(data)
	draft := func(name, extra string) string {
		return p.file(name, `{"kind":"observed","body":{"content":{"digest":"`+d+`","size":`+itoa(len(data))+`},"class":"source",`+
			`"referent":{"endpoint":"https://api.example/x","parameters":{},"response_digest":"`+d+`"},`+
			`"capture":{"at":"2026-01-02T00:00:00Z","evidence":"self-asserted"}`+extra+`}}`)
	}
	// the exit of an observation blob with no disclosures: the baseline the disclosures must not move
	bare := newPubWorld(t)
	if r := bare.publish("--draft", draft("o0", ""), "--content", bare.file("c", data)); r.code != ExitOK {
		t.Fatalf("publish bare: %d %s", r.code, r.stdout)
	}
	base := map[string]int{}
	for _, cmd := range []string{"show", "verify", "explain"} {
		base[cmd] = bare.run(cmd, d, "--json").code
	}
	if r := bare.run("show", d); !regexp.MustCompile(`licence:\n\s+state: unknown`).MatchString(r.stdout) {
		t.Fatalf("baseline show should read licence unknown:\n%s", r.stdout)
	}

	r := p.publish("--draft", draft("o1", `,"licence":"CC0-1.0","replication":"bytes","shelf_life_days":30,`+
		`"availability":{"redistribution":"permitted","obtainable":true},"attribution":"A. Observer"`), "--content", p.file("c", data))
	if r.code != ExitOK {
		t.Fatalf("publish: %d %s", r.code, r.stdout)
	}
	for _, cmd := range []string{"show", "verify", "explain"} {
		h := p.run(cmd, d)
		// the human surface is a nested listing: `licence:` then its state and value lines
		for _, want := range []string{`licence:\n\s+state: default\n\s+value: "CC0-1.0"`, `replication:\n\s+state: default\n\s+value: "bytes"`,
			`shelf life days:\n\s+state: default\n\s+value: 30`, `availability:\n\s+state: default\n(.*\n)*?\s+redistribution: permitted`} {
			if !regexp.MustCompile(want).MatchString(h.stdout) {
				t.Errorf("%s: missing %q in\n%s", cmd, want, h.stdout)
			}
		}
		for _, bad := range []string{`licence:\n\s+state: unknown`, `replication:\n\s+state: undeclared`} {
			if regexp.MustCompile(bad).MatchString(h.stdout) {
				t.Errorf("%s: still prints %q", cmd, bad)
			}
		}
		j := p.run(cmd, d, "--json")
		if j.code != base[cmd] || h.code != base[cmd] {
			t.Errorf("%s: exit %d (json %d), want the bare observation's %d: disclosures never move an exit (I6)", cmd, h.code, j.code, base[cmd])
		}
		disc := jsonOf(t, j).Members["disclosures"].(*canon.Object)
		lic := disc.Members["licence"].(*canon.Object)
		if string(canon.Encode(lic.Members["state"])) == `"unknown"` || string(canon.Encode(lic.Members["value"])) != `"CC0-1.0"` {
			t.Errorf("%s --json licence = %s, want default CC0-1.0", cmd, canon.Encode(lic))
		}
		if rep := disc.Members["replication"].(*canon.Object); string(canon.Encode(rep.Members["value"])) != `"bytes"` {
			t.Errorf("%s --json replication = %s", cmd, canon.Encode(rep))
		}
	}
}
