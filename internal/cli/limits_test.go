package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/wire"
)

// Documented limits (C-core-07). Each row is a gap the documentation tells users about, where they read it, and
// a probe that holds while the gap is open. The test fails in two ways, both forcing the documentation and this
// table to move together: when a quoted sentence leaves its file (the doc changed, so the row must change), and
// when a probe finds the gap closed (the code changed, so the doc must change). docs/KNOWN-LIMITS.md is generated
// from the table and is the published list.

// limitSource is where users read a limit: a file of the repository, or a command's --help, and the words there.
type limitSource struct {
	file string   // repository-relative path; "" when help is set
	help []string // a command line whose --help output carries the words
	says string   // the quoted words (matched with runs of whitespace collapsed)
}

func (s limitSource) where() string {
	if s.file != "" {
		return "`" + s.file + "`"
	}
	return "`commons " + strings.Join(s.help, " ") + " --help`"
}

type limit struct {
	id      string
	gap     string // what is not there, in a user's words
	sources []limitSource
	probe   string // what the test checks
	closes  string // what closing the gap looks like (the probe then fails)
	open    func(t *testing.T) (bool, string)
}

func squash(s string) string { return strings.Join(strings.Fields(s), " ") }

var limits = []limit{
	{
		id:  "L-01",
		gap: "Priority needs time evidence this reader verified, and no command verifies Bitcoin time: every multi-author construction is `contested` (#59)",
		sources: []limitSource{
			{file: "docs/DESIGN-notes-claims-model.md", says: "Until readers can verify Bitcoin time evidence locally (#59), every multi-author construction is honestly `contested`."},
			{file: "CHANGELOG.md", says: "The default verifies nothing, so every rival construction is `contested` until the Bitcoin-time profile lands."},
		},
		probe:  "two keys claim one blob, each with an anchor whose proof parses: `verify` exits 3, authorship `contested`, each anchor's time state `backend-unconfigured`",
		closes: "a chain backend verifies one claimant's bound strictly earlier: `default author`",
		open: func(t *testing.T) (bool, string) {
			w := fixture(t)
			r := w.run("verify", dig("contested"), "--json")
			o := jsonOf(t, r)
			s := string(canon.Encode(o))
			return r.code == ExitCouldNot && o.Members["authorship"] == canon.String("contested") &&
				strings.Count(s, `"state":"backend-unconfigured"`) == 2, s
		},
	},
	{
		id:  "L-02",
		gap: "No chain backend, header sync or receipt store: no anchor is ever verified, and every answer is clock-free",
		sources: []limitSource{
			{file: "internal/README.md", says: "Not built: the receipt store (§9) and the commands (§10)"},
			{file: "docs/CLI-OUTPUTS.md", says: "no chain backend is configured, so no bound is verified; a state, not a failed invocation (exit 3)"},
		},
		probe:  "no registered command starts with `anchor`; `explain` says no chain backend is configured",
		closes: "an `anchor headers sync` / `anchor status` command (bitcoin-time note §10) and a configurable backend",
		open: func(t *testing.T) (bool, string) {
			for _, c := range Commands() {
				if strings.HasPrefix(c.Name, "anchor") {
					return false, "command " + c.Name
				}
			}
			w := fixture(t)
			tc, _ := jsonOf(t, w.run("explain", dig("contested"), "--json")).Members["time_context"].(canon.String)
			return strings.Contains(string(tc), "no chain backend is configured"), string(tc)
		},
	},
	{
		id:  "L-03",
		gap: "Seed-phrase (mnemonic) key derivation",
		sources: []limitSource{
			{file: "docs/KEY-FILES.md", says: "Seed-phrase (mnemonic) derivation is not built."},
			{help: []string{"key", "new"}, says: "Seed-phrase derivation is not built."},
		},
		probe:  "no command or option mentions a mnemonic, seed phrase or words",
		closes: "a key command or option that derives a key from a phrase",
		open: func(t *testing.T) (bool, string) {
			for _, c := range Commands() {
				names := []string{c.Name}
				for _, f := range c.Flags {
					names = append(names, f.Name)
				}
				for _, n := range names {
					if strings.Contains(n, "mnemonic") || strings.Contains(n, "phrase") || strings.Contains(n, "words") || strings.Contains(n, "seed") {
						return false, c.Name + " " + n
					}
				}
			}
			return true, "none"
		},
	},
	{
		id:  "L-04",
		gap: "Native (unsandboxed) re-runs and secret or host-resource grants are not expressible in an execution policy",
		sources: []limitSource{
			{file: "docs/EXEC-POLICY.md", says: "Native (unsandboxed) runs and accepting native records from others: the format has no member for them, so a re-run is always sandboxed."},
			{file: "docs/EXEC-POLICY.md", says: "Secret or host-resource grants: there is no place in the file for them"},
		},
		probe:  "a policy with a `native` or a `secrets` member is refused before any work (exit 2); the same policy without it is accepted (control)",
		closes: "a member for native runs or secret grants",
		open: func(t *testing.T) (bool, string) {
			dir := t.TempDir()
			base := `{"format":"` + ExecPolicyFormat + `","images":["sha256:` + strings.Repeat("1", 64) + `"]`
			write := func(name, body string) string {
				p := filepath.Join(dir, name)
				os.WriteFile(p, []byte(body), 0o644)
				return p
			}
			if _, prob := readExecPolicy(write("ok.json", base+"}")); prob != nil {
				t.Fatalf("control policy refused: %s", prob.Detail)
			}
			for _, m := range []string{`"native":true`, `"secrets":["TOKEN"]`} {
				if _, prob := readExecPolicy(write("x.json", base+","+m+"}")); prob == nil || prob.Exit != ExitDidNotStart {
					return false, m + " accepted"
				}
			}
			return true, "both refused"
		},
	},
	{
		id:  "L-05",
		gap: "The task contract grammar is provisional: only the provisional profile is read; any other contract leaves readiness `unchecked`",
		sources: []limitSource{
			{help: []string{"publish", "task"}, says: "the edition's contract, a JSON object (the contract grammar is provisional)"},
		},
		probe:  "`publish task` with a contract of any other profile prints readiness `unchecked`, naming the profile it reads",
		closes: "a specified contract grammar this reader reads",
		open: func(t *testing.T) (bool, string) {
			p := newPubWorld(t)
			ct := p.file("c.json", `{"profile":"rc-task-contract/1","beneficiary":"`+p.signer+`","any_issuer":true}`)
			r := runIn(p.root, nil, "publish", "task", "--key", p.key, "--name", "t", "--contract", ct, "--json")
			return r.code == ExitOK && strings.Contains(r.stdout, `"readiness":{"state":"unchecked"`) &&
				strings.Contains(r.stdout, resolve.ProvisionalProfile), r.stdout
		},
	},
	{
		id:  "L-06",
		gap: "No rule or schema dialect is specified: an edition rule or member schema is always `unchecked`",
		sources: []limitSource{
			{file: "docs/DESIGN-notes-claims-model.md", says: "a member schema under no dialect the reader implements is loaded, named and always `unchecked`"},
		},
		probe:  "the publisher's pre-pin check is built with no rule dialect",
		closes: "a dialect note and a dialect shipped in the reader",
		open: func(t *testing.T) (bool, string) {
			return len(ruleDialects) == 0, "rule dialects shipped: " + string(rune('0'+len(ruleDialects)))
		},
	},
	{
		id:  "L-07",
		gap: "Fixed-root identity (`rc/2`) is a review candidate, not enabled: an `rc/2` line is an unverified other-major line",
		sources: []limitSource{
			{file: "docs/DESIGN-notes-fixed-root-identity.md", says: "**Status: review candidate; not enabled in the production reader or writer.**"},
			{file: "internal/README.md", says: "### Candidate identity admission (opt-in, not wired)"},
		},
		probe:  "the format major is 1, and a signed `rc/2` line reads as `unsupported` and unverified",
		closes: "activating the profile (the major moves, or the reader verifies `rc/2`)",
		open: func(t *testing.T) (bool, string) {
			line, _ := wire.Sign(wire.Draft{RC: "rc/2", Kind: "describes", TS: "2026-10-16T00:00:00Z",
				Body: obj("about", canon.Value(obj("content", dig("x"))), "note", "n")}, testKey("limits"))
			st, err := wire.Read(line)
			if err != nil {
				return false, err.Error()
			}
			return wire.Major == 1 && st.Status == wire.Unsupported && !st.Verified, string(st.Status) + " " + st.Why
		},
	},
	{
		id:  "L-08",
		gap: "No critical extension is implemented: any statement marking one critical is kept, verified and `unsupported`",
		sources: []limitSource{
			{file: "docs/READER-EXTENSIONS.md", says: "**No concrete extension is implemented or enabled.**"},
		},
		probe:  "a signed statement with `crit: [x_ext]` reads verified and `unsupported`, naming the extension",
		closes: "a registered extension in the production reader",
		open: func(t *testing.T) (bool, string) {
			line, _ := wire.Sign(wire.Draft{Kind: "describes", TS: "2026-10-16T00:00:00Z", Crit: []string{"x_ext"},
				Body: obj("about", canon.Value(obj("content", dig("x"))), "note", "n", "x_ext", true)}, testKey("limits"))
			st, err := wire.Read(line)
			if err != nil {
				return false, err.Error()
			}
			return st.Verified && st.Status == wire.Unsupported && strings.Contains(st.Why, "x_ext"), string(st.Status) + " " + st.Why
		},
	},
	{
		id:  "L-09",
		gap: "Key and execution-policy file formats are provisional (version 0) and expected to change before a stable release",
		sources: []limitSource{
			{file: "docs/KEY-FILES.md", says: "**Status: provisional.** The format tag is this tool's own and is versioned (`rc-key/0`)."},
			{file: "docs/EXEC-POLICY.md", says: "**Status: provisional.**"},
		},
		probe:  "the key file tag is `rc-key/0` and the execution policy tag is `rc-exec-policy/0`",
		closes: "a stable (`/1`) tag for either format",
		open: func(t *testing.T) (bool, string) {
			return KeyFormat == "rc-key/0" && ExecPolicyFormat == "rc-exec-policy/0", KeyFormat + " " + ExecPolicyFormat
		},
	},
}

// TestDocumentedLimits: C-core-07.
func TestDocumentedLimits(t *testing.T) {
	conformance.Covers(t, "C-core-07")
	root, _ := conformance.RepoRoot()
	for _, l := range limits {
		t.Run(l.id, func(t *testing.T) {
			for _, s := range l.sources {
				var text string
				if s.file != "" {
					b, err := os.ReadFile(filepath.Join(root, s.file))
					if err != nil {
						t.Fatal(err)
					}
					text = string(b)
				} else {
					r := runIn(t.TempDir(), nil, append(s.help, "--help")...)
					text = r.stdout
				}
				if !strings.Contains(squash(text), squash(s.says)) {
					t.Fatalf("%s no longer says %q: update this row and docs/KNOWN-LIMITS.md", s.where(), s.says)
				}
			}
			if open, got := l.open(t); !open {
				t.Fatalf("the gap looks closed (%s): update the documentation in %d place(s), then this row\nobserved: %s", l.gap, len(l.sources), got)
			}
		})
	}
	p := filepath.Join(root, "docs", "KNOWN-LIMITS.md")
	want := limitsMarkdown()
	if os.Getenv("RC_UPDATE_DOCS") == "1" {
		os.WriteFile(p, []byte(want), 0o644)
	}
	if got, err := os.ReadFile(p); err != nil || string(got) != want {
		t.Fatal("docs/KNOWN-LIMITS.md is not the generated list; run RC_UPDATE_DOCS=1 go test -run TestDocumentedLimits ./internal/cli")
	}
}

func limitsMarkdown() string {
	var b strings.Builder
	b.WriteString("# Known limits\n\n")
	b.WriteString("Generated from `internal/cli/limits_test.go` by `RC_UPDATE_DOCS=1 go test -run TestDocumentedLimits ./internal/cli`.\n")
	b.WriteString("Do not edit by hand.\n\n")
	b.WriteString("Every gap below is documented where users read it, and each has a test asserting the gap is still open\n")
	b.WriteString("(conformance case C-core-07). The test fails when the quoted words leave their file or when the probe finds\n")
	b.WriteString("the gap closed, so the documentation and this list change with the code.\n\n")
	b.WriteString("| id | limit | where users read it | the test checks (holds while open) | closed when |\n|---|---|---|---|---|\n")
	for _, l := range limits {
		var ws []string
		for _, s := range l.sources {
			ws = append(ws, s.where())
		}
		b.WriteString("| " + l.id + " | " + l.gap + " | " + strings.Join(ws, "<br>") + " | " + l.probe + " | " + l.closes + " |\n")
	}
	return b.String()
}
