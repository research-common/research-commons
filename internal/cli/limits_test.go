package cli

import (
	"fmt"
	"go/build"
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
		gap: "Priority needs time evidence this reader verified: until the reader syncs a header chain (`anchor headers sync`, from a file only, L-02), every multi-author construction is `contested` (#59)",
		sources: []limitSource{
			{file: "docs/DESIGN-notes-claims-model.md", says: "Until readers can verify Bitcoin time evidence locally (#59), every multi-author construction is honestly `contested`."},
			{file: "CHANGELOG.md", says: "No command verifies Bitcoin time yet, so every rival construction is `contested`."},
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
		gap: "Block headers come only from a file the operator obtains (`anchor headers sync --from`): no network header source (P2P, compact filters) and no operator-node provider, so keeping a chain view fresh is a manual step. Every read re-validates the whole persisted chain, so a chain synced from genesis costs each read about a second and a few hundred MB: start from a bootstrap near the tip",
		sources: []limitSource{
			{file: "internal/README.md", says: "Not built: a network header source, the operator-node provider (§6.2), and persisted policy"},
			{help: []string{"anchor", "headers", "sync"}, says: "No network source is built: obtain the file from sources you choose."},
			{help: []string{"anchor", "headers", "sync"}, says: "Recommended: start from a bootstrap near the tip"},
		},
		probe:  "`anchor headers sync` without `--from` exits 2, and no command has an option naming a peer, node, RPC or URL",
		closes: "a network header source or an operator-node provider (bitcoin-time note §6.1–§6.2)",
		open: func(t *testing.T) (bool, string) {
			for _, c := range Commands() {
				if !strings.HasPrefix(c.Name, "anchor") {
					continue
				}
				for _, f := range c.Flags {
					for _, w := range []string{"peer", "node", "rpc", "url", "connect"} {
						if strings.Contains(f.Name, w) {
							return false, c.Name + " --" + f.Name
						}
					}
				}
			}
			r := runIn(t.TempDir(), nil, "anchor", "headers", "sync", "--json")
			return r.code == ExitDidNotStart && strings.Contains(r.stdout, "no network source is built"), r.stdout
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
		gap: "Task contracts are read under " + resolve.TaskContractV1Profile + " (and the provisional profile, under its own name) only: any other profile, or an unknown field, leaves readiness `unchecked`; no identity profile is registered, so `counting_unit: identity` reads `unknown`",
		sources: []limitSource{
			{help: []string{"publish", "task"}, says: "any other profile or an unknown field leaves readiness unchecked"},
		},
		probe:  "`publish task` with a contract of another profile prints readiness `unchecked`, naming the profile it reads",
		closes: "a later contract profile this reader reads",
		open: func(t *testing.T) (bool, string) {
			p := newPubWorld(t)
			ct := p.file("c.json", `{"profile":"rc-task-contract/1","beneficiary":"`+p.signer+`","any_issuer":true}`)
			r := runIn(p.root, nil, "publish", "task", "--key", p.key, "--name", "t", "--contract", ct, "--json")
			return r.code == ExitOK && strings.Contains(r.stdout, `"readiness":{"state":"unchecked"`) &&
				strings.Contains(r.stdout, resolve.TaskContractV1Profile), r.stdout
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
		gap: "No command writes a fixed-root identity (`rc/2`) statement: identities can be read, not created, by this tool (no inception, grant, cut or actor-bearing publish)",
		sources: []limitSource{
			{file: "docs/DESIGN-notes-fixed-root-identity.md", says: "**Status: reader active** (`rc/1` + `rc/2` read; no writer yet)."},
			{file: "internal/README.md", says: "### Identity admission (reader active, no writer)"},
		},
		probe:  "the writer's major is 1, `publish --draft` refuses an `identity_inception` draft and a draft carrying an `rc` or `x_actor_v1` member, while the reader verifies a signed `rc/2` line",
		closes: "a command that signs `rc/2` (inception, grant, cut, or a publish acting for an identity)",
		open: func(t *testing.T) (bool, string) {
			line, _ := wire.Sign(wire.Draft{RC: "rc/2", Kind: "identity_inception", TS: "2026-10-16T00:00:00Z", Crit: []string{wire.IdentityCrit},
				Body: obj("profile", wire.FixedRootProfile, wire.IdentityCrit, canon.Value(obj()))}, testKey("limits"))
			st, err := wire.ReadStored(line)
			if err != nil || !st.Verified || st.Status != wire.Valid {
				return false, "the reader does not verify rc/2: " + fmt.Sprint(err)
			}
			p := newPubWorld(t)
			for _, d := range []string{
				`{"kind":"identity_inception","body":{"profile":"fixed-root-v1","x_identity_v1":{}}}`,
				`{"kind":"authored","rc":"rc/2","body":{}}`,
				`{"kind":"authored","x_actor_v1":{"grant":"g","identity":"i"},"body":{}}`,
			} {
				if r := p.publish("--draft", p.file("d.json", d)); r.code == ExitOK {
					return false, "publish --draft signed " + d
				}
			}
			return wire.Major == 1, "writer major " + fmt.Sprint(wire.Major) + ", reader majors " + fmt.Sprint(wire.ReaderMajors)
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
	{
		id:  "L-10",
		gap: "`fetch` dials https (and http on request) only, through no proxy: a holds naming an `ipfs:`, object-store or `file:` location is never fetched",
		sources: []limitSource{
			{help: []string{"fetch"}, says: "content-addressed networks (ipfs:), object-store schemes and file: are not fetched: admit a local copy with pull. The transport uses no proxy."},
		},
		probe:  "an `ipfs:`, an `s3:` and a `file:` location are refused before dialling with every opt-in given",
		closes: "a transport for another scheme, or proxy support",
		open: func(t *testing.T) (bool, string) {
			for _, l := range []string{"ipfs://bafy", "s3://bucket/key", "file:///tmp/x"} {
				if schemeAllowed(l, true) == nil {
					return false, l + " is fetched"
				}
			}
			return true, "ipfs: s3: file: refused"
		},
	},
	{
		id:  "L-11",
		gap: "The tool does not build for Windows: the execution sandbox opens files with `O_NOFOLLOW` and signals processes with Unix calls",
		sources: []limitSource{
			{file: "docs/CLI-OUTPUTS.md", says: "Windows is not supported: the tool does not build for it."},
		},
		probe:  "under GOOS=windows, `internal/run` includes a file that uses `syscall.O_NOFOLLOW`, and no `_windows.go` file exists in the package",
		closes: "a Windows implementation of the sandbox file opens (a `_windows.go` file, or build constraints on the Unix-only files)",
		open: func(t *testing.T) (bool, string) {
			root, _ := conformance.RepoRoot()
			ctx := build.Default
			ctx.GOOS, ctx.GOARCH, ctx.CgoEnabled = "windows", "amd64", false
			pkg, err := ctx.ImportDir(filepath.Join(root, "internal", "run"), 0)
			if err != nil {
				return false, err.Error()
			}
			for _, f := range pkg.GoFiles {
				if strings.HasSuffix(f, "_windows.go") {
					return false, "windows file " + f
				}
			}
			for _, f := range pkg.GoFiles {
				b, err := os.ReadFile(filepath.Join(root, "internal", "run", f))
				if err != nil {
					return false, err.Error()
				}
				if strings.Contains(string(b), "syscall.O_NOFOLLOW") {
					return true, f + " is built for windows and uses syscall.O_NOFOLLOW"
				}
			}
			return false, "no windows-built file uses syscall.O_NOFOLLOW"
		},
	},
	{
		id:  "L-12",
		gap: "`--json` output may change between alpha releases: it carries no `schema` member yet",
		sources: []limitSource{
			{file: "docs/CLI-OUTPUTS.md", says: "the `--json` output may change between alpha releases. It carries no `schema` member yet."},
		},
		probe:  "`list --json` is an object with no `schema` member",
		closes: "a `schema` member on every `--json` object, and a stated compatibility rule",
		open: func(t *testing.T) (bool, string) {
			w := fixture(t)
			r := w.run("list", "--json")
			o := jsonOf(t, r)
			_, has := o.Members["schema"]
			return r.code == ExitOK && !has, r.stdout[:min(len(r.stdout), 200)]
		},
	},
	{
		id:  "L-13",
		gap: "`publish --draft` signs a `rotate_key` without `commons rotate`'s checks (successor, key events already held, merged tips); it warns and proceeds, so the owner's way out after a compromise stays open",
		sources: []limitSource{
			{help: []string{"publish"}, says: "A rotate_key draft is signed as written: none of `commons rotate`'s checks run"},
		},
		probe:  "after `rotate` signs a first rotation, `rotate` refuses a second (`key-already-retired`, exit 1), while `publish --draft` of a `rotate_key` is signed (exit 0) with a `warnings` list naming the skipped checks",
		closes: "`publish --draft` runs the rotate checks for a `rotate_key` (or refuses one it cannot check)",
		open: func(t *testing.T) (bool, string) {
			p := newPubWorld(t)
			p.describe(t, "A1")
			if r := p.rotate("--successor", testKey("S").Signer()); r.code != ExitOK {
				return false, "first rotation: " + r.stdout
			}
			if r := p.rotate("--successor", testKey("U").Signer()); r.code != exitWriterRefused || !strings.Contains(r.stdout, "key-already-retired") {
				return false, "rotate does not refuse a second rotation: " + r.stdout
			}
			d := p.file("rot2.json", `{"kind":"rotate_key","body":{"successor":"`+testKey("U").Signer()+`"}}`)
			r := p.publish("--draft", d)
			o := outObj(t, r)
			w, has := o.Members["warnings"]
			return r.code == ExitOK && has && strings.Contains(string(canon.Encode(w)), "skips the checks"), r.stdout[:min(len(r.stdout), 300)]
		},
	},
	{
		id:  "L-14",
		gap: "A response layout reads JSON only, through one JSON pointer to the record array and one to the state: a CSV, XML, compressed or archived response, or a state spread over several fields, is not read, so its observation's state stays the observer's asserted `state_at_capture` and a rule resolved through a pinned profile is at best `final (as captured, not re-checked)`",
		sources: []limitSource{
			{file: "CHANGELOG.md", says: "Other formats (CSV, XML, a compressed or archived response) are not read yet"},
			{file: "docs/DESIGN-notes-claims-model.md", says: "Other formats (CSV, XML, a compressed or archived response) stay `unchecked`, naming why, until another layout dialect is specified (§15)."},
		},
		probe:  "with a profile pinned in the store-root policy, citing a response layout, and held, `verify` of an observation whose rule `run >= RF` cites it at asserted state `RF`, over a held CSV response whose run column is `R1`, exits 0 with referent `final (as captured, not re-checked)` and the layout read `unchecked` (not I-JSON)",
		closes: "a layout dialect for another response format reads the state out of such a response, so the asserted state is checked against it",
		open: func(t *testing.T) (bool, string) {
			lay := canon.Encode(obj("layout", resolve.ResponseLayoutTag, "records", "", "state", "/run"))
			ld := dig(string(lay))
			prof := canon.Encode(obj("profile", resolve.SourceProfileTag, "source", "s", "dialect", resolve.DialectOrderedLabel, "labels", []string{"SF", "R1", "RF"},
				"documents", []string{ld}))
			pd := dig(string(prof))
			w := newWorld(t)
			w.blob("p", prof)
			w.blob("l", lay)
			captured := "run,value\nR1,1\n"
			w.blob(captured, []byte(captured))
			os.WriteFile(filepath.Join(w.root, PolicyFile), []byte(`{"policy":"rc-hub-policy/1","series":{"source_profiles":[{"digest":"`+pd+`"}]}}`), 0o644)
			ref := obj("endpoint", "https://api.example/settlement", "parameters", obj("period", "x"), "response_digest", dig(captured))
			id := w.sign("O", "O", "observed", obj("content", content(captured), "class", "source", "referent", canon.Value(ref),
				"capture", obj("at", "2026-01-02T00:00:00Z", "evidence", "self-asserted"),
				"finality", obj("rule", "run >= RF", "rule_source", pd, "state_at_capture", obj("run", "RF"))))
			r := w.run("verify", id)
			return r.code == ExitOK && strings.Contains(r.stdout, "status: final (as captured, not re-checked)") &&
				strings.Contains(r.stdout, "unchecked (the response is not I-JSON"), r.stdout[:min(len(r.stdout), 600)]
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
