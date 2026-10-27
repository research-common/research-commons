// Package cli is the command-line surface of the next-format tool: the command registry, the outputs
// contract of claims-model note §13 (closed vocabulary, exit table, exit 2 before any work, RFC 9457
// problem details, inert peer text) and the commands over a local store. cmd/commons is a thin main around
// Main, so every command runs in-process under test.
package cli

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"slices"
	"strings"

	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/store"
)

// Build identifies the binary. main sets Version and Commit through -ldflags; an empty Commit falls back to
// the VCS revision the Go toolchain stamped into the binary.
type Build struct {
	Version, Commit string
}

// Env is everything Main reads from the process, injectable for tests.
type Env struct {
	Stdout, Stderr io.Writer
	Getenv         func(string) string
	Getwd          func() (string, error)
	Build          Build
}

// Ctx is one invocation as a command's Run sees it: arguments and flags already validated, the store (when
// the command reads one) discovered, checked and open.
type Ctx struct {
	Cmd    *Command
	Args   map[string]string
	Flags  map[string]string // present flags; a boolean flag maps to ""
	JSON   bool
	Root   string
	Policy *Policy
	Store  *store.Store
	Env    *Env
	// state carries what a command's Before checked and Run uses (a loaded key), so Run does not re-read it.
	state any
	// Prep is what the command's Prepare hook read, for Run.
	Prep any
}

// Flag reports a flag's value and whether it was given.
func (c *Ctx) Flag(name string) (string, bool) {
	v, ok := c.Flags[name]
	return v, ok
}

// StoreEnv is the environment variable naming the store when --store is not given.
const StoreEnv = "COMMONS_STORE"

var (
	reDigest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	reID     = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func isDigest(s string) bool { return reDigest.MatchString(s) }
func isID(s string) bool     { return reID.MatchString(s) }

// Main runs one invocation and returns its exit code. It never panics: an internal error is reported as a
// problem with exit 3, because by then work may have started and exit 2 would claim it had not.
func Main(argv []string, env *Env) (code int) {
	jsonOut := slices.Contains(argv, "--json")
	defer func() {
		if r := recover(); r != nil {
			p := &Problem{Slug: "internal-error", Title: "internal error", Class: refusal.Operational, Scope: "invocation",
				Detail: "the tool hit a bug; nothing it printed before this is complete", Next: "report the bug with the command line",
				Peer: fmt.Sprint(r), Exit: ExitCouldNot}
			code = emitProblem(env, p, jsonOut)
		}
	}()
	obj, code, err := dispatch(argv, env)
	if err != nil {
		var p *Problem
		if pp, ok := err.(*Problem); ok {
			p = pp
		} else {
			p = failed(err, "invocation", false, "run the command again; if it recurs, run status")
		}
		return emitProblem(env, p, jsonOut)
	}
	ExitName(code) // panics (recovered above) on a code outside the table
	if obj != nil {
		if jsonOut {
			env.Stdout.Write(encodeJSON(obj))
		} else {
			io.WriteString(env.Stdout, human(obj))
		}
	}
	return code
}

func emitProblem(env *Env, p *Problem, jsonOut bool) int {
	ExitName(p.Exit)
	if jsonOut {
		env.Stdout.Write(encodeJSON(p.obj()))
		return p.Exit
	}
	io.WriteString(env.Stderr, "commons: "+p.Title+"\n"+human(p.obj()))
	return p.Exit
}

// parsed is a command line split into words, flags and positional arguments.
type parsed struct {
	words []string // everything that is not a flag, in order
	flags map[string]string
	order []string // flag names in order, for duplicate detection
}

// split separates flags from words. A flag is --name, --name=value or --name value; the value form is decided
// by the flag's declaration, so split takes the known flags. "--" ends options. Anything starting with "-"
// that is not a known flag is an unknown option: exit 2.
func split(argv []string, known func(string) (Flag, bool)) (*parsed, *Problem) {
	p := &parsed{flags: map[string]string{}}
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if a == "--" {
			p.words = append(p.words, argv[i+1:]...)
			break
		}
		if a == "-h" {
			a = "--help"
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			p.words = append(p.words, a)
			continue
		}
		name, val, hasVal := strings.Cut(strings.TrimPrefix(a, "--"), "=")
		f, ok := known(name)
		if !strings.HasPrefix(a, "--") || !ok {
			return nil, usage("unknown-option", "unknown option", "this command has no such option; nothing was done",
				"invocation", "run commons help to list the options", a)
		}
		if f.Value == "" && hasVal {
			return nil, usage("malformed-argument", "an option that takes no value was given one",
				"nothing was done", "option --"+f.Name, "drop the value", a)
		}
		if f.Value != "" && !hasVal {
			if i+1 >= len(argv) {
				return nil, usage("malformed-argument", "an option is missing its value", "nothing was done",
					"option --"+f.Name, "give --"+f.Name+" <"+f.Value+">", "")
			}
			i++
			val = argv[i]
		}
		if _, dup := p.flags[f.Name]; dup {
			return nil, usage("malformed-argument", "an option was given twice", "nothing was done",
				"option --"+f.Name, "give it once", "")
		}
		if f.Check != nil {
			if err := f.Check(val); err != nil {
				return nil, usage("malformed-argument", "an option's value has the wrong shape", err.Error(),
					"option --"+f.Name, "see commons help", val)
			}
		}
		p.flags[f.Name] = val
		p.order = append(p.order, f.Name)
	}
	return p, nil
}

func dispatch(argv []string, env *Env) (*Obj, int, error) {
	// first pass: find the command by its words, accepting every flag any command declares, so a flag before
	// the command name is not mistaken for the name
	anyFlag := func(n string) (Flag, bool) {
		for _, g := range globalFlags {
			if g.Name == n {
				return g, true
			}
		}
		for _, c := range registry {
			for _, f := range c.Flags {
				if f.Name == n {
					return f, true
				}
			}
		}
		return Flag{}, false
	}
	pre, prob := split(argv, anyFlag)
	if prob != nil {
		return nil, 0, prob
	}
	if _, ok := pre.flags["version"]; ok && len(pre.words) == 0 {
		return versionObj(env.Build), ExitOK, nil
	}
	if len(pre.words) == 0 {
		return helpObj(nil), ExitOK, nil
	}
	if pre.words[0] == "help" {
		c, n := lookup(pre.words[1:])
		if len(pre.words) > 1 && (c == nil || n != len(pre.words)-1) {
			if len(pre.words) == 2 && (pre.words[1] == "outputs" || pre.words[1] == "exits") {
				return outputsObj(pre.words[1]), ExitOK, nil
			}
			return nil, 0, usage("unknown-command", "unknown command", "there is no such command; nothing was done",
				"invocation", "run commons help to list the commands", strings.Join(pre.words[1:], " "))
		}
		return helpObj(c), ExitOK, nil
	}
	cmd, n := lookup(pre.words)
	if cmd == nil {
		return nil, 0, usage("unknown-command", "unknown command", "there is no such command; nothing was done",
			"invocation", "run commons help to list the commands", pre.words[0])
	}
	// second pass: only this command's flags and the global ones
	own := func(n string) (Flag, bool) {
		for _, f := range append(slices.Clone(globalFlags), cmd.Flags...) {
			if f.Name == n {
				return f, true
			}
		}
		return Flag{}, false
	}
	p, prob := split(argv, own)
	if prob != nil {
		return nil, 0, prob
	}
	if _, ok := p.flags["help"]; ok {
		return helpObj(cmd), ExitOK, nil
	}
	if _, ok := p.flags["version"]; ok {
		return versionObj(env.Build), ExitOK, nil
	}
	ctx := &Ctx{Cmd: cmd, Args: map[string]string{}, Flags: p.flags, Env: env}
	_, ctx.JSON = p.flags["json"]
	pos := p.words[n:]
	if prob := bindArgs(cmd, pos, ctx.Args); prob != nil {
		return nil, 0, prob
	}
	if cmd.Prepare != nil {
		if prob := cmd.Prepare(ctx); prob != nil {
			return nil, 0, prob
		}
	}
	if cmd.Store {
		root, prob := discover(p.flags, env)
		if prob != nil {
			return nil, 0, prob
		}
		pol, prob := loadHubPolicy(root)
		if prob != nil {
			return nil, 0, prob
		}
		if cmd.ReaderPolicy {
			if pol.Reader, pol.ReaderSource, prob = loadReaderPolicy(p.flags, env); prob != nil {
				return nil, 0, prob
			}
		}
		ctx.Root, ctx.Policy = root, pol
		if cmd.Before != nil {
			if prob := cmd.Before(ctx); prob != nil {
				return nil, 0, prob
			}
		}
		// every argument and configuration check has passed: from here on, work starts (journal replay)
		s, err := store.Open(root, store.Options{})
		if err != nil {
			return nil, 0, failed(err, "store", false, "run status; if the store is damaged, fsck")
		}
		ctx.Store = s
	} else {
		if _, ok := p.flags["store"]; ok {
			return nil, 0, usage("unknown-option", "this command reads no store", "--store does not apply; nothing was done",
				"option --store", "drop --store", "")
		}
		if cmd.Before != nil {
			if prob := cmd.Before(ctx); prob != nil {
				return nil, 0, prob
			}
		}
	}
	return cmd.Run(ctx)
}

func bindArgs(cmd *Command, pos []string, into map[string]string) *Problem {
	if len(pos) > len(cmd.Args) {
		return usage("unexpected-argument", "too many arguments", "nothing was done", "invocation",
			"see commons help "+cmd.Name, pos[len(cmd.Args)])
	}
	for i, a := range cmd.Args {
		if i >= len(pos) {
			if a.Optional {
				continue
			}
			return usage("missing-argument", "a required argument is missing", "nothing was done",
				"argument "+a.Name, "see commons help "+cmd.Name, "")
		}
		v := pos[i]
		ok := true
		want := ""
		switch a.Shape {
		case ShapeRef:
			ok, want = isDigest(v) || isID(v), "a content digest (sha256: + 64 lowercase hex) or a statement id (64 lowercase hex)"
		case ShapeDigest:
			ok, want = isDigest(v), "a content digest (sha256: + 64 lowercase hex)"
		case ShapeID:
			ok, want = isID(v), "a statement id (64 lowercase hex)"
		}
		if !ok {
			return usage("malformed-argument", "an argument has the wrong shape",
				"the argument must be "+want+"; nothing was done", "argument "+a.Name, "give the full digest or id", v)
		}
		into[a.Name] = v
	}
	return nil
}

// discover finds the store: --store, else $COMMONS_STORE, else the nearest ancestor of the working directory
// holding an rc-store marker. A named directory without a marker, or with a marker naming another layout, is
// exit 2: the read commands never create a store.
func discover(flags map[string]string, env *Env) (string, *Problem) {
	noStore := func(detail, scope, peer string) *Problem {
		p := usage("no-store", "no store to read", detail+"; nothing was done", scope,
			"run inside a store, or give --store <dir> or "+StoreEnv, peer)
		p.Class = refusal.Operational
		return p
	}
	check := func(dir, scope string) (string, *Problem) {
		abs, err := filepath.Abs(dir)
		if err != nil {
			return "", noStore("the directory could not be resolved", scope, dir)
		}
		switch err := store.CheckMarker(abs); {
		case err == store.ErrNoMarker:
			return "", noStore("the directory holds no rc-store marker", scope, dir)
		case err != nil:
			return "", noStore("the rc-store marker is unusable or names a layout this tool does not implement ("+store.Layout()+")", scope, dir)
		}
		return abs, nil
	}
	if d, ok := flags["store"]; ok {
		return check(d, "option --store")
	}
	if d := env.Getenv(StoreEnv); d != "" {
		return check(d, "environment "+StoreEnv)
	}
	wd, err := env.Getwd()
	if err != nil {
		return "", noStore("the working directory could not be read", "invocation", "")
	}
	for dir := wd; ; {
		if err := store.CheckMarker(dir); err == nil {
			return dir, nil
		} else if err != store.ErrNoMarker {
			return "", noStore("the nearest rc-store marker is unusable or names a layout this tool does not implement", "store", dir)
		}
		up := filepath.Dir(dir)
		if up == dir {
			return "", noStore("no rc-store marker in the working directory or any parent", "invocation", "")
		}
		dir = up
	}
}

// OSEnv is the process environment.
func OSEnv(b Build) *Env {
	return &Env{Stdout: os.Stdout, Stderr: os.Stderr, Getenv: os.Getenv, Getwd: os.Getwd, Build: b}
}

func versionObj(b Build) *Obj {
	v, c := b.Version, b.Commit
	if v == "" {
		v = "devel"
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		if c == "" {
			for _, s := range bi.Settings {
				if s.Key == "vcs.revision" {
					c = s.Value
				}
			}
		}
		if c == "" {
			c = "unknown"
		}
		return newObj().set("version", textV(v)).set("commit", textV(c)).set("go", textV(bi.GoVersion))
	}
	if c == "" {
		c = "unknown"
	}
	return newObj().set("version", textV(v)).set("commit", textV(c))
}

func helpObj(c *Command) *Obj {
	if c == nil {
		o := newObj().set("usage", textV("commons <command> [options] [--json]"))
		var cmds listV
		for _, c := range registry {
			cmds = append(cmds, newObj().set("command", textV(c.Name)).set("summary", textV(c.Summary)))
		}
		o.set("commands", cmds)
		var gl listV
		for _, f := range globalFlags {
			gl = append(gl, newObj().set("option", textV("--"+f.Name)).set("summary", textV(f.Help)))
		}
		o.set("global_options", gl)
		o.set("more", textV("commons help <command> · commons help outputs (state tokens) · commons help exits (exit codes)"))
		return o
	}
	o := newObj().set("usage", textV(synopsis(c))).set("summary", textV(c.Summary))
	if c.Help != "" {
		o.set("description", textV(c.Help))
	}
	var fl listV
	for _, f := range c.Flags {
		fl = append(fl, newObj().set("option", textV("--"+f.Name)).set("summary", textV(f.Help)))
	}
	if len(fl) > 0 {
		o.set("options", fl)
	}
	return o
}

func outputsObj(which string) *Obj {
	o := newObj()
	if which == "exits" {
		var l listV
		for _, r := range ExitRows() {
			l = append(l, newObj().set("exit", textV(r[0])).set("name", textV(r[1])).set("meaning", textV(r[2])))
		}
		return o.set("exit_codes", l)
	}
	var l listV
	for _, t := range vocabulary {
		l = append(l, newObj().set("token", textV(t.Word)).set("kind", textV(t.Kind)).set("meaning", textV(t.Meaning)))
	}
	return o.set("state_tokens", l)
}

// outputsMarkdown is docs/CLI-OUTPUTS.md: the exit table and the closed vocabulary, generated from the tables
// the code prints from (claims-model note §13; C-core-132, C-core-133).
func outputsMarkdown() string {
	var b strings.Builder
	b.WriteString("# Command-line outputs\n\n")
	b.WriteString("Generated from `internal/cli` (`exit.go`, `vocab.go`) by `RC_UPDATE_DOCS=1 go test -run TestOutputsDoc ./internal/cli`.\n")
	b.WriteString("Do not edit by hand: a test fails when this file and the code differ. `commons help exits` and\n`commons help outputs` print the same tables.\n\n")
	b.WriteString("Errors are RFC 9457 problem-details objects (`type`, `title`, `detail`, `class`, `scope`, `committed`,\n`next`, `exit`; peer-supplied text only in `peer_text`). Types are `" + ProblemTypeBase + "<slug>`.\n\n")
	b.WriteString("## Exit codes\n\n| exit | name | meaning |\n|---|---|---|\n")
	for _, r := range ExitRows() {
		b.WriteString("| " + r[0] + " | " + r[1] + " | " + r[2] + " |\n")
	}
	b.WriteString("\n## State tokens\n\nJSON members carrying tokens: `" + strings.Join(tokenKeys, "`, `") + "`.\n\n| token | kind | meaning |\n|---|---|---|\n")
	for _, t := range vocabulary {
		b.WriteString("| `" + t.Word + "` | " + t.Kind + " | " + t.Meaning + " |\n")
	}
	return b.String()
}
