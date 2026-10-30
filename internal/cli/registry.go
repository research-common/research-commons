package cli

import (
	"slices"
	"strings"
)

// The command registry. A command is one file in this package that registers itself from init():
//
//	func init() {
//		Register(&Command{Name: "hub check", Summary: "…", Flags: []Flag{{Name: "base", Value: "rev"}},
//			Store: true, Run: hubCheck})
//	}
//
// Everything the outputs contract needs is done here, once, for every command: global flags (--json,
// --store, --help), unknown-option and argument-shape checks, store discovery and the policy file check, all
// before Run is called, so a command cannot start work on an invocation that should exit 2 (claims-model
// note §13, C-core-133a). Run returns one result tree (node.go) and an exit code from the exit table; the
// registry renders it on the human or the JSON surface. A multi-word name ("hub check") is matched by its
// words.

// Shape is what a positional argument must look like; a value of the wrong shape exits 2 before any work.
type Shape int

const (
	// ShapeRef is a content digest ("sha256:" + 64 lowercase hex) or a statement id (64 lowercase hex).
	ShapeRef Shape = iota
	// ShapeDigest is a content digest only.
	ShapeDigest
	// ShapeID is a statement id only.
	ShapeID
	// ShapeText is free text, checked by the command (before any work) if at all.
	ShapeText
)

// Arg is a positional argument.
type Arg struct {
	Name     string
	Shape    Shape
	Optional bool
}

// Flag is a command option. Value names the option's argument ("" for a boolean option).
type Flag struct {
	Name  string
	Value string
	Help  string
	// Check validates the value before any work; an error exits 2 with the value as peer text.
	Check func(string) error
}

// Command is one registered command.
type Command struct {
	Name    string // one or more words
	Summary string
	Args    []Arg
	Flags   []Flag
	// Store: the command reads a store. The registry discovers it, checks its marker and its policy file, and
	// opens it (journal replay, storage note §3.4) before Run.
	Store bool
	// ReaderPolicy: the command answers under the reader policy (--policy <file>, else $COMMONS_POLICY). The
	// registry adds the --policy option and parses the file before Run; a command without it rejects
	// --policy and ignores the environment variable.
	ReaderPolicy bool
	// Writes: the command appends to the store (publish). The read-command sweeps (every Store command run bare
	// or over every fixture ref) skip it: a writer needs a key and its own arguments.
	Writes bool
	// Prepare, when set, runs after argument binding and before store discovery: every check of the
	// invocation's own inputs (key file, draft, content file, policy files it names) belongs here, so a bad
	// input exits 2 before any work (claims-model note §13). It may stash what it read in Ctx.Prep for Run.
	Prepare func(*Ctx) *Problem
	// Help is extra text after the synopsis.
	Help string
	// Before validates the invocation beyond argument shapes (a directory exists, options do not conflict)
	// after the store and policies are checked and before the store is opened: a problem it returns is exit 2
	// with nothing done. It must not write.
	Before func(*Ctx) *Problem
	Run    func(*Ctx) (*Obj, int, error)
}

var registry []*Command

// Register adds a command. It panics on a duplicate name or a flag that shadows a global flag, at init time,
// so a conflicting registration never builds a working binary.
func Register(c *Command) {
	for _, d := range registry {
		if d.Name == c.Name {
			panic("cli: command " + c.Name + " registered twice")
		}
	}
	for _, f := range c.Flags {
		if slices.ContainsFunc(globalFlags, func(g Flag) bool { return g.Name == f.Name }) {
			panic("cli: command " + c.Name + " flag --" + f.Name + " shadows a global flag")
		}
	}
	if c.ReaderPolicy {
		c.Flags = append(c.Flags, readerPolicyFlag)
	}
	registry = append(registry, c)
	slices.SortFunc(registry, func(a, b *Command) int { return strings.Compare(a.Name, b.Name) })
}

// Commands returns every registered command, by name.
func Commands() []*Command { return slices.Clone(registry) }

// lookup finds the command whose words are the longest prefix of words; it returns the number of words used.
func lookup(words []string) (*Command, int) {
	var best *Command
	n := 0
	for _, c := range registry {
		cw := strings.Fields(c.Name)
		if len(cw) > len(words) || len(cw) <= n {
			continue
		}
		if slices.Equal(cw, words[:len(cw)]) {
			best, n = c, len(cw)
		}
	}
	return best, n
}

// globalFlags are accepted by every command, before or after its name.
var globalFlags = []Flag{
	{Name: "json", Help: "print one JSON object on stdout (an RFC 9457 problem-details object on error)"},
	{Name: "store", Value: "dir", Help: "the store to read (default: $COMMONS_STORE, else the nearest ancestor directory holding rc-store)"},
	{Name: "help", Help: "print help for the command and exit 0"},
	{Name: "version", Help: "print the version and exit 0"},
}

func synopsis(c *Command) string {
	s := "commons " + c.Name
	for _, f := range c.Flags {
		if f.Value != "" {
			s += " [--" + f.Name + " <" + f.Value + ">]"
		} else {
			s += " [--" + f.Name + "]"
		}
	}
	for _, a := range c.Args {
		x := "<" + a.Name + ">"
		if a.Optional {
			x = "[" + x + "]"
		}
		s += " " + x
	}
	return s + " [--json]"
}
