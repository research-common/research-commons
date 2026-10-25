package cli

import "strconv"

// Exit codes (claims-model note §13). One table: Exit codes, their names and their meanings come from here,
// and so does the documented table (`commons help exits`, docs/CLI-OUTPUTS.md). Every code is below 64, so
// none collides with the shell's reserved values (126, 127, 128+n).
const (
	ExitOK          = 0
	ExitWrong       = 1
	ExitDidNotStart = 2
	ExitCouldNot    = 3
	ExitNothing     = 4
	ExitEnvironment = 5
)

// exitTable is the one source of exit codes.
var exitTable = []struct {
	Code    int
	Name    string
	Meaning string
}{
	{ExitOK, "ok", "the requested operation succeeded; for verify, checked and passed. Not a claim that everything referenced is valid"},
	{ExitWrong, "checked and wrong", "a comparison ran to completion and disagreed (verify only)"},
	{ExitDidNotStart, "did not start", "the invocation or the reader's own configuration could not be acted on: unknown option, malformed argument, unreadable or unparseable policy, no store. Nothing ran and nothing was committed"},
	{ExitCouldNot, "could not check", "contested, unknown, unchecked, unpinned, unsupported, an optional capability not configured, a reader limit, or a failure after work started"},
	{ExitNothing, "nothing to re-run", "the derivation names an input it did not pin"},
	{ExitEnvironment, "environment mismatch", "the declared environment differs from, or is not available in, the one that ran"},
}

// ExitName is the name of an exit code; it panics on a code not in the table, so no surface can return one.
func ExitName(code int) string {
	for _, r := range exitTable {
		if r.Code == code {
			return r.Name
		}
	}
	panic("cli: exit code " + strconv.Itoa(code) + " is not in the exit table")
}

// ExitRows is the table as (code, name, meaning) rows, in order.
func ExitRows() [][3]string {
	out := make([][3]string, 0, len(exitTable))
	for _, r := range exitTable {
		out = append(out, [3]string{strconv.Itoa(r.Code), r.Name, r.Meaning})
	}
	return out
}
