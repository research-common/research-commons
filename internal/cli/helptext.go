package cli

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The text renderer for help pages. `--json` help is the helpObj / outputsObj object and is untouched by
// anything in this file: the text surface only decides how the same words are laid out (sections, aligned
// columns, wrapping at the terminal width, grouping, examples).

const helpMore = "commons help <command> · commons help outputs (state tokens) · commons help exits (exit codes)"

// termWidth is $COLUMNS when it is a positive integer, else 80, clamped to [60, 120]. The terminal itself is
// never probed, so the same environment always prints the same bytes.
func termWidth(env *Env) int {
	w := 80
	if env != nil && env.Getenv != nil {
		if n, err := strconv.Atoi(strings.TrimSpace(env.Getenv("COLUMNS"))); err == nil && n > 0 {
			w = n
		}
	}
	return min(max(w, 60), 120)
}

func runeLen(s string) int { return utf8.RuneCountInString(s) }

// wrapWords lays words out in lines of at most width columns, the first line starting after first columns
// already used and later lines after rest columns. A word wider than a line stands alone on one.
func wrapWords(words []string, width, first, rest int) []string {
	var lines []string
	var cur strings.Builder
	used := first
	empty := true
	for _, w := range words {
		l := runeLen(w)
		if !empty && used+1+l > width {
			lines = append(lines, cur.String())
			cur.Reset()
			used, empty = rest, true
		}
		if !empty {
			cur.WriteByte(' ')
			used++
		}
		cur.WriteString(w)
		used += l
		empty = false
	}
	return append(lines, cur.String())
}

// wrapText wraps one paragraph; every line carries the indent, the first line the lead in place of it.
func wrapText(text string, width int, lead, indent string) string {
	lines := wrapWords(strings.Fields(text), width, runeLen(lead), runeLen(indent))
	var b strings.Builder
	for i, l := range lines {
		if i == 0 {
			b.WriteString(lead)
		} else {
			b.WriteString(indent)
		}
		b.WriteString(l + "\n")
	}
	return b.String()
}

// wrapTokens is wrapText over tokens that must not be split (a usage line's "[--key <file>]").
func wrapTokens(toks []string, width int, lead, indent string) string {
	lines := wrapWords(toks, width, runeLen(lead), runeLen(indent))
	var b strings.Builder
	for i, l := range lines {
		if i == 0 {
			b.WriteString(lead)
		} else {
			b.WriteString(indent)
		}
		b.WriteString(l + "\n")
	}
	return b.String()
}

// --- paragraphs ---------------------------------------------------------------------------------------------

// helpParas splits a Help string into paragraphs for the text surface only. It cuts at sentence ends and never
// edits a word: strings.Join(helpParas(h), " ") == h, so the JSON description (the unsplit Help) and the text
// say the same thing. A paragraph starts at an exit-code sentence, a "Side effects" or external-signing
// sentence, a bare option sentence, or when the paragraph in progress is already long.
func helpParas(h string) []string {
	var sents []string
	start := 0
	for i := 0; i+2 < len(h); i++ {
		if h[i] == '.' && h[i+1] == ' ' && sentenceStart(h[i+2]) && !abbrevBefore(h[:i+1]) {
			sents = append(sents, h[start:i+1])
			start = i + 2
		}
	}
	sents = append(sents, h[start:])
	var paras []string
	cur := ""
	for _, s := range sents {
		hard := strings.HasPrefix(s, "Exit ") || strings.HasPrefix(s, "Side effects:") ||
			strings.HasPrefix(s, "External signing (") || strings.HasPrefix(s, "--dry-run")
		if cur != "" && (hard || runeLen(cur) >= 420) {
			paras = append(paras, cur)
			cur = ""
		}
		if cur != "" {
			cur += " "
		}
		cur += s
	}
	if cur != "" {
		paras = append(paras, cur)
	}
	return paras
}

func sentenceStart(c byte) bool { return c >= 'A' && c <= 'Z' || c == '-' || c == '`' }

func abbrevBefore(s string) bool {
	for _, a := range []string{"e.g.", "i.e.", "vs.", "etc."} {
		if strings.HasSuffix(s, a) {
			return true
		}
	}
	return false
}

// --- top level ------------------------------------------------------------------------------------------------

// commandGroups lists every registered command in exactly one group (a test holds that); the order here is
// the order of the top-level page.
var commandGroups = []struct {
	Title string
	Names []string
}{
	{"Store", []string{"init", "status", "fsck", "repair", "gc", "history"}},
	{"Read", []string{"list", "show", "explain", "verify"}},
	{"Publish and keys", []string{"publish", "publish task", "publish grant", "key new", "key show", "key sign",
		"package show", "rotate", "revoke"}},
	{"Identity", []string{"identity new", "identity grant", "identity cut"}},
	{"Exchange", []string{"pull", "push", "fetch", "hub check"}},
	{"Run", []string{"run"}},
	{"Anchors", []string{"anchor stamp", "anchor upgrade", "anchor status", "anchor headers sync"}},
}

func commandByName(name string) *Command {
	for _, c := range registry {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func renderTopHelp(width int) string {
	var b strings.Builder
	b.WriteString("Usage:\n  commons <command> [options] [--json]\n")
	label := 0
	for _, c := range registry {
		label = max(label, len(c.Name))
	}
	for _, g := range commandGroups {
		b.WriteString("\n" + g.Title + ":\n")
		var es [][2]string
		for _, n := range g.Names {
			if c := commandByName(n); c != nil {
				es = append(es, [2]string{c.Name, c.Summary})
			}
		}
		columnFixed(&b, "  ", es, label, width) // one label width for the page: the summaries line up
	}
	b.WriteString("\nGlobal options:\n")
	var gl [][2]string
	for _, f := range globalFlags {
		gl = append(gl, [2]string{optLabel(f), f.Help})
	}
	columnFixed(&b, "  ", gl, 13, width)
	b.WriteString("\nMore:\n")
	b.WriteString(wrapText("commons help <command> — the options of one command", width, "  ", "    "))
	b.WriteString(wrapText("commons help outputs — the state tokens a result can carry", width, "  ", "    "))
	b.WriteString(wrapText("commons help exits — the exit codes", width, "  ", "    "))
	return b.String()
}

func optLabel(f Flag) string {
	if f.Value == "" {
		return "--" + f.Name
	}
	return "--" + f.Name + " <" + f.Value + ">"
}

// --- one command ----------------------------------------------------------------------------------------------

// shortUsageOptions is the option count above which the usage line says [options] and the options are listed
// below it instead of in it.
const shortUsageOptions = 6

func usageTokens(c *Command) []string {
	toks := []string{"commons", c.Name}
	if len(c.Flags) > shortUsageOptions {
		toks = append(toks, "[options]")
	} else {
		for _, f := range c.Flags {
			t := "[--" + f.Name
			if f.Value != "" {
				t += " <" + f.Value + ">"
			}
			t += "]"
			if f.Repeat {
				t += "…"
			}
			toks = append(toks, t)
		}
	}
	for _, a := range c.Args {
		x := "<" + a.Name + ">"
		if a.Variadic {
			x += "…"
		}
		if a.Optional {
			x = "[" + x + "]"
		}
		toks = append(toks, x)
	}
	return append(toks, "[--json]")
}

// optionGroups labels the options of the commands that have many. A command listed here has every one of its
// options in exactly one group (a test holds that); a command not listed prints one "Options" list.
var optionGroups = map[string][]struct {
	Title string
	Names []string
}{}

func init() {
	signing := []string{"key", "prev", "ts", "dry-run"}
	external := []string{"prepare", "signer", "complete", "signature"}
	disclosures := []string{"attribution", "availability", "comparator", "description", "extends", "fulfills",
		"intended-for", "licence", "licence-texts", "pre-registration", "replication", "sampling",
		"shelf-life-days", "supersedes"}
	type grp = struct {
		Title string
		Names []string
	}
	optionGroups["publish"] = []grp{
		{"Signing options", signing},
		{"Statement options", []string{"draft", "kind", "content", "media-type", "type", "provenance", "no-holds"}},
		{"Describes and retracts options", []string{"about", "note", "of", "reason"}},
		{"Acting-for-identity options", []string{"as", "grant", "amends"}},
		{"Authored disclosure options", disclosures},
		{"External signing options", external},
	}
	optionGroups["run"] = []grp{
		{"Signing options", signing},
		{"Execution options", []string{"exec-policy", "input", "publish", "request-log"}},
		{"Per-output options (each value is <output>=<value>)", append([]string{"of", "media-type"}, disclosures...)},
	}
	for _, n := range []string{"identity new", "identity grant", "identity cut"} {
		c := commandByName(n)
		if c == nil {
			continue
		}
		var own []string
		skip := map[string]bool{}
		for _, s := range append(append([]string{}, signing...), external...) {
			skip[s] = true
		}
		for _, f := range c.Flags {
			if !skip[f.Name] {
				own = append(own, f.Name)
			}
		}
		gs := []grp{{"Signing options", signing}}
		if len(own) > 0 {
			gs = append(gs, grp{"Identity options", own})
		}
		optionGroups[n] = append(gs, grp{"External signing options", external})
	}
}

func renderCommandHelp(c *Command, width int) string {
	var b strings.Builder
	b.WriteString("Usage:\n")
	b.WriteString(wrapTokens(usageTokens(c), width, "  ", "      "))
	b.WriteString("\n" + wrapText(c.Summary, width, "", ""))
	if c.Help != "" {
		for _, p := range helpParas(c.Help) {
			b.WriteString("\n" + wrapText(p, width, "", ""))
		}
	}
	if len(c.Flags) > 0 {
		label := 0
		for _, f := range c.Flags {
			label = max(label, runeLen(optLabel(f)))
		}
		label = min(label, 24)
		entry := func(name string) [2]string {
			for _, f := range c.Flags {
				if f.Name == name {
					return [2]string{optLabel(f), f.Help}
				}
			}
			return [2]string{"--" + name, ""}
		}
		if gs, ok := optionGroups[c.Name]; ok {
			for _, g := range gs {
				b.WriteString("\n" + g.Title + ":\n")
				var es [][2]string
				for _, n := range g.Names {
					es = append(es, entry(n))
				}
				columnFixed(&b, "  ", es, label, width)
			}
		} else {
			b.WriteString("\nOptions:\n")
			var es [][2]string
			for _, f := range c.Flags {
				es = append(es, [2]string{optLabel(f), f.Help})
			}
			columnFixed(&b, "  ", es, label, width)
		}
	}
	if len(c.Examples) > 0 {
		b.WriteString("\nExamples:\n")
		for _, e := range c.Examples {
			b.WriteString(wrapText(e, width, "  ", "      "))
		}
	}
	return b.String()
}

// columnFixed is column with the label width given, so the groups of one page align with each other.
func columnFixed(b *strings.Builder, indent string, entries [][2]string, l, width int) {
	hang := strings.Repeat(" ", len(indent)+l+2)
	for _, e := range entries {
		if runeLen(e[0]) > l {
			b.WriteString(indent + e[0] + "\n")
			b.WriteString(wrapText(e[1], width, hang, hang))
			continue
		}
		pad := strings.Repeat(" ", l-runeLen(e[0]))
		b.WriteString(wrapText(e[1], width, indent+e[0]+pad+"  ", hang))
	}
}

// --- exits and outputs ------------------------------------------------------------------------------------------

func renderExitsHelp(width int) string {
	var b strings.Builder
	b.WriteString("Exit codes:\n")
	nameW := 0
	for _, r := range ExitRows() {
		nameW = max(nameW, runeLen(r[1]))
	}
	for _, r := range ExitRows() {
		lead := fmt.Sprintf("  %-2s  %-*s  ", r[0], nameW, r[1])
		b.WriteString(wrapText(r[2], width, lead, strings.Repeat(" ", runeLen(lead))))
	}
	return b.String()
}

func renderOutputsHelp(width int) string {
	var b strings.Builder
	b.WriteString("State tokens:\n")
	for i, t := range vocabulary {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(wrapText(t.Word+"  ("+t.Kind+")", width, "  ", "    "))
		b.WriteString(wrapText(t.Meaning, width, "      ", "      "))
	}
	return b.String()
}

// --- error hints ----------------------------------------------------------------------------------------------

func unknownOptionHint(c *Command) string {
	return "run commons help " + c.Name + " to list its options"
}

// unknownCommandHint names the registered command nearest the words given: within edit distance 2 of the first
// one, two or three words, or the one command whose name starts with them (so "hub" finds "hub check").
func unknownCommandHint(words []string) string {
	const generic = "run commons help to list the commands"
	if s := suggestCommand(words); s != "" {
		return "did you mean `commons " + s + "`? " + generic
	}
	return generic
}

func suggestCommand(words []string) string {
	best, bestD := "", 3
	for k := 1; k <= min(3, len(words)); k++ {
		given := strings.Join(words[:k], " ")
		var prefixed []string
		for _, c := range registry {
			if strings.HasPrefix(c.Name, given+" ") {
				prefixed = append(prefixed, c.Name)
			}
			if len(strings.Fields(c.Name)) != k {
				continue
			}
			if d := editDistance(given, c.Name); d <= 2 && d < runeLen(given) && d < bestD {
				best, bestD = c.Name, d
			}
		}
		if len(prefixed) == 1 {
			return prefixed[0]
		}
	}
	return best
}

// editDistance is the Levenshtein distance between a and b in runes.
func editDistance(a, b string) int {
	x, y := []rune(a), []rune(b)
	prev := make([]int, len(y)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(x); i++ {
		cur := make([]int, len(y)+1)
		cur[0] = i
		for j := 1; j <= len(y); j++ {
			cost := 1
			if x[i-1] == y[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(y)]
}
