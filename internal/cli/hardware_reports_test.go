package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/wire"
)

// docs/HARDWARE-COMPATIBILITY.md is generated from the report files in docs/hardware-reports/. This test checks
// every report's shape, verifies the signed line a report may carry as evidence, and fails when the page is not
// the generated one. Regenerate with RC_UPDATE_DOCS=1 go test -run TestHardwareReports ./internal/cli.

var hwSteps = []string{"read", "sign", "reject", "timeout", "disconnect", "size", "revoke", "rotate"}

type hwReport struct {
	id, date, by, source                     string
	vendor, model, firmware, app, appVersion string
	emulator                                 bool
	os, arch, toolVersion, toolCommit        string
	route, alg                               string
	steps                                    map[string]string
	notes, links                             []string
	evidence                                 string
}

func hwStr(t *testing.T, file string, o *canon.Object, k string) string {
	t.Helper()
	v, ok := o.Get(k)
	s, isStr := v.(canon.String)
	if !ok || !isStr || strings.TrimSpace(string(s)) == "" || strings.ContainsAny(string(s), "|\n") {
		t.Fatalf("%s: %q must be a non-empty string without | or a line break", file, k)
	}
	return string(s)
}

func hwObj(t *testing.T, file string, o *canon.Object, k string, members ...string) *canon.Object {
	t.Helper()
	v, _ := o.Get(k)
	c, ok := v.(*canon.Object)
	if !ok {
		t.Fatalf("%s: %q must be an object", file, k)
	}
	hwOnly(t, file, k, c, members...)
	return c
}

func hwOnly(t *testing.T, file, where string, o *canon.Object, members ...string) {
	t.Helper()
	for _, k := range o.Keys {
		if !contains(members, k) {
			t.Fatalf("%s: unknown member %q in %s", file, k, where)
		}
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func hwList(t *testing.T, file string, o *canon.Object, k string) []string {
	t.Helper()
	v, ok := o.Get(k)
	if !ok {
		return nil
	}
	a, isArr := v.(canon.Array)
	if !isArr {
		t.Fatalf("%s: %q must be a list of strings", file, k)
	}
	var out []string
	for _, e := range a {
		s, isStr := e.(canon.String)
		if !isStr || s == "" {
			t.Fatalf("%s: %q must be a list of non-empty strings", file, k)
		}
		out = append(out, string(s))
	}
	return out
}

var hwID = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*-\d{4}-\d{2}-\d{2}$`)

func loadHardwareReports(t *testing.T, root string) []hwReport {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(root, "docs", "hardware-reports", "*.json"))
	sort.Strings(files)
	var out []hwReport
	for _, f := range files {
		name := filepath.Base(f)
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		v, err := canon.Parse(b)
		top, ok := v.(*canon.Object)
		if err != nil || !ok {
			t.Fatalf("%s: not one JSON object: %v", name, err)
		}
		hwOnly(t, name, "the report", top, "format", "id", "date", "by", "source", "device", "host", "tool", "route", "alg", "steps", "notes", "links", "evidence")
		r := hwReport{steps: map[string]string{}}
		if hwStr(t, name, top, "format") != "hardware-report/1" {
			t.Fatalf("%s: format must be hardware-report/1", name)
		}
		r.id, r.date, r.by, r.source = hwStr(t, name, top, "id"), hwStr(t, name, top, "date"), hwStr(t, name, top, "by"), hwStr(t, name, top, "source")
		if r.id+".json" != name || !hwID.MatchString(r.id) || !strings.HasSuffix(r.id, r.date) {
			t.Fatalf("%s: the file name must be <id>.json, and the id lowercase and ending in the report's date", name)
		}
		if r.source != "maintainer" && r.source != "contributor" {
			t.Fatalf("%s: source must be maintainer or contributor", name)
		}
		d := hwObj(t, name, top, "device", "vendor", "model", "emulator", "firmware", "app", "app_version")
		r.vendor, r.model, r.firmware = hwStr(t, name, d, "vendor"), hwStr(t, name, d, "model"), hwStr(t, name, d, "firmware")
		r.app, r.appVersion = hwStr(t, name, d, "app"), hwStr(t, name, d, "app_version")
		em, _ := d.Get("emulator")
		eb, isBool := em.(canon.Bool)
		if !isBool {
			t.Fatalf("%s: device.emulator must be true or false", name)
		}
		r.emulator = bool(eb)
		h := hwObj(t, name, top, "host", "os", "arch")
		r.os, r.arch = hwStr(t, name, h, "os"), hwStr(t, name, h, "arch")
		tl := hwObj(t, name, top, "tool", "version", "commit")
		r.toolVersion, r.toolCommit = hwStr(t, name, tl, "version"), hwStr(t, name, tl, "commit")
		r.route, r.alg = hwStr(t, name, top, "route"), hwStr(t, name, top, "alg")
		if r.route != "connector" && r.route != "package" {
			t.Fatalf("%s: route must be connector or package", name)
		}
		if r.alg != "ed25519" && r.alg != "eip191-secp256k1" {
			t.Fatalf("%s: alg must be ed25519 or eip191-secp256k1", name)
		}
		st := hwObj(t, name, top, "steps", hwSteps...)
		for _, k := range hwSteps {
			r.steps[k] = hwStr(t, name, st, k)
			if !contains([]string{"pass", "fail", "not-run", "n/a"}, r.steps[k]) {
				t.Fatalf("%s: steps.%s must be pass, fail, not-run or n/a", name, k)
			}
			if r.steps[k] == "fail" && len(hwList(t, name, top, "notes")) == 0 {
				t.Fatalf("%s: a failed step needs a note saying what happened", name)
			}
		}
		r.notes, r.links = hwList(t, name, top, "notes"), hwList(t, name, top, "links")
		for _, l := range r.links {
			if !strings.HasPrefix(l, "https://") {
				t.Fatalf("%s: links must be https URLs", name)
			}
		}
		if _, has := top.Get("evidence"); has {
			r.evidence = hwStr(t, name, hwObj(t, name, top, "evidence", "line"), "line")
			// the reader every store uses: the line must be valid, with a signature that verifies, under the report's algorithm
			s, err := wire.ReadStored([]byte(r.evidence))
			if err != nil || s.Status != wire.Valid || !s.Verified || s.Alg != r.alg {
				t.Fatalf("%s: evidence.line is not a valid signed statement under %s: %v", name, r.alg, err)
			}
		}
		out = append(out, r)
	}
	return out
}

func TestHardwareReports(t *testing.T) {
	root, err := conformance.RepoRoot()
	if err != nil {
		t.Fatal(err)
	}
	reports := loadHardwareReports(t, root)
	if len(reports) == 0 {
		t.Fatal("no report files in docs/hardware-reports")
	}
	p := filepath.Join(root, "docs", "HARDWARE-COMPATIBILITY.md")
	want := hardwareMarkdown(reports)
	if os.Getenv("RC_UPDATE_DOCS") == "1" {
		os.WriteFile(p, []byte(want), 0o644)
	}
	if got, err := os.ReadFile(p); err != nil || string(got) != want {
		t.Fatal("docs/HARDWARE-COMPATIBILITY.md is not the generated page; run RC_UPDATE_DOCS=1 go test -run TestHardwareReports ./internal/cli")
	}
	// a tampered evidence line must be refused: the check above is not a formality
	for _, r := range reports {
		if r.evidence == "" {
			continue
		}
		bad := strings.Replace(r.evidence, `"seq":0`, `"seq":1`, 1)
		if s, err := wire.ReadStored([]byte(bad)); bad == r.evidence || (err == nil && s.Verified && s.Status == wire.Valid) {
			t.Fatalf("%s: an altered evidence line still verifies", r.id)
		}
	}
}

func hardwareMarkdown(reports []hwReport) string {
	var b strings.Builder
	b.WriteString(hardwareIntro)
	b.WriteString("| device | firmware, app | host | key kind | route | tool | " + strings.Join(hwSteps, " | ") + " | evidence | by | report |\n")
	b.WriteString("|---|---|---|---|---|---|" + strings.Repeat("---|", len(hwSteps)) + "---|---|---|\n")
	sorted := append([]hwReport(nil), reports...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, c := sorted[i], sorted[j]
		ka := fmt.Sprint(a.vendor, a.model, a.emulator, a.alg, a.date)
		kc := fmt.Sprint(c.vendor, c.model, c.emulator, c.alg, c.date)
		return ka < kc
	})
	show := map[string]string{"pass": "pass", "fail": "**FAIL**", "not-run": "not run", "n/a": "n/a"}
	for _, r := range sorted {
		dev := r.vendor + " " + r.model
		if r.emulator {
			dev += " (emulator)"
		}
		fw := "firmware " + r.firmware + "; " + r.app + " " + r.appVersion
		by := r.by
		if r.source == "contributor" {
			by += " (reported)"
		}
		ev := "none"
		if r.evidence != "" {
			ev = "signed line, verified"
		}
		b.WriteString("| " + dev + " | " + fw + " | " + r.os + " " + r.arch + " | `" + r.alg + "` | " + r.route + " | " + r.toolVersion + " `" + r.toolCommit + "` |")
		for _, k := range hwSteps {
			b.WriteString(" " + show[r.steps[k]] + " |")
		}
		b.WriteString(" " + ev + " | " + by + ", " + r.date + " | [file](hardware-reports/" + r.id + ".json) |\n")
	}
	b.WriteString(hardwareRest)
	return b.String()
}

const hardwareIntro = `# Hardware compatibility

Generated from the report files in ` + "`docs/hardware-reports/`" + ` by
` + "`RC_UPDATE_DOCS=1 go test -run TestHardwareReports ./internal/cli`" + `. Do not edit by hand: add a report file.

This page records what people have **observed** when signing with a hardware device. It is not a list of
supported devices: what the tool supports, and what it does not do yet, is in
[` + "`KNOWN-LIMITS.md`" + `](KNOWN-LIMITS.md). A row says that one person ran the steps below on one device, firmware
and host, with one build of the tool, on one day.

No hardware is needed to use the tool. Every command works with a key file.

**Reports are wanted**, for any device, firmware or host not listed, and for a listed one with a newer build.
A report that something fails is worth as much as one that it works.

## What has been observed

`

const hardwareRest = `
How to read a row:

- **route**: ` + "`connector`" + ` means the tool talked to the device itself (` + "`--ledger`" + `). ` + "`package`" + ` means the tool wrote
  a signing package, something else had the device sign it, and the tool completed it.
- **by**: "(reported)" marks a report from a contributor that the maintainers have not repeated.
- **evidence**: "signed line, verified" means the report carries a statement the device signed, and the test
  behind this page verified its signature. That proves a key signed with the tool's format. It cannot prove
  which device or firmware held the key: that part is the reporter's word.
- A step that does not apply to a route or a device reads n/a. The notes in the report file say why.

## Not yet observed

Reports for these would fill the largest gaps:

- Ledger Nano S Plus, Flex and Stax as hardware (the Nano S Plus row above is the emulator).
- A Ledger on macOS or Windows. The USB connector is built for Linux only (L-20).
- Ethereum app versions other than 1.19.3 on hardware.
- A rejection of a ` + "`revoke`" + ` or ` + "`rotate`" + ` request on hardware.
- YubiKey firmware 5.7 or later, and the PIV applet.
- Any other device that can produce an Ed25519 or an EIP-191 secp256k1 signature over bytes the tool prepares.

## Before you test

- **Use a key that holds nothing and means nothing.** On a Ledger, a throwaway passphrase or an account number
  you use for nothing else. On a card, an empty slot. Never overwrite a slot that holds a key.
- **Work in a new, empty store** (` + "`commons init`" + ` in a new directory). Nothing in the drill needs a hub.
- **Do not post** serial numbers, or an address or key that you use for anything else.
- The drill signs a ` + "`revoke_key`" + ` and a ` + "`rotate_key`" + ` for the throwaway keys. That is the point of those steps.

## The drill for a device with a connector (Ledger)

Use two paths you use for nothing else, for example ` + "`m/44'/60'/7'/0/0`" + ` and ` + "`m/44'/60'/8'/0/0`" + `, written
` + "`<path>`" + ` and ` + "`<path2>`" + ` below. Open the Ethereum app on the device first.

| step | run | pass when |
|---|---|---|
| read | ` + "`commons key show --ledger --ledger-path <path>`" + ` | exit 0, and it prints the app, its version and a signer; call the signer ` + "`<signer>`" + ` |
| sign | ` + "`commons identity new --prepare i.pkg --signer <signer>`" + `, then ` + "`commons key sign --package i.pkg --ledger --ledger-path <path> --out i.sig`" + ` and approve on the device, then ` + "`commons identity new --complete i.pkg --signature i.sig`" + `, then ` + "`commons fsck`" + ` | every command exits 0 and ` + "`fsck`" + ` reports clean |
| reject | the same ` + "`key sign`" + ` with ` + "`--out r.sig`" + `, rejected on the device | exit 1, and ` + "`r.sig`" + ` does not exist |
| timeout | the same ` + "`key sign`" + ` with ` + "`--ledger-timeout 5s --out t.sig`" + `, left alone; afterwards reject the review on the device | exit 3 saying the device did not answer in time, and ` + "`t.sig`" + ` does not exist |
| disconnect | the same ` + "`key sign`" + ` with ` + "`--out u.sig`" + `; unplug the device while the review is on its screen | exit 3, and ` + "`u.sig`" + ` does not exist |
| size | ` + "`commons revoke --ledger --ledger-path <path> --expect-signer <signer> --reason key_compromise --last-good none --note <text>`" + `, once with 7,000 characters of text (reject it on the device) and once with 8,000 | the first is offered for review; the second exits 3 before any review; ` + "`fsck`" + ` still clean. If your device differs, say at what size |
| revoke | the same ` + "`revoke`" + ` without ` + "`--note`" + `, first with ` + "`--dry-run`" + `, then for real and approved | the dry run exits 0 and asks for no approval; the real one exits 0 and ` + "`fsck`" + ` is clean |
| rotate | ` + "`commons key new --out succ.key`" + `, read the signer at ` + "`<path2>`" + `, then ` + "`commons rotate --ledger --ledger-path <path2> --expect-signer <that signer> --successor <the new key's signer>`" + `, approved | exit 0 and ` + "`fsck`" + ` is clean |

After a step that leaves a review on the device, finish or reject it there before the next command.

## A device without a connector

A device the tool cannot talk to can still be reported through the package route: ` + "`--prepare`" + ` writes the
bytes to sign, your own program has the device sign them, and ` + "`--complete`" + ` verifies and commits. Only the
sign and size steps apply; the others read n/a. Say in the notes what drove the device, and link to the
script. If the device has no screen, say so: the only review is then ` + "`commons package show`" + ` on the host.

## Sending a report

Copy a file in [` + "`hardware-reports/`" + `](hardware-reports/), change it, and open a pull request with it and
the regenerated page. If you would rather not open a pull request, open an issue with the same fields and
a maintainer will add the file, marked as reported.

The fields:

| field | meaning |
|---|---|
| ` + "`format`" + ` | ` + "`hardware-report/1`" + ` |
| ` + "`id`" + ` | the file's name without ` + "`.json`" + `: lowercase, ending in the date |
| ` + "`date`" + `, ` + "`by`" + ` | the day of the run, and a name to credit (a GitHub handle is fine) |
| ` + "`source`" + ` | ` + "`contributor`" + `; a maintainer changes it to ` + "`maintainer`" + ` only after repeating the run |
| ` + "`device`" + ` | ` + "`vendor`" + `, ` + "`model`" + `, ` + "`emulator`" + ` (true or false), ` + "`firmware`" + `, ` + "`app`" + `, ` + "`app_version`" + `; write "not recorded" for what you do not know |
| ` + "`host`" + ` | ` + "`os`" + ` and ` + "`arch`" + ` |
| ` + "`tool`" + ` | ` + "`version`" + ` and ` + "`commit`" + `, both from ` + "`commons --version`" + ` |
| ` + "`route`" + `, ` + "`alg`" + ` | ` + "`connector`" + ` or ` + "`package`" + `; ` + "`ed25519`" + ` or ` + "`eip191-secp256k1`" + ` |
| ` + "`steps`" + ` | one of ` + "`pass`" + `, ` + "`fail`" + `, ` + "`not-run`" + `, ` + "`n/a`" + ` for each of the eight steps |
| ` + "`notes`" + ` | what differed, sizes, status words. Required when a step failed |
| ` + "`links`" + ` | an issue or a script, optional |
| ` + "`evidence.line`" + ` | optional: the inception the device signed in the sign step, copied whole from the one file under ` + "`statements/<signer>/`" + ` at that point |

The test behind this page refuses a report with a missing or unknown field, and verifies ` + "`evidence.line`" + ` with
the reader every store uses. A report whose line does not verify is not merged.

## Keeping it current

Each row is dated and names the build it was run with. A row for an old build is not wrong; it is old.
A new run is a new file: old files are not edited, so the page keeps its history. A release that changes
a connector is the time to run the drill again.
`
