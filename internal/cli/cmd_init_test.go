package cli

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/store"
)

// TestInitPublishShow: init creates a store, publish writes to it, show reads it back.
func TestInitPublishShow(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "mystore")
	r := runIn(base, nil, "init", dir, "--json")
	if r.code != 0 || !strings.Contains(r.stdout, "commons key new --out") {
		t.Fatalf("init: %d %s", r.code, r.stdout)
	}
	if err := store.CheckMarker(dir); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "rc-store")); strings.TrimSpace(string(b)) != `{"layout":"rc-store/1"}` {
		t.Fatalf("marker %q", b)
	}
	// idempotent
	before := snapshot(t, dir)
	r = runIn(base, nil, "init", dir)
	if r.code != 0 || !strings.Contains(r.stdout, "already a store") || snapshot(t, dir) != before {
		t.Fatalf("second init: %d %s", r.code, r.stdout)
	}
	// no argument: the working directory
	empty := t.TempDir()
	if r := runIn(empty, nil, "init"); r.code != 0 || store.CheckMarker(empty) != nil {
		t.Fatalf("init in wd: %d %s", r.code, r.stdout)
	}
	// publish then show
	kd := t.TempDir()
	key, _ := newKeyFile(t, kd, "ed25519")
	content := filepath.Join(kd, "c")
	os.WriteFile(content, []byte("hello"), 0o644)
	r = runIn(dir, nil, "publish", "--key", key, "--kind", "authored", "--content", content, "--json")
	if r.code != 0 {
		t.Fatalf("publish: %d %s", r.code, r.stdout)
	}
	o := jsonOf(t, r)
	_ = o
	r = runIn(dir, nil, "show", "sha256:"+fmt.Sprintf("%x", sha256.Sum256([]byte("hello"))), "--json")
	if r.code != 0 {
		t.Fatalf("show: %d %s", r.code, r.stdout)
	}
}

func TestInitRefuses(t *testing.T) {
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "x"), []byte("x"), 0o644)
	r := runIn(d, nil, "init", d)
	if r.code != 2 {
		t.Fatalf("non-empty: %d %s", r.code, r.stdout)
	}
	if ents, _ := os.ReadDir(d); len(ents) != 1 {
		t.Fatal("init wrote into a refused directory")
	}
	other := t.TempDir()
	os.WriteFile(filepath.Join(other, "rc-store"), []byte(`{"layout":"rc-store/9"}`), 0o644)
	if r := runIn(other, nil, "init", other); r.code != 2 {
		t.Fatalf("other layout: %d", r.code)
	}
	if r := runIn(d, nil, "init", filepath.Join(d, "x")); r.code != 2 {
		t.Fatalf("file: %d", r.code)
	}
}

// TestFirstRunNoKey: every signing command with no key exits 2, changes nothing, and tells the user to run
// commons key new --out <file> and give --key or COMMONS_KEY; so does init's own output.
func TestFirstRunNoKey(t *testing.T) {
	conformance.Partial(t, "C-core-108", "the CLI half: no signing command generates a key implicitly (publish, publish task, gc --release exit 2 and point at commons key new); push does not exist as a command, so the refusal of an unsigned draft at push stays with the gate test")
	p := newPubWorld(t)
	c := p.file("c", "bytes")
	ct := p.file("ct.json", `{}`)
	before := snapshot(t, p.root)
	for _, args := range [][]string{
		{"publish", "--kind", "authored", "--content", c},
		{"publish", "task", "--name", "t", "--contract", ct},
		{"gc", "--release", dig("sole")},
	} {
		r := runIn(p.root, nil, append(args, "--json")...)
		if r.code != 2 || snapshot(t, p.root) != before {
			t.Fatalf("%v: exit %d %s", args, r.code, r.stdout)
		}
		o := jsonOf(t, r)
		var text string
		for _, k := range []string{"detail", "next"} {
			if s, ok := o.Members[k].(canon.String); ok {
				text += string(s) + " "
			}
		}
		if !strings.Contains(text, "commons key new --out <file>") || !strings.Contains(text, "--key") || !strings.Contains(text, KeyEnv) {
			t.Fatalf("%v: no first-run guidance: %s", args, text)
		}
	}
	r := runIn(t.TempDir(), nil, "init", filepath.Join(t.TempDir(), "s"))
	if !strings.Contains(r.stdout, "commons key new --out <file>") || !strings.Contains(r.stdout, "--key <file>") || !strings.Contains(r.stdout, KeyEnv) {
		t.Fatalf("init output: %s", r.stdout)
	}
}

// TestStatusKey: status says whether COMMONS_KEY names a loadable key (the signer only, never key material).
func TestStatusKey(t *testing.T) {
	w := newWorld(t)
	kd := t.TempDir()
	key, signer := newKeyFile(t, kd, "ed25519")
	secret := ""
	if b, err := os.ReadFile(key); err == nil {
		secret = string(b[strings.Index(string(b), `"seed":"`)+8:][:64])
	}
	r := runIn(w.root, map[string]string{KeyEnv: key}, "status", "--json")
	if r.code != 0 || !strings.Contains(r.stdout, `"configured":true`) || !strings.Contains(r.stdout, signer) || strings.Contains(r.stdout, secret) {
		t.Fatalf("configured: %d %s", r.code, r.stdout)
	}
	r = runIn(w.root, nil, "status", "--json")
	if r.code != 0 || !strings.Contains(r.stdout, `"configured":false`) {
		t.Fatalf("unset: %d %s", r.code, r.stdout)
	}
	bad := filepath.Join(kd, "bad")
	os.WriteFile(bad, []byte("not a key"), 0o600)
	r = runIn(w.root, map[string]string{KeyEnv: bad}, "status", "--json")
	if r.code != 0 || !strings.Contains(r.stdout, `"configured":false`) || strings.Contains(r.stdout, "not a key\"") {
		t.Fatalf("unusable: %d %s", r.code, r.stdout)
	}
}
