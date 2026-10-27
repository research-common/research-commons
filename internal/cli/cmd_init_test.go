package cli

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
