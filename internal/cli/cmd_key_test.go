package cli

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/wire"
)

// newKeyFile runs `key new` into dir and returns the path and the signer it printed.
func newKeyFile(t *testing.T, dir, alg string) (string, string) {
	t.Helper()
	p := filepath.Join(dir, alg+".key")
	r := runIn(dir, nil, "key", "new", "--out", p, "--alg", alg, "--json")
	if r.code != 0 {
		t.Fatalf("key new: %d %s%s", r.code, r.stdout, r.stderr)
	}
	return p, string(jsonOf(t, r).Members["signer"].(canon.String))
}

// secretOf reads the hex secret back out of a key file (the test may; no command does).
func secretOf(t *testing.T, path string) string {
	b, _ := os.ReadFile(path)
	v, _ := canon.Parse([]byte(strings.TrimSpace(string(b))))
	o := v.(*canon.Object)
	for _, k := range []string{"seed", "scalar"} {
		if s, ok := o.Members[k].(canon.String); ok {
			return string(s)
		}
	}
	t.Fatal("no secret")
	return ""
}

// TestKeyNewShow: first-run key generation. Both algorithms; mode 0600; never overwritten; no directory
// created; key show recomputes the signer; the file's signer signs a statement that verifies.
func TestKeyNewShow(t *testing.T) {
	dir := t.TempDir()
	for _, alg := range []string{wire.AlgEd25519, wire.AlgEIP191} {
		p, signer := newKeyFile(t, dir, alg)
		fi, _ := os.Stat(p)
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s: mode %v", alg, fi.Mode())
		}
		before, _ := os.ReadFile(p)
		if r := runIn(dir, nil, "key", "new", "--out", p, "--alg", alg, "--json"); r.code != 2 || !strings.Contains(r.stdout, "never overwritten") {
			t.Fatalf("%s: overwrite: %d %s", alg, r.code, r.stdout)
		}
		if after, _ := os.ReadFile(p); string(after) != string(before) {
			t.Fatal("key file changed by a refused key new")
		}
		r := runIn(dir, nil, "key", "show", p, "--json")
		if r.code != 0 || string(jsonOf(t, r).Members["signer"].(canon.String)) != signer {
			t.Fatalf("%s: key show: %d %s", alg, r.code, r.stdout)
		}
		lk, prob := loadKey(p, "test")
		if prob != nil {
			t.Fatal(prob)
		}
		st, err := wire.Write(wire.Draft{Kind: "retracts", TS: "2026-10-16T00:00:00Z", Body: obj("of", strings.Repeat("ab", 32))}, lk.Key, time.Now())
		if err != nil || !st.Verified || st.Signer != signer {
			t.Fatalf("%s: signing with the file's key: %v", alg, err)
		}
	}
	// the directory must exist; nothing is created
	missing := filepath.Join(dir, "nope", "k.key")
	if r := runIn(dir, nil, "key", "new", "--out", missing, "--json"); r.code != 2 {
		t.Fatalf("missing dir: %d", r.code)
	}
	if _, err := os.Stat(filepath.Dir(missing)); err == nil {
		t.Fatal("key new created a directory")
	}
	if r := runIn(dir, nil, "key", "new", "--json"); r.code != 2 {
		t.Fatal("key new without --out")
	}
	if r := runIn(dir, nil, "key", "new", "--out", filepath.Join(dir, "x"), "--alg", "rsa", "--json"); r.code != 2 {
		t.Fatal("unknown alg accepted")
	}
}

// TestKeyCustody: a group- or world-readable key file, a symlink, and malformed files are refused before any
// work, exit 2; no output of any key-touching command, success or failure, contains the secret.
func TestKeyCustody(t *testing.T) {
	dir := t.TempDir()
	p, _ := newKeyFile(t, dir, wire.AlgEd25519)
	q, _ := newKeyFile(t, dir, wire.AlgEIP191)
	secrets := []string{secretOf(t, p), secretOf(t, q)}
	var outs []string
	run := func(env map[string]string, args ...string) result {
		r := runIn(dir, env, args...)
		outs = append(outs, r.stdout+r.stderr)
		return r
	}
	w := fixture(t)
	content := filepath.Join(dir, "c.txt")
	os.WriteFile(content, []byte("custody"), 0o644)
	publish := func(env map[string]string, extra ...string) result {
		args := append([]string{"publish", "--store", w.root, "--kind", "authored", "--content", content, "--json"}, extra...)
		return run(env, args...)
	}
	run(nil, "key", "show", p)
	run(nil, "key", "show", q, "--json")
	if r := publish(nil, "--key", p, "--dry-run"); r.code != 0 {
		t.Fatalf("dry run: %d %s", r.code, r.stdout)
	}
	// no key named: exit 2, pointing at key new
	if r := publish(nil); r.code != 2 || !strings.Contains(r.stdout, "commons key new --out") {
		t.Fatalf("no key: %d %s", r.code, r.stdout)
	}
	// COMMONS_KEY is the only other source
	if r := publish(map[string]string{KeyEnv: p}, "--dry-run"); r.code != 0 {
		t.Fatalf("env key: %d %s", r.code, r.stdout)
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o660} {
		os.Chmod(p, mode)
		if r := publish(nil, "--key", p); r.code != 2 || !strings.Contains(r.stdout, "chmod 600") {
			t.Fatalf("mode %v: %d %s", mode, r.code, r.stdout)
		}
		if r := run(nil, "key", "show", p, "--json"); r.code != 2 {
			t.Fatalf("key show mode %v: %d", mode, r.code)
		}
	}
	os.Chmod(p, 0o600)
	link := filepath.Join(dir, "link.key")
	os.Symlink(p, link)
	if r := run(nil, "key", "show", link, "--json"); r.code != 2 || !strings.Contains(r.stdout, "not a regular file") {
		t.Fatalf("symlink: %d %s", r.code, r.stdout)
	}
	// malformed: the content is never echoed, whatever is wrong with it
	sec := secrets[0]
	for i, body := range []string{
		sec,
		`{"alg":"ed25519","format":"rc-key/0","seed":"` + sec[:62] + `"}`,
		`{"alg":"ed25519","format":"rc-key/0","seed":"` + strings.ToUpper(sec) + `"}`,
		`{"alg":"ed25519","format":"rc-key/0","seed":"` + sec + `","extra":1}`,
		`{"alg":"eip191-secp256k1","format":"rc-key/0","seed":"` + sec + `"}`,
		`{"alg":"eip191-secp256k1","format":"rc-key/0","scalar":"` + strings.Repeat("f", 64) + `"}`,
		`{"alg":"ed25519","format":"rc-key/1","seed":"` + sec + `"}`,
		`{"alg":"ed25519","format":"rc-key/0","seed":"` + sec + `"`,
	} {
		bad := filepath.Join(dir, "bad"+string(rune('a'+i))+".key")
		os.WriteFile(bad, []byte(body), 0o600)
		if r := run(nil, "key", "show", bad, "--json"); r.code != 2 || !strings.Contains(r.stdout, "not shown") {
			t.Fatalf("malformed %d: %d %s", i, r.code, r.stdout)
		}
		if r := publish(nil, "--key", bad); r.code != 2 {
			t.Fatalf("publish with malformed %d: %d", i, r.code)
		}
	}
	for _, o := range outs {
		for _, s := range secrets {
			if strings.Contains(strings.ToLower(o), s) || strings.Contains(o, hex.EncodeToString([]byte(s))[:32]) {
				t.Fatalf("key material in output:\n%s", o)
			}
		}
	}
}
