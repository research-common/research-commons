//go:build sandbox_oci

// `commons run` on the OCI sandbox runner against a real container runtime, through the binary's bridge
// (Sandbox()). Not part of `go test ./...`: run with
//
//	RC_TEST_IMAGE=alpine:latest go test -tags sandbox_oci -run OCI -v ./internal/clirun
//
// The image must already be held by the runtime (it is never pulled) and provide `sh`.

package clirun

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/cli"
	"github.com/research-common/research-commons/internal/run"
)

// ociImage is the test image as the runtime holds it, or a skip.
func ociImage(t *testing.T) run.Image {
	t.Helper()
	ref := os.Getenv("RC_TEST_IMAGE")
	if ref == "" {
		t.Skip("RC_TEST_IMAGE is not set")
	}
	o := &run.OCI{}
	if err := o.Available(context.Background()); err != nil {
		t.Skip("no OCI runtime: " + err.Error())
	}
	dg, _, err := o.Image(context.Background(), run.Image{Reference: ref})
	if err != nil {
		t.Skip("image not held: " + err.Error())
	}
	return run.Image{Reference: ref, Digest: dg}
}

// TestOCIRunPublish: `run` and `run --publish` on the OCI sandbox through the binary's bridge, with a pinned input
// and an unpinned one supplied with --input. The step reads both from /in and writes their concatenation; the
// printed run is completed with a measured record naming the oci boundary; --publish commits an authored (partial
// provenance, the supplied bytes by digest) and the runner's holds, and the store holds the output bytes.
func TestOCIRunPublish(t *testing.T) {
	img := ociImage(t)
	table := []byte("pinned table\n")
	script := []byte("cat /in/feed /in/table > \"$OUT_DIR/result.txt\"\n")
	w := newRunWorldCode(t, script, "", [][]byte{table},
		"image", object("reference", canon.String(img.Reference), "digest", canon.String(img.Digest)),
		"resources", object("memory", canon.Int(64<<20), "wall_time", canon.Int(30_000)),
		"inputs", object("feed", canon.String("registry.example/feed:latest"), "table", canon.String(run.Digest(table))),
		"outputs", object("result", canon.String("result.txt")))
	feed := filepath.Join(t.TempDir(), "feed")
	os.WriteFile(feed, []byte("tag bytes\n"), 0o644)
	runOCI := func(args ...string) result {
		var o, e strings.Builder
		env := &cli.Env{Stdout: &o, Stderr: &e, Getenv: func(string) string { return "" }, Getwd: func() (string, error) { return w.root, nil },
			Build: cli.Build{Version: "test", Commit: "0000000"}, Exec: Sandbox()}
		code := cli.Main(append([]string{"run", "--json", w.spec, "--exec-policy", w.policy}, args...), env)
		return result{code, o.String() + e.String()}
	}
	want(t, "not supplied", runOCI(), 3, `"ran":false`, run.ReasonNotSupplied)
	out := run.Digest([]byte("tag bytes\npinned table\n"))
	want(t, "run", runOCI("--input", "feed="+feed), 0, `"ran":true`, `"completed":true`, `"boundary":"sandbox: oci, image `+img.Digest,
		`"profile":"sandbox"`, out, `"published":false`)
	want(t, "run --publish", runOCI("--input", "feed="+feed, "--publish", "--key", w.key), 0, `"committed":true`, `"kind":"authored"`, `"kind":"holds"`)
	au := w.statements("authored")
	if len(au) != 1 || member(au[0].Body, "content", "digest") != canon.String(out) ||
		member(au[0].Body, "provenance_partial", "supplied", "feed") != canon.String(run.Digest([]byte("tag bytes\n"))) ||
		member(au[0].Body, "provenance_partial", "environment", "peak_rss_bytes") == nil {
		t.Fatalf("authored: %d", len(au))
	}
	if h := w.statements("holds"); len(h) != 1 || member(h[0].Body, "content", "digest") != canon.String(out) {
		t.Fatal("no holds for the output")
	}
	if r := w.cmd("show", out, "--json"); r.code != 0 || !strings.Contains(r.stdout, "held here") {
		t.Fatalf("the output bytes are not held: %d %s", r.code, r.stdout)
	}
}
