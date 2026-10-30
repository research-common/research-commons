// Command commons is the Research Commons tool. All logic lives in internal/cli; this is the process
// boundary only: it wires the one execution bridge (internal/clirun) that `verify --rerun` calls.
package main

import (
	"os"

	"github.com/research-common/research-commons/internal/cli"
	"github.com/research-common/research-commons/internal/clirun"
)

// Set at link time: go build -ldflags "-X main.version=0.5.0-alpha.1 -X main.commit=$(git rev-parse HEAD)".
var version, commit string

func main() {
	env := cli.OSEnv(cli.Build{Version: version, Commit: commit})
	// The OCI sandbox runs a re-run only when the reader passes --rerun and an execution policy; nothing else
	// in the binary reaches it.
	env.Rerun = clirun.Sandbox()
	os.Exit(cli.Main(os.Args[1:], env))
}
