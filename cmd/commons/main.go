// Command commons is the Research Commons tool. All logic lives in internal/cli; this is the process
// boundary only.
package main

import (
	"os"

	"github.com/research-common/research-commons/internal/cli"
)

// Set at link time: go build -ldflags "-X main.version=0.5.0-alpha.1 -X main.commit=$(git rev-parse HEAD)".
var version, commit string

func main() {
	os.Exit(cli.Main(os.Args[1:], cli.OSEnv(cli.Build{Version: version, Commit: commit})))
}
