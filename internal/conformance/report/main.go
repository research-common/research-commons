// Command report writes the conformance report of a test run.
//
//	go test -json ./... > run.json
//	go run ./internal/conformance/report -revision "$(git rev-parse HEAD)" run.json > conformance-report.json
//
// Several files are read as one run (the default build, then a build with tags: name the tags with -tags).
// The counts and every case that did not pass go to standard error. Exit 1 when a case failed or a line of
// the input is not a test event, so a release job cannot attach the report of a broken run.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/conformance/specgraph"
)

func main() {
	revision := flag.String("revision", "", "the commit the tests ran at (required)")
	tags := flag.String("tags", "", "comma-separated build tags of the runs read, besides the default build")
	platform := flag.String("platform", runtime.GOOS+"/"+runtime.GOARCH, "GOOS/GOARCH the tests ran on")
	goVersion := flag.String("go", runtime.Version(), "the toolchain the tests ran with")
	flag.Parse()
	if *revision == "" || flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: report -revision <commit> [-tags a,b] <go-test-json file>...")
		os.Exit(2)
	}
	if err := run(*revision, *tags, *platform, *goVersion, flag.Args()); err != nil {
		fmt.Fprintln(os.Stderr, "report:", err)
		os.Exit(1)
	}
}

var moduleLine = regexp.MustCompile(`(?m)^module (\S+)`)

func run(revision, tags, platform, goVersion string, files []string) error {
	root, err := conformance.RepoRoot()
	if err != nil {
		return err
	}
	mod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return err
	}
	m := moduleLine.FindSubmatch(mod)
	if m == nil {
		return fmt.Errorf("go.mod names no module")
	}
	version, err := os.ReadFile(filepath.Join(root, "VERSION"))
	if err != nil {
		return err
	}
	g, problems, err := specgraph.Build(root)
	if err != nil {
		return err
	}
	if len(problems) > 0 {
		return fmt.Errorf("the case documents do not read cleanly: %s", strings.Join(problems, "; "))
	}
	r := specgraph.NewRun(string(m[1]))
	for _, f := range files {
		in, err := os.Open(f)
		if err != nil {
			return err
		}
		err = r.Read(in)
		in.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", f, err)
		}
	}
	meta := specgraph.Meta{Revision: revision, Version: strings.TrimSpace(string(version)), Go: goVersion, Platform: platform}
	for _, t := range strings.Split(tags, ",") {
		if t = strings.TrimSpace(t); t != "" {
			meta.Tags = append(meta.Tags, t)
		}
	}
	rep := specgraph.NewReport(g, r, meta)
	os.Stdout.Write(rep.JSON())
	fmt.Fprint(os.Stderr, rep.Summary())
	if !rep.Clean() {
		return fmt.Errorf("a case failed or the input holds lines that are not test events")
	}
	return nil
}
