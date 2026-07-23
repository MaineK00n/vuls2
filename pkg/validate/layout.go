package validate

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/pkg/errors"
)

// contentDirs are the top-level directories vuls db add ingests content
// from; a valid extracted repository carries at least one of them. Multiple
// are legitimate: microsoft-bulletin/cvrf emit both data and microsoftkb.
var contentDirs = []string{"attack", "capec", "cwe", "data", "eol", "microsoftkb"}

var layoutCheck = RepositoryCheck{
	Name:        "layout",
	Description: "repository layout: datasource.json exists, only known top-level entries, at least one content directory",
	Detect:      detectLayout,
}

// detectLayout reports structural problems of the repository root: a missing
// datasource.json, top-level entries that neither db add nor the dotgit
// tooling knows about, entries of the wrong kind (a content name that is not
// a directory), and the absence of any known content directory.
func detectLayout(root string) ([]Finding, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, errors.Wrapf(err, "read %s", root)
	}

	var findings []Finding
	add := func(path, message string) {
		findings = append(findings, Finding{Path: path, Check: "layout", Message: message})
	}

	if !slices.ContainsFunc(entries, func(e os.DirEntry) bool { return e.Name() == "datasource.json" }) {
		add("datasource.json", "datasource.json is missing")
	}

	contents := 0
	for _, e := range entries {
		switch name := e.Name(); {
		case slices.Contains(contentDirs, name):
			if !e.IsDir() {
				add(name, fmt.Sprintf("%s is not a directory", name))
				continue
			}
			contents++
		case name == ".git":
		case name == "README.md", name == "datasource.json":
			if e.IsDir() {
				add(name, fmt.Sprintf("%s is not a regular file", name))
			}
		default:
			add(name, fmt.Sprintf("unknown top-level entry (expected: %q)", append(slices.Clone(contentDirs), ".git", "README.md", "datasource.json")))
		}
	}

	if contents == 0 {
		add("", fmt.Sprintf("no content directory (expected at least one of: %s)", strings.Join(contentDirs, ", ")))
	}

	return findings, nil
}
