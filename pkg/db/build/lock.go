package build

import (
	"encoding/json/v2"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/pkg/errors"
	"oras.land/oras-go/v2/registry/remote"
)

// Lock is the recipe a vuls db is built from: the extracted dotgit of every
// data source in the db, each pinned to one commit. The sources are added in
// the order listed, which the db reflects: a vulnerability root lists its
// sources in the order they were added.
//
// A lock names data only. Which vuls binary builds it and where the result is
// published are the caller's concern.
type Lock struct {
	// Branch is the extracted branch every commit must belong to (e.g. "main"
	// or "nightly"). A commit that is not an ancestor of the branch is refused.
	Branch string `json:"branch"`
	// Registry is the OCI repository the extracted dotgits are pulled from,
	// without a tag (e.g. "ghcr.io/vulsio/vuls-data-db").
	Registry string `json:"registry"`
	// Sources lists the data sources of the db.
	Sources []Source `json:"sources"`
}

// Source is one data source of a Lock.
type Source struct {
	// Name is the extracted repository name without its prefix: the dotgit
	// is pulled from "<registry>:vuls-data-extracted-<name>".
	Name string `json:"name"`
	// Commit is the full 40-hex SHA the source is checked out at.
	Commit string `json:"commit"`
}

// Repository returns the OCI reference the source's dotgit is pulled from.
func (s Source) Repository(registry string) string {
	return fmt.Sprintf("%s:vuls-data-extracted-%s", registry, s.Name)
}

var commitRegexp = regexp.MustCompile(`^[0-9a-f]{40}$`)

// nameRegexp is what may follow "vuls-data-extracted-" in an OCI tag: a tag
// is [A-Za-z0-9_][A-Za-z0-9._-]{0,127}, the prefix supplies the first
// character and 20 of the 128, so the name is at most 108 of the rest.
var nameRegexp = regexp.MustCompile(`^[A-Za-z0-9._-]{1,108}$`)

// validBranchName applies the rules of git check-ref-format --branch to a
// branch name, so that "refs/heads/<branch>" names a branch and not a
// revision expression: "nightly~1" or "nightly^{commit}" would otherwise
// resolve, and the build would pin to something other than a branch head.
// "HEAD" is refused as git refuses it, and so is "@", which --branch would
// expand to the current branch instead of taking as a name.
func validBranchName(name string) bool {
	if name == "" || name == "@" || name == "HEAD" || strings.HasPrefix(name, "-") || strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") || strings.HasSuffix(name, ".") || strings.HasSuffix(name, ".lock") {
		return false
	}
	if strings.Contains(name, "..") || strings.Contains(name, "@{") || strings.Contains(name, "//") || strings.Contains(name, "/.") || strings.HasPrefix(name, ".") {
		return false
	}
	for _, r := range name {
		if r <= 0x20 || r == 0x7f || strings.ContainsRune("~^:?*[\\", r) {
			return false
		}
	}
	for _, component := range strings.Split(name, "/") {
		if strings.HasSuffix(component, ".lock") {
			return false
		}
	}
	return true
}

// ReadLock parses and validates a lock. Unknown members are rejected so a
// typo in a hand-edited lock fails here rather than being silently ignored.
func ReadLock(r io.Reader) (Lock, error) {
	var l Lock
	if err := json.UnmarshalRead(r, &l, json.RejectUnknownMembers(true)); err != nil {
		return Lock{}, errors.Wrap(err, "unmarshal lock")
	}
	if err := l.Validate(); err != nil {
		return Lock{}, errors.Wrap(err, "validate lock")
	}
	return l, nil
}

// Validate checks that the lock can be built from: a branch, a registry
// without tag or digest, and at least one source with a unique name and a
// full commit SHA.
func (l Lock) Validate() error {
	if l.Branch == "" {
		return errors.New("branch is empty")
	}
	if !validBranchName(l.Branch) {
		return errors.Errorf("unexpected branch. expected: %q, actual: %q", "<branch name> (git check-ref-format --branch)", l.Branch)
	}

	if l.Registry == "" {
		return errors.New("registry is empty")
	}
	host, repository, found := strings.Cut(l.Registry, "/")
	if !found || host == "" || repository == "" || strings.Contains(l.Registry, "@") || strings.Contains(repository, ":") || strings.HasSuffix(repository, "/") {
		return errors.Errorf("unexpected registry. expected: %q, actual: %q", "<host>/<repository> (no tag, no digest)", l.Registry)
	}
	// The host becomes a directory under the work directory, and the pull
	// removes that directory before it fetches anything: "." or ".." would
	// point it outside the work directory.
	if host == "." || host == ".." {
		return errors.Errorf("unexpected registry host. expected: %q, actual: %q", "<host> (not . or ..)", host)
	}

	if len(l.Sources) == 0 {
		return errors.New("sources is empty")
	}
	seen := make(map[string]struct{}, len(l.Sources))
	for i, s := range l.Sources {
		if s.Name == "" {
			return errors.Errorf("sources[%d]: name is empty", i)
		}
		if !nameRegexp.MatchString(s.Name) {
			return errors.Errorf("sources[%d]: unexpected name. expected: %q, actual: %q", i, "<extracted repository name without vuls-data-extracted- prefix> ([A-Za-z0-9._-], at most 108 characters)", s.Name)
		}
		if _, ok := seen[s.Name]; ok {
			return errors.Errorf("sources[%d]: duplicate name %q", i, s.Name)
		}
		seen[s.Name] = struct{}{}

		if !commitRegexp.MatchString(s.Commit) {
			return errors.Errorf("sources[%d] (%s): unexpected commit. expected: %q, actual: %q", i, s.Name, "40 lowercase hex digits", s.Commit)
		}

		// The reference the build will pull must parse as the OCI client
		// parses it (lowercase repository path, valid host), so that
		// --check and the build agree on what a valid lock is.
		if _, err := remote.NewRepository(s.Repository(l.Registry)); err != nil {
			return errors.Wrapf(err, "sources[%d] (%s): invalid OCI reference %q", i, s.Name, s.Repository(l.Registry))
		}
	}

	return nil
}
