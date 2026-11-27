package build

import (
	"encoding/json/v2"
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
	// Sources lists the data sources of the db.
	Sources []Source `json:"sources"`
}

// Source is one data source of a Lock.
type Source struct {
	// Name identifies the source's row in the lock (e.g. "alma-errata").
	Name string `json:"name"`
	// Repository is the OCI reference, with a tag, the source's extracted
	// dotgit is pulled from (e.g.
	// "ghcr.io/vulsio/vuls-data-db:vuls-data-extracted-alma-errata").
	Repository string `json:"repository"`
	// Branch is the extracted branch the commit must belong to (e.g. "main"
	// or "nightly"). A commit that is not an ancestor of the branch is
	// refused. Each source names its own, so one db can take a source from
	// main and the others from nightly.
	Branch string `json:"branch"`
	// Commit is the full 40-hex SHA the source is checked out at.
	Commit string `json:"commit"`
	// Hold tells whatever maintains the lock not to move this row: someone
	// put the source at this commit on purpose. The build does not read it,
	// and a held source is built at its commit like any other. It is part of
	// the format so that a lock carrying it is not refused for an unknown
	// member.
	Hold bool `json:"hold,omitzero"`
}

var commitRegexp = regexp.MustCompile(`^[0-9a-f]{40}$`)

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

// Validate checks that the lock can be built from: at least one source, each
// with a unique name, a unique repository with a tag, a branch and a full
// commit SHA.
func (l Lock) Validate() error {
	if len(l.Sources) == 0 {
		return errors.New("sources is empty")
	}
	names := make(map[string]struct{}, len(l.Sources))
	repositories := make(map[string]struct{}, len(l.Sources))
	for i, s := range l.Sources {
		if s.Name == "" {
			return errors.Errorf("sources[%d]: name is empty", i)
		}
		if _, ok := names[s.Name]; ok {
			return errors.Errorf("sources[%d]: duplicate name %q", i, s.Name)
		}
		names[s.Name] = struct{}{}

		if s.Repository == "" {
			return errors.Errorf("sources[%d] (%s): repository is empty", i, s.Name)
		}
		// The reference must parse as the OCI client that pulls it parses
		// it (lowercase repository path, valid host), so that a bad
		// reference fails when the lock is read, not partway through a
		// build.
		ref, err := remote.NewRepository(s.Repository)
		if err != nil {
			return errors.Wrapf(err, "sources[%d] (%s): invalid OCI reference %q", i, s.Name, s.Repository)
		}
		// A tag, not a digest: the commit pins the content, and the pull
		// lays the dotgit out under <host>/<repository>/<tag>.
		if err := ref.Reference.ValidateReferenceAsTag(); err != nil {
			return errors.Errorf("sources[%d] (%s): unexpected repository. expected: %q, actual: %q", i, s.Name, "<host>/<repository>:<tag>", s.Repository)
		}
		// The host becomes a directory under the work directory, and the
		// pull removes that directory before it fetches anything: "." or
		// ".." would point it outside the work directory.
		if ref.Reference.Registry == "." || ref.Reference.Registry == ".." {
			return errors.Errorf("sources[%d] (%s): unexpected repository host. expected: %q, actual: %q", i, s.Name, "<host> (not . or ..)", ref.Reference.Registry)
		}
		if _, ok := repositories[s.Repository]; ok {
			return errors.Errorf("sources[%d] (%s): duplicate repository %q", i, s.Name, s.Repository)
		}
		repositories[s.Repository] = struct{}{}

		if s.Branch == "" {
			return errors.Errorf("sources[%d] (%s): branch is empty", i, s.Name)
		}
		if !validBranchName(s.Branch) {
			return errors.Errorf("sources[%d] (%s): unexpected branch. expected: %q, actual: %q", i, s.Name, "<branch name> (git check-ref-format --branch)", s.Branch)
		}

		if !commitRegexp.MatchString(s.Commit) {
			return errors.Errorf("sources[%d] (%s): unexpected commit. expected: %q, actual: %q", i, s.Name, "40 lowercase hex digits", s.Commit)
		}
	}

	return nil
}
