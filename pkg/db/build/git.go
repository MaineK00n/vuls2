package build

import (
	stderrors "errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// git runs one git command in dir and returns its trimmed stdout. Any
// non-zero exit is an error carrying stderr.
func git(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	bs, err := cmd.Output()
	if err != nil {
		switch ee, ok := stderrors.AsType[*exec.ExitError](err); {
		case ok:
			return "", errors.Wrapf(err, "exec %q: %s", cmd.String(), strings.TrimSpace(string(ee.Stderr)))
		default:
			return "", errors.Wrapf(err, "exec %q", cmd.String())
		}
	}
	return strings.TrimSpace(string(bs)), nil
}

// commitExists reports whether commit names a commit object in dir.
// rev-parse --verify --quiet exits 1 when the name does not resolve to a
// commit (missing, or an object of another type); any other failure is an
// error. cat-file -e is not used: with ^{commit} it exits 128 for a missing
// object, the same status as a broken repository.
func commitExists(dir, commit string) (bool, error) {
	cmd := exec.Command("git", "-C", dir, "rev-parse", "--verify", "--quiet", fmt.Sprintf("%s^{commit}", commit))
	if _, err := cmd.Output(); err != nil {
		switch ee, ok := stderrors.AsType[*exec.ExitError](err); {
		case ok && ee.ExitCode() == 1:
			return false, nil
		case ok:
			return false, errors.Wrapf(err, "exec %q: %s", cmd.String(), strings.TrimSpace(string(ee.Stderr)))
		default:
			return false, errors.Wrapf(err, "exec %q", cmd.String())
		}
	}
	return true, nil
}

// isAncestor reports whether commit is an ancestor of ref in dir.
// merge-base --is-ancestor exits 0 for yes and 1 for no; any other status
// (128 for a name that does not resolve) is an error.
func isAncestor(dir, commit, ref string) (bool, error) {
	cmd := exec.Command("git", "-C", dir, "merge-base", "--is-ancestor", commit, ref)
	if _, err := cmd.Output(); err != nil {
		switch ee, ok := stderrors.AsType[*exec.ExitError](err); {
		case ok && ee.ExitCode() == 1:
			return false, nil
		case ok:
			return false, errors.Wrapf(err, "exec %q: %s", cmd.String(), strings.TrimSpace(string(ee.Stderr)))
		default:
			return false, errors.Wrapf(err, "exec %q", cmd.String())
		}
	}
	return true, nil
}

func revParse(dir, rev string) (string, error) {
	s, err := git(dir, "rev-parse", "--verify", fmt.Sprintf("%s^{commit}", rev))
	if err != nil {
		return "", errors.Wrapf(err, "rev-parse %s", rev)
	}
	return s, nil
}

// authorTime returns the author date of rev. The extracted datasource.json
// records the author date of the commit it was built from, which is what the
// previous Makefile-driven build wrote (git show --format=%at).
func authorTime(dir, rev string) (time.Time, error) {
	s, err := git(dir, "show", "-s", "--format=%at", rev)
	if err != nil {
		return time.Time{}, errors.Wrapf(err, "show author date of %s", rev)
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return time.Time{}, errors.Wrapf(err, "parse author time %q of %s", s, rev)
	}
	return time.Unix(n, 0).UTC(), nil
}

// commitsAfter returns the commits reachable from ref but not from commit,
// oldest first.
func commitsAfter(dir, commit, ref string) ([]string, error) {
	s, err := git(dir, "rev-list", "--reverse", fmt.Sprintf("%s..%s", commit, ref))
	if err != nil {
		return nil, errors.Wrapf(err, "rev-list %s..%s", commit, ref)
	}
	if s == "" {
		return nil, nil
	}
	return strings.Split(s, "\n"), nil
}
