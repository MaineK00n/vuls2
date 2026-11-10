package build

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
)

// git runs one git command in dir and returns its trimmed stdout. A non-zero
// exit comes back as an error carrying stderr, so callers that need the exit
// code use gitExit instead.
func git(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	bs, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return "", errors.Wrapf(err, "exec %q: %s", cmd.String(), strings.TrimSpace(string(ee.Stderr)))
		}
		return "", errors.Wrapf(err, "exec %q", cmd.String())
	}
	return strings.TrimSpace(string(bs)), nil
}

// gitExit runs one git command in dir and reports whether it exited 0. Exit
// status 1 is a "no" answer (git's convention for merge-base --is-ancestor
// and cat-file -e), anything else is an error.
func gitExit(dir string, args ...string) (bool, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 1 {
			return false, nil
		}
		return false, errors.Wrapf(err, "exec %q", cmd.String())
	}
	return true, nil
}

func commitExists(dir, commit string) (bool, error) {
	return gitExit(dir, "cat-file", "-e", fmt.Sprintf("%s^{commit}", commit))
}

func isAncestor(dir, commit, ref string) (bool, error) {
	return gitExit(dir, "merge-base", "--is-ancestor", commit, ref)
}

func revParse(dir, rev string) (string, error) {
	return git(dir, "rev-parse", "--verify", fmt.Sprintf("%s^{commit}", rev))
}

// authorTime returns the author date of rev. The extracted datasource.json
// records the author date of the commit it was built from, which is what the
// previous Makefile-driven build wrote (git show --format=%at).
func authorTime(dir, rev string) (time.Time, error) {
	s, err := git(dir, "show", "-s", "--format=%at", rev)
	if err != nil {
		return time.Time{}, err
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
		return nil, err
	}
	if s == "" {
		return nil, nil
	}
	return strings.Split(s, "\n"), nil
}
