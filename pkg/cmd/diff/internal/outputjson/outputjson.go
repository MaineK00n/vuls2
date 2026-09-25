// Package outputjson writes the --output-json summary file shared by the
// `vuls diff` subcommands.
package outputjson

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
)

// Write publishes summary at path. Callers buffer the summary during the
// diff and call Write afterwards: the buffer is only populated once the diff
// has produced its report, so an early failure (an unreadable DB, a vuls0
// crash) never yields a half-built summary.
//
// The file at path therefore always reflects the run that just finished:
//   - a complete summary is written to a temporary file next to path and
//     renamed into place, so a crash mid-write cannot leave a partial file;
//   - an empty summary (the diff failed before producing one) removes any
//     file a previous run left at path, so CI cannot read stale rows and
//     hold back the wrong sources.
//
// An empty path writes nothing. The diff's own verdict is returned by the
// caller after this.
func Write(path string, summary []byte) error {
	if path == "" {
		return nil
	}

	if len(summary) == 0 {
		return Clear(path)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*")
	if err != nil {
		return errors.Wrapf(err, "create temporary file for %s", path)
	}
	defer os.Remove(tmp.Name()) //nolint:errcheck

	if _, err := tmp.Write(summary); err != nil {
		_ = tmp.Close()
		return errors.Wrapf(err, "write %s", tmp.Name())
	}
	if err := tmp.Close(); err != nil {
		return errors.Wrapf(err, "close %s", tmp.Name())
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return errors.Wrapf(err, "chmod %s", tmp.Name())
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return errors.Wrapf(err, "rename %s to %s", tmp.Name(), path)
	}
	return nil
}

// Clear removes any file a previous run left at path; a missing file is not
// an error. Callers run it first thing in the command's RunE, before anything
// that can fail ahead of the diff (override parsing, opening inputs), so
// that no failure once the command runs can leave a stale summary for CI to
// consume. An empty path is a no-op.
//
// Usage errors are the one exception: an unparseable flag value or a wrong
// number of positional arguments is rejected by Cobra before RunE runs, so
// the path is left untouched. Those are deterministic mistakes in the
// caller's command line, not runtime failures, and CI should remove the
// file before invoking the command (and gate on the exit status) rather
// than rely on this cleanup alone.
func Clear(path string) error {
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return errors.Wrapf(err, "remove stale %s", path)
	}
	return nil
}

// Validate rejects an output path that names one of the command's inputs,
// or lies inside an input directory (the scan-results directory), so that
// Clear and Write can never delete or overwrite a DB, a vuls0 binary or a
// scan result. Paths are compared after making them absolute and resolving
// symlinks, so an alias of an input is rejected too. Callers run it before
// Clear. An empty path is a no-op.
func Validate(path string, inputs ...string) error {
	if path == "" {
		return nil
	}
	out, err := resolve(path)
	if err != nil {
		return errors.Wrapf(err, "resolve %s", path)
	}
	for _, in := range inputs {
		if in == "" {
			continue
		}
		r, err := resolve(in)
		if err != nil {
			return errors.Wrapf(err, "resolve %s", in)
		}
		if out == r {
			return errors.Errorf("--output-json %s is an input of the diff", path)
		}
		if fi, err := os.Stat(r); err == nil && fi.IsDir() && strings.HasPrefix(out, r+string(filepath.Separator)) {
			return errors.Errorf("--output-json %s lies inside the input directory %s", path, in)
		}
	}
	return nil
}

// resolve returns path as an absolute, symlink-free, cleaned path. A path
// that does not exist yet (the usual case for the output) is resolved
// through its nearest existing ancestor so that a symlinked directory still
// compares equal to its target.
func resolve(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		return r, nil
	}
	dir, base := filepath.Split(filepath.Clean(abs))
	dir = filepath.Clean(dir)
	if dir == abs { // filesystem root
		return abs, nil
	}
	r, err := resolve(dir)
	if err != nil {
		return "", err
	}
	return filepath.Join(r, base), nil
}
