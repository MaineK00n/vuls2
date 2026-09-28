// Package outputjson opens the --output-json summary file shared by the
// `vuls diff` subcommands.
//
// The file is a plain stream: it is created (truncated) before the diff
// runs and the summary is written into it once the report exists. A diff
// that fails before producing a summary therefore leaves an empty file, and
// a crash mid-write leaves a partial one. That is deliberate: CI gates on
// the command's exit status first and only reads the file after a
// successful exit, so the only property that matters is that a previous
// run's rows can never be mistaken for this run's, which truncation
// guarantees.
package outputjson

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
)

// Create opens path for the summary, truncating a previous run's file.
// Only a regular file (or nothing) may exist at path: a directory, symlink,
// FIFO, device or socket is refused, since truncating or opening those would
// destroy something that is not ours or block. Callers run Validate first so
// the path cannot be one of the diff's inputs. An empty path returns a nil
// file and no error.
func Create(path string) (*os.File, error) {
	if path == "" {
		return nil, nil
	}
	fi, err := os.Lstat(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, errors.Wrapf(err, "stat %s", path)
	}
	if err == nil && !fi.Mode().IsRegular() {
		return nil, errors.Errorf("--output-json %s exists and is not a regular file (%s)", path, fi.Mode().Type())
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, errors.Wrapf(err, "create %s", path)
	}
	return f, nil
}

// Validate rejects an output path that names one of the command's inputs,
// or lies inside an input directory (the scan-results directory), so that
// Create can never truncate a DB, a vuls0 binary or a scan result. An
// existing output is matched against existing inputs by filesystem identity
// (os.SameFile); otherwise paths are compared after making them absolute
// and resolving symlinks. An empty path is a no-op.
func Validate(path string, inputs ...string) error {
	if path == "" {
		return nil
	}
	out, err := resolve(path)
	if err != nil {
		return errors.Wrapf(err, "resolve %s", path)
	}
	outInfo, err := os.Stat(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return errors.Wrapf(err, "stat %s", path)
	}
	for _, in := range inputs {
		if in == "" {
			continue
		}
		if outInfo != nil {
			if inInfo, err := os.Stat(in); err == nil && os.SameFile(outInfo, inInfo) {
				return errors.Errorf("--output-json %s is an input of the diff", path)
			}
		}
		r, err := resolve(in)
		if err != nil {
			return errors.Wrapf(err, "resolve %s", in)
		}
		if out == r {
			return errors.Errorf("--output-json %s is an input of the diff", path)
		}
		if fi, err := os.Stat(r); err == nil && fi.IsDir() && insideDir(out, r) {
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

// insideDir reports whether path lies strictly inside dir (both resolved).
func insideDir(path, dir string) bool {
	// A root ("/" or `C:\`) already ends with the separator; appending
	// another would never match and let "/diff.json" escape an input of "/".
	prefix := dir
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}
	return len(path) > len(prefix) && strings.HasPrefix(path, prefix)
}
