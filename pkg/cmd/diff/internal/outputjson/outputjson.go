// Package outputjson writes the --output-json summary file shared by the
// `vuls diff` subcommands.
package outputjson

import (
	"io/fs"
	"os"
	"path/filepath"

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
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return errors.Wrapf(err, "remove stale %s", path)
		}
		return nil
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
