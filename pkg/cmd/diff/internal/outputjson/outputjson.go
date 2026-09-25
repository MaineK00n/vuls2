// Package outputjson writes the --output-json summary file shared by the
// `vuls diff` subcommands.
package outputjson

import (
	"os"

	"github.com/pkg/errors"
)

// Write writes summary to path. Callers buffer the summary during the diff
// and call Write afterwards: the buffer is only populated once the diff has
// produced its report, so an early failure (an unreadable DB, a vuls0 crash)
// leaves no half-written file for CI to misread. An empty path or an empty
// summary writes nothing. The diff's own verdict is returned by the caller
// after this.
func Write(path string, summary []byte) error {
	if path == "" || len(summary) == 0 {
		return nil
	}
	if err := os.WriteFile(path, summary, 0o644); err != nil {
		return errors.Wrapf(err, "write %s", path)
	}
	return nil
}
