// Package override parses repeated `--change-rate-threshold-override` flag
// values of the form `<key>=<rate>` into a map. Shared between the diff db
// and diff detection commands so both accept the same input syntax.
package override

import (
	"log/slog"
	"math"
	"strconv"
	"strings"

	"github.com/pkg/errors"
)

// Parse converts a slice of "<key>=<rate>" entries into a map. Whitespace
// around the key and rate is tolerated. Duplicate keys are accepted with the
// last value winning and a warning logged. Returns an error for malformed
// entries (missing "=", empty key, non-numeric rate, negative rate).
func Parse(entries []string) (map[string]float64, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	m := make(map[string]float64, len(entries))
	for _, e := range entries {
		k, v, ok := strings.Cut(e, "=")
		if !ok {
			return nil, errors.Errorf("missing %q separator: %q", "=", e)
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" {
			return nil, errors.Errorf("empty key: %q", e)
		}
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return nil, errors.Wrapf(err, "parse rate %q (entry %q)", v, e)
		}
		// strconv.ParseFloat happily accepts "NaN" / "Inf"; both produce
		// surprising downstream behavior (NaN: every comparison false,
		// every diff FAILs even when within threshold; Inf: every diff
		// PASSes regardless of rate). Refuse them up front.
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return nil, errors.Errorf("non-finite rate not allowed: %q", e)
		}
		if f < 0 {
			return nil, errors.Errorf("negative rate not allowed: %q", e)
		}
		if _, dup := m[k]; dup {
			slog.Warn("duplicate override key, last wins", "key", k, "rate", f)
		}
		m[k] = f
	}
	return m, nil
}
