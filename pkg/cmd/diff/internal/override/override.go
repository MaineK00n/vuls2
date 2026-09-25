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
// entries (missing "=", empty key, non-numeric / non-finite / negative rate).
func Parse(entries []string) (map[string]float64, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	m := make(map[string]float64, len(entries))
	for _, e := range entries {
		k, v, ok := strings.Cut(e, "=")
		if !ok {
			return nil, errors.Errorf("unexpected override entry. expected: %q, actual: %q", "<key>=<rate>", e)
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if k == "" {
			return nil, errors.Errorf("unexpected override key. expected: non-empty, actual: %q (entry: %q)", k, e)
		}
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return nil, errors.Wrapf(err, "unexpected override rate. expected: numeric, actual: %q (entry: %q)", v, e)
		}
		if err := CheckRate(f); err != nil {
			return nil, errors.Wrapf(err, "unexpected override rate (entry: %q)", e)
		}
		if _, dup := m[k]; dup {
			slog.Warn("duplicate override key, last wins", "key", k, "rate", f)
		}
		m[k] = f
	}
	return m, nil
}

// CheckRate rejects a change-rate threshold that is not finite or is
// negative. It backs both the override entries and the default
// --change-rate-threshold flag: strconv.ParseFloat (and pflag's Float64)
// happily accept "NaN" / "Inf", and both produce surprising downstream
// behavior (NaN: every comparison false, so every diff FAILs even when
// within threshold; Inf: every diff PASSes regardless of rate). NaN and
// Inf also cannot be JSON-encoded, so they would additionally prevent the
// --output-json summary from being published.
func CheckRate(f float64) error {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return errors.Errorf("expected: finite, actual: %v", f)
	}
	if f < 0 {
		return errors.Errorf("expected: >= 0, actual: %v", f)
	}
	return nil
}
