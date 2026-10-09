// Package override parses the override flag values of the diff commands
// into maps. Shared between the diff db and diff detection commands so both
// accept the same input syntax.
//
// Two syntaxes exist:
//
//   - `<key>=<rate>` for the legacy `--change-rate-threshold-override` flag
//     (Parse), where the rate applies to every axis alike;
//   - `<key>=<axis>:<rate>` for `--rate-threshold-override` (ParseAxes),
//     where the rate applies to the named axis only.
package override

import (
	"log/slog"
	"math"
	"strconv"
	"strings"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls2/pkg/diff/threshold"
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
		if k == "" {
			return nil, errors.Errorf("unexpected override key. expected: non-empty, actual: %q (entry: %q)", k, e)
		}
		f, err := parseRate(strings.TrimSpace(v), e)
		if err != nil {
			return nil, err
		}
		if _, dup := m[k]; dup {
			slog.Warn("duplicate override key, last wins", "key", k, "rate", f)
		}
		m[k] = f
	}
	return m, nil
}

// ParseAxes converts a slice of "<key>=<axis>:<rate>" entries into a
// per-axis map. The key is everything before the first "=", so keys
// containing ":" (e.g. "ubuntu:26.04") or "/" (e.g. "cpe/cisco-json") need
// no quoting. axes lists the axes the command accepts; an entry naming any
// other axis is an error, as is an entry without an axis — "relax every
// axis at once" is deliberately not expressible here, so that the removed
// axis stays tight unless named. Whitespace around each part is tolerated.
// Duplicate (key, axis) pairs are accepted with the last value winning and
// a warning logged.
func ParseAxes(entries []string, axes []threshold.Axis) (map[threshold.Axis]map[string]float64, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	m := make(map[threshold.Axis]map[string]float64, len(axes))
	for _, e := range entries {
		k, v, ok := strings.Cut(e, "=")
		if !ok {
			return nil, errors.Errorf("unexpected override entry. expected: %q, actual: %q", "<key>=<axis>:<rate>", e)
		}
		k = strings.TrimSpace(k)
		if k == "" {
			return nil, errors.Errorf("unexpected override key. expected: non-empty, actual: %q (entry: %q)", k, e)
		}
		as, rs, ok := strings.Cut(v, ":")
		if !ok {
			return nil, errors.Errorf("unexpected override value. expected: %q, actual: %q (entry: %q)", "<axis>:<rate>", v, e)
		}
		a := threshold.Axis(strings.TrimSpace(as))
		if !containsAxis(axes, a) {
			return nil, errors.Errorf("unexpected override axis. expected: one of %v, actual: %q (entry: %q)", axes, a, e)
		}
		f, err := parseRate(strings.TrimSpace(rs), e)
		if err != nil {
			return nil, err
		}
		if m[a] == nil {
			m[a] = make(map[string]float64)
		}
		if _, dup := m[a][k]; dup {
			slog.Warn("duplicate override key, last wins", "key", k, "axis", a, "rate", f)
		}
		m[a][k] = f
	}
	return m, nil
}

func containsAxis(axes []threshold.Axis, a threshold.Axis) bool {
	for _, x := range axes {
		if x == a {
			return true
		}
	}
	return false
}

// parseRate parses a percentage, refusing non-numeric, non-finite and
// negative values. strconv.ParseFloat happily accepts "NaN" / "Inf"; both
// produce surprising downstream behavior (NaN: every comparison false,
// every diff FAILs even when within threshold; Inf: every diff PASSes
// regardless of rate), so they are refused up front.
func parseRate(v, entry string) (float64, error) {
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, errors.Wrapf(err, "unexpected override rate. expected: numeric, actual: %q (entry: %q)", v, entry)
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, errors.Errorf("unexpected override rate. expected: finite, actual: %v (entry: %q)", f, entry)
	}
	if f < 0 {
		return 0, errors.Errorf("unexpected override rate. expected: >= 0, actual: %v (entry: %q)", f, entry)
	}
	return f, nil
}
