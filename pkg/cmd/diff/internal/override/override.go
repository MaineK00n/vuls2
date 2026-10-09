// Package override parses the override flag values of the diff commands
// into maps. Shared between the diff db and diff detection commands so both
// accept the same input syntax.
//
// Three syntaxes exist:
//
//   - `<key>=<rate>` for the legacy `--change-rate-threshold-override` flag
//     (Parse), where the rate applies to every axis alike;
//   - `<key>=<axis>:<rate>` for `--rate-threshold-override` (ParseAxes),
//     where the rate applies to the named axis only;
//   - `<axis>:<rate>` for `--rate-threshold` (ParseDefaults), the same
//     entry without a key: the default of the named axis.
package override

import (
	"log/slog"
	"math"
	"slices"
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
		f, err := parseRate(strings.TrimSpace(v))
		if err != nil {
			return nil, errors.Wrapf(err, "parse rate. entry: %q", e)
		}
		if _, dup := m[k]; dup {
			slog.Warn("duplicate override key, last wins", "key", k, "rate", f)
		}
		m[k] = f
	}
	return m, nil
}

// ParseAxes converts a slice of "<key>=<axis>:<rate>" entries into a
// per-key map of partial Rates. The key is everything before the first
// "=", so keys containing ":" (e.g. "ubuntu:26.04") or "/" (e.g.
// "cpe/cisco-json") need no quoting. axes lists the axes the command
// accepts; an entry naming any other axis is an error, as is an entry
// without an axis — "relax every axis at once" is deliberately not
// expressible here, so that the removed axis stays tight unless named.
// Whitespace around each part is tolerated. Duplicate (key, axis) pairs
// are accepted with the last value winning and a warning logged.
func ParseAxes(entries []string, axes []threshold.Axis) (map[string]threshold.Rates, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	m := make(map[string]threshold.Rates, len(entries))
	for _, e := range entries {
		k, v, ok := strings.Cut(e, "=")
		if !ok {
			return nil, errors.Errorf("unexpected override entry. expected: %q, actual: %q", "<key>=<axis>:<rate>", e)
		}
		k = strings.TrimSpace(k)
		if k == "" {
			return nil, errors.Errorf("unexpected override key. expected: non-empty, actual: %q (entry: %q)", k, e)
		}
		a, f, err := parseAxisRate(v, axes)
		if err != nil {
			return nil, errors.Wrapf(err, "parse override entry %q", e)
		}
		if m[k] == nil {
			m[k] = make(threshold.Rates, len(axes))
		}
		if _, dup := m[k][a]; dup {
			slog.Warn("duplicate override key, last wins", "key", k, "axis", a, "rate", f)
		}
		m[k][a] = f
	}
	return m, nil
}

// ParseDefaults converts a slice of "<axis>:<rate>" entries — the default
// threshold of each named axis — into Rates. Axes not mentioned are absent
// from the result so the caller can keep its built-in default for them.
// The rules match ParseAxes: axes lists the accepted axes, whitespace is
// tolerated, a duplicate axis warns and the last value wins. An entry
// carrying a "=" is refused with a hint, since that is the override form.
func ParseDefaults(entries []string, axes []threshold.Axis) (threshold.Rates, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	r := make(threshold.Rates, len(axes))
	for _, e := range entries {
		if strings.Contains(e, "=") {
			return nil, errors.Errorf("unexpected threshold entry. expected: %q (a per-target override belongs to --rate-threshold-override), actual: %q", "<axis>:<rate>", e)
		}
		a, f, err := parseAxisRate(e, axes)
		if err != nil {
			return nil, errors.Wrapf(err, "parse threshold entry %q", e)
		}
		if _, dup := r[a]; dup {
			slog.Warn("duplicate threshold axis, last wins", "axis", a, "rate", f)
		}
		r[a] = f
	}
	return r, nil
}

// parseAxisRate parses "<axis>:<rate>", accepting only axes. Whitespace
// around the axis and the rate is tolerated.
func parseAxisRate(s string, axes []threshold.Axis) (threshold.Axis, float64, error) {
	as, rs, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, errors.Errorf("unexpected entry. expected: %q, actual: %q", "<axis>:<rate>", s)
	}
	a := threshold.Axis(strings.TrimSpace(as))
	if !slices.Contains(axes, a) {
		return "", 0, errors.Errorf("unexpected axis. expected: one of %v, actual: %q", axes, a)
	}
	f, err := parseRate(strings.TrimSpace(rs))
	if err != nil {
		return "", 0, errors.Wrap(err, "parse rate")
	}
	return a, f, nil
}

// parseRate parses a percentage, refusing non-numeric, non-finite and
// negative values. strconv.ParseFloat happily accepts "NaN" / "Inf"; both
// produce surprising downstream behavior (the judgement is `rate >
// threshold`, so a NaN threshold makes every comparison false and every
// diff PASSes however large the change; +Inf likewise PASSes everything),
// so they are refused up front.
func parseRate(v string) (float64, error) {
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return 0, errors.Wrapf(err, "unexpected rate. expected: numeric, actual: %q", v)
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, errors.Errorf("unexpected rate. expected: finite, actual: %v", f)
	}
	if f < 0 {
		return 0, errors.Errorf("unexpected rate. expected: >= 0, actual: %v", f)
	}
	return f, nil
}
