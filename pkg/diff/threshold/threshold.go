// Package threshold holds the per-axis change-rate thresholds shared by
// `vuls diff db` and `vuls diff detection`. A diff is judged on up to three
// axes — added, changed, removed — each with its own default threshold and
// its own per-target overrides, so that routine additions can be tolerated
// while removals stay tightly bounded.
package threshold

import (
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/pkg/errors"
)

// Axis is one direction of change a diff is judged on.
type Axis string

const (
	// Added counts units present only in the target.
	Added Axis = "added"
	// Changed counts units present on both sides under the same key but
	// with different content. Only diffs that compare content have it;
	// `diff detection` compares ID sets and never reports it.
	Changed Axis = "changed"
	// Removed counts units present only in the baseline.
	Removed Axis = "removed"
)

// Rates maps an axis to a percentage: either a change rate or a threshold.
type Rates map[Axis]float64

// Threshold is the per-axis threshold set of one diff command.
type Threshold struct {
	// Axes the command judges, in report order. Default and Overrides may
	// only mention these.
	Axes []Axis
	// Default threshold per axis. A missing axis means 0 (no change
	// tolerated on it).
	Default Rates
	// Overrides keyed by target (e.g. "ubuntu:26.04" or "cpe/cisco-json"
	// for db; "debian_13" or "cpe_jvn/jvn-feed-rss" for detection), each a
	// partial Rates: an axis a target does not mention is not overridden
	// for it. Resolve looks keys up in precedence order, per axis.
	Overrides map[string]Rates
}

// Legacy builds the Threshold equivalent to the single-threshold flags
// (`--change-rate-threshold` / `--change-rate-threshold-override`): the
// default and every override apply to all axes alike. Each axis rate is at
// most the legacy combined rate, so the mapping is never stricter than the
// legacy judgement.
func Legacy(axes []Axis, def float64, overrides map[string]float64) Threshold {
	t := Threshold{Axes: axes, Default: make(Rates, len(axes)), Overrides: make(map[string]Rates, len(overrides))}
	for _, a := range axes {
		t.Default[a] = def
	}
	for k, v := range overrides {
		r := make(Rates, len(axes))
		for _, a := range axes {
			r[a] = v
		}
		t.Overrides[k] = r
	}
	return t
}

// Validate checks that Default and Overrides only mention declared axes
// and only carry finite, non-negative values.
func (t Threshold) Validate() error {
	if len(t.Axes) == 0 {
		return errors.New("unexpected axes. expected: non-empty, actual: empty")
	}
	for a, v := range t.Default {
		if !slices.Contains(t.Axes, a) {
			return errors.Errorf("unexpected default axis. expected: one of %v, actual: %q", t.Axes, a)
		}
		if err := validateValue(v); err != nil {
			return errors.Wrapf(err, "validate default of %s axis", a)
		}
	}
	for k, r := range t.Overrides {
		if k == "" {
			return errors.Errorf("unexpected override key. expected: non-empty, actual: %q", k)
		}
		for a, v := range r {
			if !slices.Contains(t.Axes, a) {
				return errors.Errorf("unexpected override axis. expected: one of %v, actual: %q (key: %q)", t.Axes, a, k)
			}
			if err := validateValue(v); err != nil {
				return errors.Wrapf(err, "validate override of %s axis for %q", a, k)
			}
		}
	}
	return nil
}

// validateValue rejects a NaN / ±Inf / negative threshold value. The
// judgement is `rate > threshold`, so a NaN threshold makes every
// comparison false and lets every diff PASS however large the change;
// +Inf likewise PASSes everything; a negative threshold can never be met.
func validateValue(f float64) error {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return errors.Errorf("unexpected value. expected: finite, actual: %v", f)
	}
	if f < 0 {
		return errors.Errorf("unexpected value. expected: >= 0, actual: %v", f)
	}
	return nil
}

// Resolve returns the threshold of every axis for one target. keys are the
// override keys to try, narrowest first (e.g. "cpe/cisco-json", then
// "cpe"); the first hit wins per axis, and an axis with no hit falls back to
// Default (0 when absent). The result carries every axis in t.Axes.
func (t Threshold) Resolve(keys ...string) Rates {
	r := make(Rates, len(t.Axes))
	for _, a := range t.Axes {
		r[a] = t.Default[a]
		for _, k := range keys {
			if v, ok := t.Overrides[k][a]; ok {
				r[a] = v
				break
			}
		}
	}
	return r
}

// Exceeded returns, in axes order, the axes whose rate is above its
// threshold. A missing rate or threshold counts as 0.
func Exceeded(axes []Axis, rates, thresholds Rates) []Axis {
	var out []Axis
	for _, a := range axes {
		if rates[a] > thresholds[a] {
			out = append(out, a)
		}
	}
	return out
}

// Rate computes one axis' change rate as a percentage of the baseline unit
// count: n / baseline * 100. When baseline is 0 but n > 0 the rate is 100
// (only the added axis can get here — changed and removed units are drawn
// from the baseline); when both are 0 it is 0. The added rate can exceed
// 100% when additions outnumber baseline entries — capping would hide the
// magnitude of large additions.
func Rate(baseline, n int) float64 {
	switch {
	case baseline > 0:
		return float64(n) / float64(baseline) * 100
	case n > 0:
		return 100
	default:
		return 0
	}
}

// Format renders rates in axes order as "a% / b% / c%", wrapping in bold
// the ones above their threshold so a FAIL row shows which axis tripped.
// Rates print with one decimal; the judgement is made on the unrounded
// values, so a bold cell may print equal to its threshold.
func Format(axes []Axis, rates, thresholds Rates) string {
	cells := make([]string, 0, len(axes))
	for _, a := range axes {
		cell := fmt.Sprintf("%.1f%%", rates[a])
		if rates[a] > thresholds[a] {
			cell = fmt.Sprintf("**%s**", cell)
		}
		cells = append(cells, cell)
	}
	return strings.Join(cells, " / ")
}

// FormatExceeded renders "rate% > threshold%" for an exceeded axis, one
// decimal each.
func FormatExceeded(rate, threshold float64) string {
	return fmt.Sprintf("%.1f%% > %.1f%%", rate, threshold)
}

// FormatThresholds renders thresholds in axes order as "a% / b% / c%".
func FormatThresholds(axes []Axis, thresholds Rates) string {
	cells := make([]string, 0, len(axes))
	for _, a := range axes {
		cells = append(cells, fmt.Sprintf("%.1f%%", thresholds[a]))
	}
	return strings.Join(cells, " / ")
}

// Max returns the largest rate over axes (0 when none).
func Max(axes []Axis, rates Rates) float64 {
	m := 0.0
	for _, a := range axes {
		m = max(m, rates[a])
	}
	return m
}
