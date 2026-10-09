// Package thresholdflag registers the threshold flags shared by the diff db
// and diff detection commands and turns them into a threshold.Config.
//
// Two flag families exist and are mutually exclusive on one command line:
//
//   - per axis: `--added-rate-threshold`, `--changed-rate-threshold` (only
//     on commands that judge a changed axis), `--removed-rate-threshold`,
//     and `--rate-threshold-override <key>=<axis>:<rate>`;
//   - legacy: `--change-rate-threshold` and
//     `--change-rate-threshold-override <key>=<rate>`, kept for callers of
//     the pre-axis CLI; the single value applies to every axis alike.
package thresholdflag

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/pflag"

	"github.com/MaineK00n/vuls2/pkg/cmd/diff/internal/override"
	"github.com/MaineK00n/vuls2/pkg/diff/threshold"
)

// Flags holds the parsed values of both flag families for one command.
type Flags struct {
	axes     []threshold.Axis
	defaults map[threshold.Axis]*float64

	overrides []string

	legacyThreshold float64
	legacyOverrides []string
}

// Defaults are the built-in per-axis thresholds (%): additions are the
// routine pattern of vulnerability data and get a generous default;
// changes and removals are tolerated only when asked for explicitly.
var Defaults = threshold.Rates{
	threshold.Added:   30,
	threshold.Changed: 0,
	threshold.Removed: 0,
}

// Register adds the flags for axes to fs. targetDesc names the judged pair
// (e.g. "(ecosystem, data source)") and keyDesc describes the override key
// vocabulary; both are spliced into the help text.
func Register(fs *pflag.FlagSet, axes []threshold.Axis, targetDesc, keyDesc string) *Flags {
	f := &Flags{axes: axes, defaults: make(map[threshold.Axis]*float64, len(axes))}
	for _, a := range axes {
		v := new(float64)
		*v = Defaults[a]
		f.defaults[a] = v
		fs.Float64Var(v, string(a)+"-rate-threshold", *v,
			fmt.Sprintf("%s rate (%%) threshold per %s; exit non-zero if exceeded", a, targetDesc))
	}
	fs.StringSliceVar(&f.overrides, "rate-threshold-override", nil,
		fmt.Sprintf("override of one axis' threshold for one target; format: <key>=<axis>:<rate> where key is %s and axis is one of %s (repeatable; comma-separated entries also accepted)",
			keyDesc, axisList(axes)))

	fs.Float64Var(&f.legacyThreshold, "change-rate-threshold", 0,
		fmt.Sprintf("DEPRECATED: use the per-axis --<axis>-rate-threshold flags. Single change rate (%%) threshold per %s applied to every axis (%s) alike; cannot be combined with the per-axis flags", targetDesc, axisList(axes)))
	fs.StringSliceVar(&f.legacyOverrides, "change-rate-threshold-override", nil,
		fmt.Sprintf("DEPRECATED: use --rate-threshold-override. Override of --change-rate-threshold; format: <key>=<rate> where key is %s, applied to every axis alike (repeatable; comma-separated entries also accepted); cannot be combined with the per-axis flags", keyDesc))
	return f
}

// Config builds the threshold configuration from whichever flag family was
// used. fs is consulted for which flags appeared on the command line: a
// flag counts as used as soon as it appears, even with an empty value, so
// the rule stays simple to state. Using both families is an error whose
// message spells out the per-axis equivalent of the legacy flags.
func (f *Flags) Config(fs *pflag.FlagSet) (threshold.Config, error) {
	legacyUsed := fs.Changed("change-rate-threshold") || fs.Changed("change-rate-threshold-override")
	axisUsed := fs.Changed("rate-threshold-override")
	for _, a := range f.axes {
		axisUsed = axisUsed || fs.Changed(string(a)+"-rate-threshold")
	}

	switch {
	case legacyUsed && axisUsed:
		return threshold.Config{}, errors.Errorf("unexpected flags. expected: either the per-axis flags (--<axis>-rate-threshold, --rate-threshold-override) or the legacy flags (--change-rate-threshold, --change-rate-threshold-override), actual: both. --change-rate-threshold X is equivalent to %s; --change-rate-threshold-override k=R is equivalent to --rate-threshold-override %s",
			f.legacyEquivalent("X"), f.legacyOverrideEquivalent("k", "R"))
	case legacyUsed:
		ov, err := override.Parse(f.legacyOverrides)
		if err != nil {
			return threshold.Config{}, errors.Wrap(err, "parse change-rate-threshold-override")
		}
		return threshold.Legacy(f.axes, f.legacyThreshold, ov), nil
	default:
		ov, err := override.ParseAxes(f.overrides, f.axes)
		if err != nil {
			return threshold.Config{}, errors.Wrap(err, "parse rate-threshold-override")
		}
		cfg := threshold.Config{Axes: f.axes, Default: make(threshold.Rates, len(f.axes)), Overrides: ov}
		for _, a := range f.axes {
			cfg.Default[a] = *f.defaults[a]
		}
		return cfg, nil
	}
}

func (f *Flags) legacyEquivalent(x string) string {
	parts := make([]string, 0, len(f.axes))
	for _, a := range f.axes {
		parts = append(parts, fmt.Sprintf("--%s-rate-threshold %s", a, x))
	}
	return strings.Join(parts, " ")
}

func (f *Flags) legacyOverrideEquivalent(k, r string) string {
	parts := make([]string, 0, len(f.axes))
	for _, a := range f.axes {
		parts = append(parts, fmt.Sprintf("%s=%s:%s", k, a, r))
	}
	return strings.Join(parts, ",")
}

func axisList(axes []threshold.Axis) string {
	parts := make([]string, 0, len(axes))
	for _, a := range axes {
		parts = append(parts, string(a))
	}
	return strings.Join(parts, "|")
}
