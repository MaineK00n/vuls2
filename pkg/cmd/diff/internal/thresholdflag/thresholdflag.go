// Package thresholdflag registers the threshold flags shared by the diff db
// and diff detection commands and turns them into a threshold.Threshold.
//
// Two flag families exist and are mutually exclusive on one command line:
//
//   - per axis: `--rate-threshold <axis>:<rate>` (the default of one axis;
//     axes not named keep the command's built-in default) and
//     `--rate-threshold-override <key>=<axis>:<rate>` (the same entry with
//     a target key in front);
//   - legacy: `--change-rate-threshold` and
//     `--change-rate-threshold-override <key>=<rate>`, kept for callers of
//     the pre-axis CLI; the single value applies to every axis alike. Both
//     are marked deprecated with pflag: hidden from --help, and using one
//     prints a notice on stderr at parse time. They go away once the known
//     callers have migrated.
package thresholdflag

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/pflag"

	"github.com/MaineK00n/vuls2/pkg/cmd/diff/internal/override"
	"github.com/MaineK00n/vuls2/pkg/diff/threshold"
)

// Flags holds the parsed values of both flag families for one command.
type Flags struct {
	axes     []threshold.Axis
	defaults threshold.Rates

	thresholds []string
	overrides  []string

	legacyThreshold float64
	legacyOverrides []string
}

// Register adds the flags for axes to fs, with defaults as the built-in
// threshold of each axis (the command's Defaults). targetDesc names the
// judged pair (e.g. "(ecosystem, data source)") and keyDesc describes the
// override key vocabulary; both are spliced into the help text.
func Register(fs *pflag.FlagSet, axes []threshold.Axis, defaults threshold.Rates, targetDesc, keyDesc string) *Flags {
	f := &Flags{axes: axes, defaults: defaults}
	fs.StringSliceVar(&f.thresholds, "rate-threshold", renderDefaults(axes, defaults),
		fmt.Sprintf("default rate (%%) threshold of one axis, per %s; exit non-zero if exceeded. format: <axis>:<rate> where axis is one of %s; axes not named keep their built-in default (repeatable; comma-separated entries also accepted)",
			targetDesc, axisList(axes)))
	fs.StringSliceVar(&f.overrides, "rate-threshold-override", nil,
		fmt.Sprintf("override of one axis' threshold for one target; format: <key>=<axis>:<rate> where key is %s and axis is one of %s (repeatable; comma-separated entries also accepted)",
			keyDesc, axisList(axes)))

	// The legacy family stays parseable but is hidden from --help, and
	// pflag announces the deprecation on stderr whenever one is used, so
	// callers still on it see the notice in their CI logs. It is removed
	// once the two known callers (vulsio/vuls-data-db and one more CI
	// consumer) have moved to the per-axis flags.
	fs.Float64Var(&f.legacyThreshold, "change-rate-threshold", 0,
		fmt.Sprintf("single change rate (%%) threshold per %s applied to every axis (%s) alike", targetDesc, axisList(axes)))
	_ = fs.MarkDeprecated("change-rate-threshold",
		fmt.Sprintf("use --rate-threshold <axis>:<rate>; the single value is applied to every axis (%s) independently, which is looser than the former combined rate. The flag is removed once the known callers have migrated", axisList(axes)))
	fs.StringSliceVar(&f.legacyOverrides, "change-rate-threshold-override", nil,
		fmt.Sprintf("override of --change-rate-threshold; format: <key>=<rate> where key is %s, applied to every axis alike", keyDesc))
	_ = fs.MarkDeprecated("change-rate-threshold-override", "use --rate-threshold-override <key>=<axis>:<rate>. The flag is removed once the known callers have migrated")
	return f
}

// Threshold builds the threshold from whichever flag family was
// used. fs is consulted for which flags appeared on the command line: a
// flag counts as used as soon as it appears, even with an empty value, so
// the rule stays simple to state. Using both families is an error whose
// message spells out the per-axis equivalent of the legacy flags.
func (f *Flags) Threshold(fs *pflag.FlagSet) (threshold.Threshold, error) {
	legacyUsed := fs.Changed("change-rate-threshold") || fs.Changed("change-rate-threshold-override")
	axisUsed := fs.Changed("rate-threshold") || fs.Changed("rate-threshold-override")

	switch {
	case legacyUsed && axisUsed:
		return threshold.Threshold{}, errors.Errorf("unexpected flags. expected: either the per-axis flags (--rate-threshold, --rate-threshold-override) or the legacy flags (--change-rate-threshold, --change-rate-threshold-override), actual: both. --change-rate-threshold X is equivalent to --rate-threshold %s; --change-rate-threshold-override k=R is equivalent to --rate-threshold-override %s",
			f.legacyEquivalent("X"), f.legacyOverrideEquivalent("k", "R"))
	case legacyUsed:
		ov, err := override.Parse(f.legacyOverrides)
		if err != nil {
			return threshold.Threshold{}, errors.Wrap(err, "parse change-rate-threshold-override")
		}
		return threshold.Legacy(f.axes, f.legacyThreshold, ov), nil
	default:
		// The slice holds the rendered built-in defaults when the flag was
		// not given, or the user's entries when it was (pflag replaces the
		// default rather than appending); either way, parse and lay the
		// result over the built-in defaults so unnamed axes keep theirs.
		def, err := override.ParseDefaults(f.thresholds, f.axes)
		if err != nil {
			return threshold.Threshold{}, errors.Wrap(err, "parse rate-threshold")
		}
		ov, err := override.ParseAxes(f.overrides, f.axes)
		if err != nil {
			return threshold.Threshold{}, errors.Wrap(err, "parse rate-threshold-override")
		}
		th := threshold.Threshold{Axes: f.axes, Default: make(threshold.Rates, len(f.axes)), Overrides: ov}
		for _, a := range f.axes {
			th.Default[a] = f.defaults[a]
			if v, ok := def[a]; ok {
				th.Default[a] = v
			}
		}
		return th, nil
	}
}

// renderDefaults renders defaults in axes order as "<axis>:<rate>"
// entries, the flag's default value as shown in --help.
func renderDefaults(axes []threshold.Axis, defaults threshold.Rates) []string {
	entries := make([]string, 0, len(axes))
	for _, a := range axes {
		entries = append(entries, fmt.Sprintf("%s:%s", a, strconv.FormatFloat(defaults[a], 'f', -1, 64)))
	}
	return entries
}

func (f *Flags) legacyEquivalent(x string) string {
	parts := make([]string, 0, len(f.axes))
	for _, a := range f.axes {
		parts = append(parts, fmt.Sprintf("%s:%s", a, x))
	}
	return strings.Join(parts, ",")
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
