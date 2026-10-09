package db

import (
	"cmp"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/pkg/errors"

	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"

	"github.com/MaineK00n/vuls2/pkg/diff/threshold"
)

// placeholderSourceID marks the row emitted for an ecosystem compared
// without any per-source data; no threshold applies to it.
const placeholderSourceID = "(none)"

// reportRow flattens (ecosystem, source) for rendering and sorting.
type reportRow struct {
	Ecosystem ecosystemTypes.Ecosystem
	SourceDiff
}

// generateReport writes a Markdown report for DB diff to w.
// It returns whether all (ecosystem, source) pairs passed and any write error.
func generateReport(w io.Writer, diffs []EcosystemDiff) (bool, error) {
	if len(diffs) == 0 {
		return true, errors.New("no ecosystems to compare")
	}

	var rows []reportRow
	for _, d := range diffs {
		if len(d.Sources) == 0 {
			// A compared ecosystem with no per-source data still gets a
			// placeholder row so the report stays explicit about what was
			// compared instead of silently omitting it.
			rows = append(rows, reportRow{Ecosystem: d.Ecosystem, SourceDiff: SourceDiff{SourceID: placeholderSourceID, Pass: d.Pass}})
			continue
		}
		for _, s := range d.Sources {
			rows = append(rows, reportRow{Ecosystem: d.Ecosystem, SourceDiff: s})
		}
	}

	// Sort: FAIL first, then by the max rate over every (bucket, axis) desc,
	// then by ecosystem asc, source asc. Per-source thresholds can hide a
	// high-rate row behind PASS, so surfacing FAIL rows first keeps triage
	// focused on what actually blocks promotion.
	slices.SortFunc(rows, func(a, b reportRow) int {
		return cmp.Or(
			func() int {
				switch {
				case !a.Pass && b.Pass:
					return -1
				case a.Pass && !b.Pass:
					return +1
				default:
					return 0
				}
			}(),
			cmp.Compare(maxRate(b.SourceDiff), maxRate(a.SourceDiff)),
			cmp.Compare(a.Ecosystem, b.Ecosystem),
			cmp.Compare(a.SourceID, b.SourceID),
		)
	})

	pass := !slices.ContainsFunc(rows, func(r reportRow) bool { return !r.Pass })

	if _, err := fmt.Fprintf(w, `# Diff Report: DB

## Summary

**Result**: %s

| Ecosystem | Source | Detection (added / changed / removed) | KB (added / changed / removed) | Threshold (added / changed / removed) | Result |
|-----------|--------|---------------------------------------|--------------------------------|---------------------------------------|--------|
`, resultLabel(pass)); err != nil {
		return false, errors.Wrap(err, "write header")
	}
	for _, r := range rows {
		// Rates above their threshold are rendered in bold so a FAIL row
		// shows which (bucket, axis) tripped without reading Details.
		if _, err := fmt.Fprintf(w, "| %s | %s | %s | %s | %s | %s |\n",
			r.Ecosystem,
			r.SourceID,
			threshold.Format(Axes, r.DetectionRates, r.Thresholds),
			threshold.Format(Axes, r.KBRates, r.Thresholds),
			thresholdCell(r.SourceDiff),
			resultLabel(r.Pass),
		); err != nil {
			return false, errors.Wrap(err, "write summary row")
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return false, errors.Wrap(err, "write summary separator")
	}

	if slices.ContainsFunc(rows, func(r reportRow) bool {
		return r.BaselineKeys > 0 || r.TargetKeys > 0
	}) {
		if _, err := fmt.Fprintf(w, `## Detection

| Ecosystem | Source | Baseline Keys | Target Keys | Added | Changed | Removed | Baseline Criterions | Target Criterions | Matched Criterions | Added Criterions | Changed Criterions | Removed Criterions |
|-----------|--------|---------------|-------------|-------|---------|---------|---------------------|-------------------|--------------------|------------------|--------------------|--------------------|
`); err != nil {
			return false, errors.Wrap(err, "write detection header")
		}
		for _, r := range rows {
			if r.BaselineKeys == 0 && r.TargetKeys == 0 {
				continue
			}
			if _, err := fmt.Fprintf(w, "| %s | %s | %d | %d | %d | %d | %d | %d | %d | %d | %d | %d | %d |\n",
				r.Ecosystem, r.SourceID, r.BaselineKeys, r.TargetKeys,
				len(r.Added), len(r.Changed), len(r.Removed),
				r.BaselineCriterions, r.TargetCriterions, r.MatchedCriterions,
				r.AddedCriterions, r.ChangedCriterions, r.RemovedCriterions); err != nil {
				return false, errors.Wrap(err, "write detection row")
			}
		}
		if _, err := fmt.Fprintln(w); err != nil {
			return false, errors.Wrap(err, "write detection separator")
		}
	}

	if slices.ContainsFunc(rows, func(r reportRow) bool {
		return r.BaselineKBKeys > 0 || r.TargetKBKeys > 0
	}) {
		if _, err := fmt.Fprintf(w, `## KB

| Ecosystem | Source | Baseline KB Keys | Target KB Keys | Matched KBs | Added | Changed | Removed |
|-----------|--------|------------------|----------------|-------------|-------|---------|---------|
`); err != nil {
			return false, errors.Wrap(err, "write kb header")
		}
		for _, r := range rows {
			if r.BaselineKBKeys == 0 && r.TargetKBKeys == 0 {
				continue
			}
			if _, err := fmt.Fprintf(w, "| %s | %s | %d | %d | %d | %d | %d | %d |\n",
				r.Ecosystem, r.SourceID, r.BaselineKBKeys, r.TargetKBKeys, r.MatchedKBs,
				len(r.AddedKBs), len(r.ChangedKBs), len(r.RemovedKBs)); err != nil {
				return false, errors.Wrap(err, "write kb row")
			}
		}
		if _, err := fmt.Fprintln(w); err != nil {
			return false, errors.Wrap(err, "write kb separator")
		}
	}

	// Details for FAIL (ecosystem, source) pairs
	var failRows []reportRow
	for _, r := range rows {
		if !r.Pass {
			failRows = append(failRows, r)
		}
	}

	if len(failRows) > 0 {
		if _, err := fmt.Fprintf(w, "## Details (FAIL sources)\n\n"); err != nil {
			return false, errors.Wrap(err, "write details header")
		}
		for _, r := range failRows {
			// The headline names every (bucket, axis) that tripped, with
			// its rate and threshold, so the reason is visible without
			// scanning the Summary row.
			if _, err := fmt.Fprintf(w, "### %s / %s (%s)\n\n", r.Ecosystem, r.SourceID, exceededLabel(r.SourceDiff)); err != nil {
				return false, errors.Wrapf(err, "write source header %s/%s", r.Ecosystem, r.SourceID)
			}
			for _, l := range []struct {
				label string
				ids   []string
			}{
				{"Added Root IDs", r.Added},
				{"Changed Root IDs", r.Changed},
				{"Removed Root IDs", r.Removed},
				{"Added KB IDs", r.AddedKBs},
				{"Changed KB IDs", r.ChangedKBs},
				{"Removed KB IDs", r.RemovedKBs},
			} {
				// Sort a clone: the slices are shared with the caller's
				// diffs, and rendering must not mutate its input.
				ids := slices.Clone(l.ids)
				slices.Sort(ids)
				if err := writeIDList(w, l.label, ids); err != nil {
					return false, errors.Wrapf(err, "%s/%s %s", r.Ecosystem, r.SourceID, l.label)
				}
			}
		}
	}

	return pass, nil
}

// thresholdCell renders the Threshold column; a placeholder row has no
// (ecosystem, source) for a threshold to apply to, so it renders "-" rather
// than a misleading 0.0%.
func thresholdCell(sd SourceDiff) string {
	if sd.SourceID == placeholderSourceID {
		return "-"
	}
	return threshold.FormatThresholds(Axes, sd.Thresholds)
}

// maxRate is the largest rate over both buckets and every axis — the
// Summary sort key within a PASS/FAIL tier.
func maxRate(sd SourceDiff) float64 {
	return max(threshold.Max(Axes, sd.DetectionRates), threshold.Max(Axes, sd.KBRates))
}

// exceededLabel lists every (bucket, axis) above its threshold as
// "detection removed 12.3% > 10.0%", comma-separated, for the Details
// headline of a FAIL source.
func exceededLabel(sd SourceDiff) string {
	var parts []string
	for _, b := range []struct {
		name  string
		rates threshold.Rates
	}{
		{"detection", sd.DetectionRates},
		{"kb", sd.KBRates},
	} {
		for _, a := range threshold.Exceeded(Axes, b.rates, sd.Thresholds) {
			parts = append(parts, fmt.Sprintf("%s %s %s", b.name, a, threshold.FormatExceeded(b.rates[a], sd.Thresholds[a])))
		}
	}
	return strings.Join(parts, ", ")
}

func resultLabel(pass bool) string {
	if pass {
		return "PASS"
	}
	return "**FAIL**"
}

// writeIDList writes a "#### <label> (N)" section with a bulleted list of IDs.
// It is a no-op when ids is empty.
func writeIDList(w io.Writer, label string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	if _, err := fmt.Fprintf(w, "#### %s (%d)\n\n", label, len(ids)); err != nil {
		return errors.Wrap(err, "write header")
	}
	for _, id := range ids {
		if _, err := fmt.Fprintf(w, "- %s\n", id); err != nil {
			return errors.Wrap(err, "write id")
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return errors.Wrap(err, "write separator")
	}
	return nil
}
