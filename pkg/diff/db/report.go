package db

import (
	"cmp"
	"fmt"
	"io"
	"slices"

	"github.com/pkg/errors"

	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
)

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
			rows = append(rows, reportRow{Ecosystem: d.Ecosystem, SourceDiff: SourceDiff{SourceID: "(none)", Pass: d.Pass}})
			continue
		}
		for _, s := range d.Sources {
			rows = append(rows, reportRow{Ecosystem: d.Ecosystem, SourceDiff: s})
		}
	}

	// Sort: FAIL first, then by max(rate) desc, then by ecosystem asc, source asc.
	// Per-source threshold can hide a high-rate row behind PASS, so surfacing
	// FAIL rows first keeps triage focused on what actually blocks promotion.
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
			cmp.Compare(max(b.DetectionChangeRate, b.KBChangeRate),
				max(a.DetectionChangeRate, a.KBChangeRate)),
			cmp.Compare(a.Ecosystem, b.Ecosystem),
			cmp.Compare(a.SourceID, b.SourceID),
		)
	})

	pass := !slices.ContainsFunc(rows, func(r reportRow) bool { return !r.Pass })

	if _, err := fmt.Fprintf(w, `# Diff Report: DB

## Summary

**Result**: %s

| Ecosystem | Source | Detection Change Rate | KB Change Rate | Threshold | Result |
|-----------|--------|-----------------------|----------------|-----------|--------|
`, resultLabel(pass)); err != nil {
		return false, errors.Wrap(err, "write header")
	}
	for _, r := range rows {
		if _, err := fmt.Fprintf(w, "| %s | %s | %.1f%% | %.1f%% | %.1f%% | %s |\n",
			r.Ecosystem,
			r.SourceID,
			r.DetectionChangeRate,
			r.KBChangeRate,
			r.Threshold,
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

| Ecosystem | Source | Baseline Keys | Target Keys | Added | Removed | Changed | Baseline Criterions | Target Criterions | Matched Criterions |
|-----------|--------|---------------|-------------|-------|---------|---------|---------------------|-------------------|--------------------|
`); err != nil {
			return false, errors.Wrap(err, "write detection header")
		}
		for _, r := range rows {
			if r.BaselineKeys == 0 && r.TargetKeys == 0 {
				continue
			}
			if _, err := fmt.Fprintf(w, "| %s | %s | %d | %d | %d | %d | %d | %d | %d | %d |\n",
				r.Ecosystem, r.SourceID, r.BaselineKeys, r.TargetKeys,
				len(r.Added), len(r.Removed), len(r.Changed),
				r.BaselineCriterions, r.TargetCriterions, r.MatchedCriterions); err != nil {
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

| Ecosystem | Source | Baseline KB Keys | Target KB Keys | Added | Removed | Changed | Baseline KBs | Target KBs | Matched KBs |
|-----------|--------|------------------|----------------|-------|---------|---------|--------------|------------|-------------|
`); err != nil {
			return false, errors.Wrap(err, "write kb header")
		}
		for _, r := range rows {
			if r.BaselineKBKeys == 0 && r.TargetKBKeys == 0 {
				continue
			}
			if _, err := fmt.Fprintf(w, "| %s | %s | %d | %d | %d | %d | %d | %d | %d | %d |\n",
				r.Ecosystem, r.SourceID, r.BaselineKBKeys, r.TargetKBKeys,
				len(r.AddedKBs), len(r.RemovedKBs), len(r.ChangedKBs),
				r.BaselineKBs, r.TargetKBs, r.MatchedKBs); err != nil {
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
			// A source can fail on either rate (e.g. microsoft on KB alone),
			// so the headline shows whichever signal is larger — same rule as
			// the summary sort.
			if _, err := fmt.Fprintf(w, "### %s / %s (%.1f%%)\n\n", r.Ecosystem, r.SourceID, max(r.DetectionChangeRate, r.KBChangeRate)); err != nil {
				return false, errors.Wrapf(err, "write source header %s/%s", r.Ecosystem, r.SourceID)
			}
			for _, l := range []struct {
				label string
				ids   []string
			}{
				{"Added Root IDs", r.Added},
				{"Removed Root IDs", r.Removed},
				{"Changed Root IDs", r.Changed},
				{"Added KB IDs", r.AddedKBs},
				{"Removed KB IDs", r.RemovedKBs},
				{"Changed KB IDs", r.ChangedKBs},
			} {
				slices.Sort(l.ids)
				if err := writeIDList(w, l.label, l.ids); err != nil {
					return false, errors.Wrapf(err, "%s/%s %s", r.Ecosystem, r.SourceID, l.label)
				}
			}
		}
	}

	return pass, nil
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
