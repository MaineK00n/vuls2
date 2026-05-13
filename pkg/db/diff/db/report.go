package db

import (
	"cmp"
	"fmt"
	"io"
	"slices"

	"github.com/pkg/errors"
)

// generateReport writes a Markdown report for DB diff to w.
// It returns whether all ecosystems passed and any write error.
func generateReport(w io.Writer, diffs []EcosystemDiff, changeRateThreshold float64) (bool, error) {
	if len(diffs) == 0 {
		return true, errors.New("no ecosystems to compare")
	}

	// Sort: FAIL first, then by max(rate) desc, then by ecosystem asc.
	// Per-target threshold can hide a high-rate row behind PASS, so surfacing
	// FAIL rows first keeps triage focused on what actually blocks promotion.
	slices.SortFunc(diffs, func(a, b EcosystemDiff) int {
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
			-cmp.Compare(max(a.DetectionChangeRate, a.KBChangeRate),
				max(b.DetectionChangeRate, b.KBChangeRate)),
			cmp.Compare(a.Ecosystem, b.Ecosystem),
		)
	})

	pass := !slices.ContainsFunc(diffs, func(r EcosystemDiff) bool { return !r.Pass })

	if _, err := fmt.Fprintf(w, `# Diff Report: DB

## Summary

**Result**: %s (Default Change Rate Threshold: %.1f%%)

| Ecosystem | Detection Change Rate | KB Change Rate | Override | Result |
|-----------|-----------------------|----------------|----------|--------|
`,
		resultLabel(pass),
		changeRateThreshold,
	); err != nil {
		return false, errors.Wrap(err, "write header")
	}
	for _, d := range diffs {
		if _, err := fmt.Fprintf(w, "| %s | %.1f%% | %.1f%% | %s | %s |\n",
			d.Ecosystem,
			d.DetectionChangeRate,
			d.KBChangeRate,
			overrideLabel(d.Threshold, d.ThresholdOverridden),
			resultLabel(d.Pass),
		); err != nil {
			return false, errors.Wrap(err, "write summary row")
		}
	}
	if _, err := fmt.Fprintln(w); err != nil {
		return false, errors.Wrap(err, "write summary separator")
	}

	if slices.ContainsFunc(diffs, func(d EcosystemDiff) bool {
		return d.BaselineKeys > 0 || d.TargetKeys > 0
	}) {
		if _, err := fmt.Fprintf(w, `## Detection

| Ecosystem | Baseline Keys | Target Keys | Added | Removed | Changed | Baseline Criterions | Target Criterions | Matched Criterions |
|-----------|---------------|-------------|-------|---------|---------|---------------------|-------------------|--------------------|
`); err != nil {
			return false, errors.Wrap(err, "write detection header")
		}
		for _, d := range diffs {
			if d.BaselineKeys == 0 && d.TargetKeys == 0 {
				continue
			}
			if _, err := fmt.Fprintf(w, "| %s | %d | %d | %d | %d | %d | %d | %d | %d |\n",
				d.Ecosystem, d.BaselineKeys, d.TargetKeys,
				len(d.Added), len(d.Removed), len(d.Changed),
				d.BaselineCriterions, d.TargetCriterions, d.MatchedCriterions); err != nil {
				return false, errors.Wrap(err, "write detection row")
			}
		}
		if _, err := fmt.Fprintln(w); err != nil {
			return false, errors.Wrap(err, "write detection separator")
		}
	}

	if slices.ContainsFunc(diffs, func(d EcosystemDiff) bool {
		return d.BaselineKBKeys > 0 || d.TargetKBKeys > 0
	}) {
		if _, err := fmt.Fprintf(w, `## KB

| Ecosystem | Baseline KB Keys | Target KB Keys | Added | Removed | Changed | Baseline KBs | Target KBs | Matched KBs |
|-----------|------------------|----------------|-------|---------|---------|--------------|------------|-------------|
`); err != nil {
			return false, errors.Wrap(err, "write kb header")
		}
		for _, d := range diffs {
			if d.BaselineKBKeys == 0 && d.TargetKBKeys == 0 {
				continue
			}
			if _, err := fmt.Fprintf(w, "| %s | %d | %d | %d | %d | %d | %d | %d | %d |\n",
				d.Ecosystem, d.BaselineKBKeys, d.TargetKBKeys,
				len(d.AddedKBs), len(d.RemovedKBs), len(d.ChangedKBs),
				d.BaselineKBs, d.TargetKBs, d.MatchedKBs); err != nil {
				return false, errors.Wrap(err, "write kb row")
			}
		}
		if _, err := fmt.Fprintln(w); err != nil {
			return false, errors.Wrap(err, "write kb separator")
		}
	}

	// Details for FAIL ecosystems
	var failDiffs []EcosystemDiff
	for _, d := range diffs {
		if !d.Pass {
			failDiffs = append(failDiffs, d)
		}
	}

	if len(failDiffs) > 0 {
		if _, err := fmt.Fprintf(w, "## Details (FAIL ecosystems)\n\n"); err != nil {
			return false, errors.Wrap(err, "write details header")
		}
		for _, d := range failDiffs {
			if _, err := fmt.Fprintf(w, "### %s (%.1f%%)\n\n", d.Ecosystem, d.DetectionChangeRate); err != nil {
				return false, errors.Wrapf(err, "write ecosystem header %s", d.Ecosystem)
			}
			if err := writeIDList(w, "Added Root IDs", d.Added); err != nil {
				return false, errors.Wrapf(err, "%s added", d.Ecosystem)
			}
			if err := writeIDList(w, "Removed Root IDs", d.Removed); err != nil {
				return false, errors.Wrapf(err, "%s removed", d.Ecosystem)
			}
			if err := writeIDList(w, "Changed Root IDs", d.Changed); err != nil {
				return false, errors.Wrapf(err, "%s changed", d.Ecosystem)
			}
			if err := writeIDList(w, "Added KB IDs", d.AddedKBs); err != nil {
				return false, errors.Wrapf(err, "%s added KBs", d.Ecosystem)
			}
			if err := writeIDList(w, "Removed KB IDs", d.RemovedKBs); err != nil {
				return false, errors.Wrapf(err, "%s removed KBs", d.Ecosystem)
			}
			if err := writeIDList(w, "Changed KB IDs", d.ChangedKBs); err != nil {
				return false, errors.Wrapf(err, "%s changed KBs", d.Ecosystem)
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

// overrideLabel renders the override threshold (e.g. "25.0%") for rows where
// an override matched, and an empty cell otherwise. Default-threshold rows
// stay blank because the default value is already shown in the summary
// header — duplicating it per-row added noise without useful signal.
func overrideLabel(t float64, overridden bool) string {
	if overridden {
		return fmt.Sprintf("%.1f%%", t)
	}
	return ""
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
