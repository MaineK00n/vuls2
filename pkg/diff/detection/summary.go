package detection

import (
	"github.com/MaineK00n/vuls2/pkg/diff/summary"
)

// summarize projects diffm onto the --output-json contract (package summary),
// one row per row of the report's Summary table.
//
// A file in which neither side detected anything is the report's "(none)"
// placeholder row; it is emitted with an empty Source, a zero rate and the
// threshold that would have applied to the file (override resolution with
// no source), and it always passes since there is nothing to compare.
func summarize(diffm map[string]FileDiff, pass bool, threshold float64, overrides map[string]float64) summary.Summary {
	var rows []summary.Row
	for _, d := range diffm {
		if len(d.Sources) == 0 {
			rows = append(rows, summary.Row{
				Name:      d.Name,
				Threshold: resolveThreshold(overrides, threshold, d.Name, ""),
				Pass:      d.Pass,
			})
			continue
		}
		for _, s := range d.Sources {
			rows = append(rows, summary.Row{
				Name:       d.Name,
				Source:     string(s.SourceID),
				ChangeRate: s.ChangeRate,
				Threshold:  s.Threshold,
				Pass:       s.Pass,
			})
		}
	}
	return summary.New(summary.CheckDetection, pass, rows)
}
