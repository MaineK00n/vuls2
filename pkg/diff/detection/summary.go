package detection

import (
	"github.com/MaineK00n/vuls2/pkg/diff/summary"
)

// summarize projects diffm onto the --output-json contract (package summary).
//
// pass is the report's overall verdict. It also covers files compared
// without any detected source, which the report renders as a "(none)"
// placeholder row; those have no source a consumer could act on and are not
// emitted, so Summary.Pass can be false while every emitted row passes.
func summarize(diffm map[string]FileDiff, pass bool) summary.Summary {
	var rows []summary.Row
	for _, d := range diffm {
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
