package search

import (
	"bytes"
	"strings"
	"testing"

	"github.com/MaineK00n/vuls2/pkg/detect/ospkg/microsoft"
)

func TestPrintKBExpandTree(t *testing.T) {
	tests := []struct {
		name             string
		exp              *microsoft.ExpandResult
		release          string
		coveredAfter     []string
		unappliedAfter   []string
		coveredDropped   []string
		unappliedDropped []string
		wantContains     []string
		wantNotContains  []string
	}{
		{
			name: "single applied root with KB-level chain",
			exp: &microsoft.ExpandResult{
				Inputs:    microsoft.ExpandInputs{Applied: []string{"5000802"}},
				Covered:   []string{"5000802"},
				Unapplied: []string{"5001330"},
				Edges: map[string][]microsoft.ExpandEdge{
					"5000802": {{To: "5001330", Source: "microsoft-cvrf", Level: microsoft.ExpandEdgeLevelKB}},
				},
			},
			wantContains: []string{
				"Inputs:",
				"Applied:   5000802",
				"Unapplied: (none)",
				"Conflicts (in both Applied & Unapplied → treated as Unapplied):",
				"(none)",
				"Supersession chains:",
				"5000802  [input:applied, covered]",
				"└─ [microsoft-cvrf, KB-level] 5001330  [discovered, unapplied]",
				"Result:",
				"Covered:   5000802",
				"Unapplied: 5001330",
			},
			wantNotContains: []string{"Release filter"},
		},
		{
			name: "applied input that is also unapplied input is flagged conflict",
			exp: &microsoft.ExpandResult{
				Inputs:    microsoft.ExpandInputs{Applied: []string{"5000802"}, Unapplied: []string{"5000802"}},
				Covered:   nil,
				Unapplied: []string{"5000802"},
				Conflicts: []string{"5000802"},
			},
			wantContains: []string{
				"Conflicts (in both Applied & Unapplied → treated as Unapplied):",
				"5000802",
				"5000802  [input:applied, input:unapplied, conflict→unapplied, unapplied]",
			},
		},
		{
			name: "edges from multiple data sources show source attribution",
			exp: &microsoft.ExpandResult{
				Inputs:    microsoft.ExpandInputs{Applied: []string{"5000802"}},
				Covered:   []string{"5000802"},
				Unapplied: []string{"5001330"},
				Edges: map[string][]microsoft.ExpandEdge{
					"5000802": {
						{To: "5001330", Source: "microsoft-cvrf", Level: microsoft.ExpandEdgeLevelKB},
						{To: "5001330", Source: "microsoft-msuc", Level: microsoft.ExpandEdgeLevelUpdate, UpdateID: "abc-123"},
					},
				},
			},
			wantContains: []string{
				"[microsoft-cvrf, KB-level] 5001330",
				"[microsoft-msuc, Update abc-123] 5001330",
				"(→ see above)",
			},
		},
		{
			name: "release filter section is rendered when release is set",
			exp: &microsoft.ExpandResult{
				Inputs:    microsoft.ExpandInputs{Applied: []string{"5000802"}},
				Covered:   []string{"5000802"},
				Unapplied: []string{"5001330", "9999999"},
			},
			release:          "Windows 10 Version 22H2 for x64-based Systems",
			coveredAfter:     []string{"5000802"},
			unappliedAfter:   []string{"5001330"},
			unappliedDropped: []string{"9999999"},
			wantContains: []string{
				`Release filter ("Windows 10 Version 22H2 for x64-based Systems"):`,
				"Covered after filter:   5000802",
				"Unapplied after filter: 5001330",
				"Dropped:                9999999",
			},
		},
		{
			name: "cycle in supersession is broken with see-above",
			exp: &microsoft.ExpandResult{
				Inputs:    microsoft.ExpandInputs{Applied: []string{"A"}},
				Covered:   []string{"A", "B"},
				Unapplied: nil,
				Edges: map[string][]microsoft.ExpandEdge{
					"A": {{To: "B", Source: "microsoft-cvrf", Level: microsoft.ExpandEdgeLevelKB}},
					"B": {{To: "A", Source: "microsoft-cvrf", Level: microsoft.ExpandEdgeLevelKB}},
				},
			},
			wantContains: []string{
				"A  [input:applied, covered]",
				"└─ [microsoft-cvrf, KB-level] B  [discovered, covered]",
				"(→ see above)",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := printKBExpandTree(&buf, tt.exp, tt.release, tt.coveredAfter, tt.unappliedAfter, tt.coveredDropped, tt.unappliedDropped); err != nil {
				t.Fatalf("printKBExpandTree() error = %v", err)
			}
			got := buf.String()
			for _, want := range tt.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("output missing %q\nfull output:\n%s", want, got)
				}
			}
			for _, notWant := range tt.wantNotContains {
				if strings.Contains(got, notWant) {
					t.Errorf("output unexpectedly contains %q\nfull output:\n%s", notWant, got)
				}
			}
		})
	}
}
