package search

import (
	"bytes"
	"strings"
	"testing"

	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/detect/ospkg/microsoft"
)

func TestPrintKBExpandTree(t *testing.T) {
	type args struct {
		exp              *microsoft.ExpandResult
		datasources      []sourceTypes.SourceID
		releases         []string
		coveredAfter     []string
		unappliedAfter   []string
		coveredDropped   []string
		unappliedDropped []string
	}
	tests := []struct {
		name            string
		args            args
		wantContains    []string
		wantNotContains []string
	}{
		{
			name: "single applied root with KB-level chain",
			args: args{
				exp: &microsoft.ExpandResult{
					Inputs:    microsoft.ExpandInputs{Applied: []string{"5000802"}},
					Covered:   []string{"5000802"},
					Unapplied: []string{"5001330"},
					Edges: map[string][]microsoft.ExpandEdge{
						"5000802": {{To: "5001330", Source: "microsoft-cvrf", Level: microsoft.ExpandEdgeLevelKB}},
					},
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
				"    Superseded by:",
				"      └─ [microsoft-cvrf, KB-level, superseded by] 5001330  [discovered, unapplied]",
				"Result:",
				"Covered:   5000802",
				"Unapplied: 5001330",
			},
			wantNotContains: []string{"Release filter", "Data sources:", "    Supersedes:"},
		},
		{
			name: "applied input that is also unapplied input is flagged conflict",
			args: args{
				exp: &microsoft.ExpandResult{
					Inputs:    microsoft.ExpandInputs{Applied: []string{"5000802"}, Unapplied: []string{"5000802"}},
					Covered:   nil,
					Unapplied: []string{"5000802"},
					Conflicts: []string{"5000802"},
				},
			},
			wantContains: []string{
				"Conflicts (in both Applied & Unapplied → treated as Unapplied):",
				"5000802",
				"5000802  [input:applied, input:unapplied, conflict→unapplied, unapplied]",
			},
		},
		{
			name: "edges from multiple data sources show source attribution",
			args: args{
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
			},
			wantContains: []string{
				"    Superseded by:",
				"[microsoft-cvrf, KB-level, superseded by] 5001330",
				"[microsoft-msuc, Updates abc-123, superseded by] 5001330",
				"(→ see above)",
			},
		},
		{
			name: "release filter section is rendered when a single release is set",
			args: args{
				exp: &microsoft.ExpandResult{
					Inputs:    microsoft.ExpandInputs{Applied: []string{"5000802"}},
					Covered:   []string{"5000802"},
					Unapplied: []string{"5001330", "9999999"},
				},
				releases:         []string{"Windows 10 Version 22H2 for x64-based Systems"},
				coveredAfter:     []string{"5000802"},
				unappliedAfter:   []string{"5001330"},
				unappliedDropped: []string{"9999999"},
			},
			wantContains: []string{
				`Release filter ("Windows 10 Version 22H2 for x64-based Systems"):`,
				"Covered after filter:   5000802",
				"Unapplied after filter: 5001330",
				"Dropped:                9999999",
			},
		},
		{
			name: "release filter renders bracketed list when multiple releases are set",
			args: args{
				exp: &microsoft.ExpandResult{
					Inputs:    microsoft.ExpandInputs{Applied: []string{"5000802"}},
					Covered:   []string{"5000802"},
					Unapplied: []string{"5001330"},
				},
				releases: []string{
					"Windows 10 Version 22H2 for x64-based Systems",
					"Windows 11 Version 23H2 for x64-based Systems",
				},
				coveredAfter:   []string{"5000802"},
				unappliedAfter: []string{"5001330"},
			},
			wantContains: []string{
				`Release filter (["Windows 10 Version 22H2 for x64-based Systems", "Windows 11 Version 23H2 for x64-based Systems"]):`,
				"Covered after filter:   5000802",
				"Unapplied after filter: 5001330",
				"Dropped:                (none)",
			},
		},
		{
			name: "datasource filter is reflected in the inputs section",
			args: args{
				exp: &microsoft.ExpandResult{
					Inputs:    microsoft.ExpandInputs{Applied: []string{"5000802"}},
					Covered:   []string{"5000802"},
					Unapplied: nil,
				},
				datasources: []sourceTypes.SourceID{"microsoft-cvrf", "microsoft-msuc"},
			},
			wantContains: []string{
				"Data sources: microsoft-cvrf microsoft-msuc",
			},
		},
		{
			name: "newest input with Supersedes-only chain shows backward section",
			args: args{
				exp: &microsoft.ExpandResult{
					Inputs:    microsoft.ExpandInputs{Applied: []string{"7000004"}},
					Covered:   []string{"7000002", "7000003", "7000004"},
					Unapplied: nil,
					Edges: map[string][]microsoft.ExpandEdge{
						"7000003": {{To: "7000004", Source: "microsoft-cvrf", Level: microsoft.ExpandEdgeLevelKB}},
						"7000002": {{To: "7000003", Source: "microsoft-cvrf", Level: microsoft.ExpandEdgeLevelKB}},
					},
				},
			},
			wantContains: []string{
				"7000004  [input:applied, covered]",
				"    Supersedes:",
				"      └─ [microsoft-cvrf, KB-level, supersedes] 7000003  [discovered, covered]",
				"          └─ [microsoft-cvrf, KB-level, supersedes] 7000002  [discovered, covered]",
			},
			wantNotContains: []string{"    Superseded by:"},
		},
		{
			name: "intermediate input renders both Superseded by and Supersedes sections",
			args: args{
				exp: &microsoft.ExpandResult{
					Inputs:    microsoft.ExpandInputs{Applied: []string{"7000003"}},
					Covered:   []string{"7000002", "7000003"},
					Unapplied: []string{"7000004"},
					Edges: map[string][]microsoft.ExpandEdge{
						"7000003": {{To: "7000004", Source: "microsoft-cvrf", Level: microsoft.ExpandEdgeLevelKB}},
						"7000002": {{To: "7000003", Source: "microsoft-cvrf", Level: microsoft.ExpandEdgeLevelKB}},
					},
				},
			},
			wantContains: []string{
				"7000003  [input:applied, covered]",
				"    Superseded by:",
				"      └─ [microsoft-cvrf, KB-level, superseded by] 7000004  [discovered, unapplied]",
				"    Supersedes:",
				"      └─ [microsoft-cvrf, KB-level, supersedes] 7000002  [discovered, covered]",
			},
		},
		{
			name: "input KB unknown to DB renders as a leaf with no sections",
			args: args{
				exp: &microsoft.ExpandResult{
					Inputs:    microsoft.ExpandInputs{Applied: []string{"9999999"}},
					Covered:   []string{"9999999"},
					Unapplied: nil,
				},
			},
			wantContains: []string{
				"9999999  [input:applied, covered]",
			},
			wantNotContains: []string{
				"    Superseded by:",
				"    Supersedes:",
			},
		},
		{
			name: "cycle in supersession is broken with see-above",
			args: args{
				exp: &microsoft.ExpandResult{
					Inputs:    microsoft.ExpandInputs{Applied: []string{"A"}},
					Covered:   []string{"A", "B"},
					Unapplied: nil,
					Edges: map[string][]microsoft.ExpandEdge{
						"A": {{To: "B", Source: "microsoft-cvrf", Level: microsoft.ExpandEdgeLevelKB}},
						"B": {{To: "A", Source: "microsoft-cvrf", Level: microsoft.ExpandEdgeLevelKB}},
					},
				},
			},
			wantContains: []string{
				"A  [input:applied, covered]",
				"      └─ [microsoft-cvrf, KB-level, superseded by] B  [discovered, covered]",
				"      └─ [microsoft-cvrf, KB-level, supersedes] B  (→ see above)",
			},
		},
		{
			// Multiple Update-level attestations from the same source to
			// the same target (e.g. several MSUC Update entries each
			// documenting "5000802 SupersededBy 5001330") collapse into a
			// single line that lists all UpdateIDs in deterministic order.
			// A KB-level attestation from the same source joins via
			// "KB-level + Updates ..." so the data sources stay grouped.
			name: "multiple Update attestations from one source are consolidated",
			args: args{
				exp: &microsoft.ExpandResult{
					Inputs:    microsoft.ExpandInputs{Applied: []string{"5000802"}},
					Covered:   []string{"5000802"},
					Unapplied: []string{"5001330"},
					Edges: map[string][]microsoft.ExpandEdge{
						"5000802": {
							{To: "5001330", Source: "microsoft-cvrf", Level: microsoft.ExpandEdgeLevelKB},
							{To: "5001330", Source: "microsoft-msuc", Level: microsoft.ExpandEdgeLevelKB},
							{To: "5001330", Source: "microsoft-msuc", Level: microsoft.ExpandEdgeLevelUpdate, UpdateID: "def-456"},
							{To: "5001330", Source: "microsoft-msuc", Level: microsoft.ExpandEdgeLevelUpdate, UpdateID: "abc-123"},
							{To: "5001330", Source: "microsoft-msuc", Level: microsoft.ExpandEdgeLevelUpdate, UpdateID: "abc-123"},
						},
					},
				},
			},
			wantContains: []string{
				"[microsoft-cvrf, KB-level, superseded by] 5001330  [discovered, unapplied]",
				"[microsoft-msuc, KB-level + Updates abc-123, def-456, superseded by] 5001330",
			},
			wantNotContains: []string{
				"[microsoft-msuc, Update abc-123,",
				"[microsoft-msuc, Update def-456,",
				// no separate Updates-only line — KB-level merged into the
				// same msuc label
				"[microsoft-msuc, Updates abc-123, def-456, superseded by]",
			},
		},
		{
			// Defensive: if microsoft.ExpandKBs ever emits an Update-level
			// edge whose UpdateID is empty (current MSUC/wsusscn2 data
			// always populate it, but vuls-data-update could in principle
			// produce malformed records), the explain label must still
			// reflect that the attestation came from Update-level data
			// rather than silently dropping the level info.
			name: "Update-level edge with empty UpdateID renders Update-level placeholder",
			args: args{
				exp: &microsoft.ExpandResult{
					Inputs:    microsoft.ExpandInputs{Applied: []string{"5000802"}},
					Covered:   []string{"5000802"},
					Unapplied: []string{"5001330"},
					Edges: map[string][]microsoft.ExpandEdge{
						"5000802": {
							{To: "5001330", Source: "microsoft-msuc", Level: microsoft.ExpandEdgeLevelUpdate, UpdateID: ""},
						},
					},
				},
			},
			wantContains: []string{
				"[microsoft-msuc, Update-level, superseded by] 5001330  [discovered, unapplied]",
			},
			wantNotContains: []string{
				"[microsoft-msuc, superseded by] 5001330",
				"[microsoft-msuc, Updates ",
			},
		},
		{
			// Mixed-direction discovery: an applied root (R) supersedes a
			// shared older KB (S). S is also superseded by a parallel newer
			// KB (P) on a different product line, which itself is superseded
			// by P2. The bidirectional ExpandKBs walk reaches P and P2 via
			// "backward to S, then forward to P, then forward to P2"; the
			// explain tree must surface them so the user can trace where
			// P/P2 in Unapplied came from. This case mirrors the production
			// 5083769 → 5044284 → 5082063 → 5091157 chain (Win11 root and
			// Server 24H2 parallel line sharing 5044284 as ancestor).
			name: "mixed-direction chain surfaces parallel newer KBs",
			args: args{
				exp: &microsoft.ExpandResult{
					Inputs:    microsoft.ExpandInputs{Applied: []string{"R"}},
					Covered:   []string{"R", "S"},
					Unapplied: []string{"P", "P2"},
					Edges: map[string][]microsoft.ExpandEdge{
						"S": {
							{To: "R", Source: "microsoft-msuc", Level: microsoft.ExpandEdgeLevelUpdate, UpdateID: "ud-r"},
							{To: "P", Source: "microsoft-msuc", Level: microsoft.ExpandEdgeLevelUpdate, UpdateID: "ud-p"},
						},
						"P": {
							{To: "P2", Source: "microsoft-msuc", Level: microsoft.ExpandEdgeLevelKB},
						},
					},
				},
			},
			wantContains: []string{
				"R  [input:applied, covered]",
				"    Supersedes:",
				"      └─ [microsoft-msuc, Updates ud-r, supersedes] S  [discovered, covered]",
				"          └─ [microsoft-msuc, Updates ud-p, superseded by] P  [discovered, unapplied]",
				"              └─ [microsoft-msuc, KB-level, superseded by] P2  [discovered, unapplied]",
			},
		},
		{
			// Inputs may echo "" entries that ExpandKBs treated as inert
			// (e.g. --applied "" --applied 5000802). The renderer must not
			// emit a blank root in "Supersession chains:" or a stray space
			// in the Applied / Unapplied joinKBList output.
			name: "empty KB IDs in inputs are not rendered",
			args: args{
				exp: &microsoft.ExpandResult{
					Inputs:    microsoft.ExpandInputs{Applied: []string{"", "5000802"}, Unapplied: []string{""}},
					Covered:   []string{"5000802"},
					Unapplied: []string{"5001330"},
					Edges: map[string][]microsoft.ExpandEdge{
						"5000802": {{To: "5001330", Source: "microsoft-cvrf", Level: microsoft.ExpandEdgeLevelKB}},
					},
				},
			},
			wantContains: []string{
				"Applied:   5000802",
				"Unapplied: (none)",
				"5000802  [input:applied, covered]",
				"      └─ [microsoft-cvrf, KB-level, superseded by] 5001330  [discovered, unapplied]",
			},
			wantNotContains: []string{
				"Applied:   \n",      // no stray leading/trailing space from "" entry
				"Applied:    5000802", // no double-space caused by leading "" in join
				"\n  \n",              // no blank root line in Supersession chains
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := printKBExpandTree(&buf, tt.args.exp, tt.args.datasources, tt.args.releases, tt.args.coveredAfter, tt.args.unappliedAfter, tt.args.coveredDropped, tt.args.unappliedDropped); err != nil {
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
