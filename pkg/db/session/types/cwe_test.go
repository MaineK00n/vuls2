package types_test

import (
	"encoding/json/v2"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	gocmpopts "github.com/google/go-cmp/cmp/cmpopts"

	cweTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe"
	customphaseTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/customphase"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/session/types"
)

func TestToCWEContent_ModesOfIntroduction(t *testing.T) {
	tests := []struct {
		name string
		in   string // a CWE as stored in the DB
		want []dbTypes.CWEContentModeOfIntroduction
	}{
		{
			name: "pre-CWE 5.0 phase is output in phases",
			in:   `{"id": "CWE-1", "kind": "weakness", "weakness": {"modes_of_introduction": [{"phase": "Implementation", "notes": ["note"]}]}}`,
			want: []dbTypes.CWEContentModeOfIntroduction{{Phases: []string{"Implementation"}, Notes: []string{"note"}}},
		},
		{
			name: "pre-CWE 5.0 empty phase is dropped",
			in:   `{"id": "CWE-1", "kind": "weakness", "weakness": {"modes_of_introduction": [{"phase": ""}]}}`,
			want: []dbTypes.CWEContentModeOfIntroduction{{}},
		},
		{
			name: "CWE 5.0 phases and custom phases",
			in:   `{"id": "CWE-1", "kind": "weakness", "weakness": {"modes_of_introduction": [{"phases": ["Architecture and Design", "Implementation"], "custom_phases": [{"domain": "Hardware", "phase": "Implementation & Physical Design"}]}]}}`,
			want: []dbTypes.CWEContentModeOfIntroduction{{
				Phases:       []string{"Architecture and Design", "Implementation"},
				CustomPhases: []customphaseTypes.CustomPhase{{Domain: "Hardware", Phase: "Implementation & Physical Design"}},
			}},
		},
		{
			name: "phase missing from phases is added",
			in:   `{"id": "CWE-1", "kind": "weakness", "weakness": {"modes_of_introduction": [{"phase": "Operation", "phases": ["Implementation"]}]}}`,
			want: []dbTypes.CWEContentModeOfIntroduction{{Phases: []string{"Implementation", "Operation"}}},
		},
		{
			name: "phase already in phases is not repeated",
			in:   `{"id": "CWE-1", "kind": "weakness", "weakness": {"modes_of_introduction": [{"phase": "Implementation", "phases": ["Implementation"]}]}}`,
			want: []dbTypes.CWEContentModeOfIntroduction{{Phases: []string{"Implementation"}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c cweTypes.CWE
			if err := json.Unmarshal([]byte(tt.in), &c); err != nil {
				t.Fatalf("unmarshal. err: %v", err)
			}

			if diff := gocmp.Diff(tt.want, dbTypes.ToCWEContent(c, nil).Weakness.ModesOfIntroduction, gocmpopts.EquateEmpty()); diff != "" {
				t.Errorf("ToCWEContent().Weakness.ModesOfIntroduction mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
