package data

import (
	"testing"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	cpecriterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
)

func cpeData(criterions ...criterionTypes.Criterion) dataTypes.Data {
	return dataTypes.Data{
		ID: "CVE-2024-0001",
		Detections: []detectionTypes.Detection{
			{
				Ecosystem: ecosystemTypes.EcosystemTypeCPE,
				Conditions: []conditionTypes.Condition{
					{
						Criteria: criteriaTypes.Criteria{
							Operator:   criteriaTypes.CriteriaOperatorTypeOR,
							Criterions: criterions,
						},
						Tag: "vulnerable",
					},
				},
			},
		},
	}
}

func TestDetectCPEPVP(t *testing.T) {
	tests := []struct {
		name string
		data dataTypes.Data
		want int
	}{
		{
			name: "match",
			data: cpeData(criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeCPE,
				CPE: &cpecriterionTypes.Criterion{
					Vulnerable: true,
					CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
					CPEMatches: []cpecriterionTypes.CPE{"cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"},
				},
			}),
			want: 0,
		},
		{
			name: "product mismatch",
			data: cpeData(criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeCPE,
				CPE: &cpecriterionTypes.Criterion{
					Vulnerable: true,
					CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
					CPEMatches: []cpecriterionTypes.CPE{"cpe:2.3:a:vendor:other:1.0.0:*:*:*:*:*:*:*"},
				},
			}),
			want: 1,
		},
		{
			name: "part and vendor mismatch",
			data: cpeData(criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeCPE,
				CPE: &cpecriterionTypes.Criterion{
					Vulnerable: true,
					CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
					CPEMatches: []cpecriterionTypes.CPE{"cpe:2.3:o:other:product:1.0.0:*:*:*:*:*:*:*"},
				},
			}),
			want: 2,
		},
		{
			name: "wildcard vendor on criterion side is compatible",
			data: cpeData(criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeCPE,
				CPE: &cpecriterionTypes.Criterion{
					Vulnerable: true,
					CPE:        "cpe:2.3:a:*:product:*:*:*:*:*:*:*:*",
					CPEMatches: []cpecriterionTypes.CPE{"cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"},
				},
			}),
			want: 0,
		},
		{
			name: "invalid criterion cpe",
			data: cpeData(criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeCPE,
				CPE: &cpecriterionTypes.Criterion{
					Vulnerable: true,
					CPE:        "not-a-cpe",
					CPEMatches: []cpecriterionTypes.CPE{"cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"},
				},
			}),
			want: 1,
		},
		{
			name: "invalid cpe_match",
			data: cpeData(criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeCPE,
				CPE: &cpecriterionTypes.Criterion{
					Vulnerable: true,
					CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
					CPEMatches: []cpecriterionTypes.CPE{"not-a-cpe"},
				},
			}),
			want: 1,
		},
		{
			name: "no cpe_matches",
			data: cpeData(criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeCPE,
				CPE: &cpecriterionTypes.Criterion{
					Vulnerable: true,
					CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				},
			}),
			want: 0,
		},
		{
			name: "non-cpe criterion is ignored",
			data: cpeData(criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeVersion,
			}),
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := detectCPEPVP(tt.data); len(got) != tt.want {
				t.Errorf("detectCPEPVP() = %+v, want %d finding(s)", got, tt.want)
			}
		})
	}
}
