package validate

import (
	"testing"

	"github.com/google/go-cmp/cmp"

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

func TestInspectCPEPVP(t *testing.T) {
	tests := []struct {
		name string
		data dataTypes.Data
		want []Violation
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
			want: []Violation{
				{
					Pointer: "/detections/0/conditions/0/criteria/criterions/0/cpe/cpe_matches/0",
					Message: `detection cpe: condition "vulnerable": criterion cpe "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*" and cpe_match "cpe:2.3:a:vendor:other:1.0.0:*:*:*:*:*:*:*" disagree on product: "product" != "other"`,
				},
			},
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
			want: []Violation{
				{
					Pointer: "/detections/0/conditions/0/criteria/criterions/0/cpe/cpe_matches/0",
					Message: `detection cpe: condition "vulnerable": criterion cpe "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*" and cpe_match "cpe:2.3:o:other:product:1.0.0:*:*:*:*:*:*:*" disagree on part: "a" != "o"`,
				},
				{
					Pointer: "/detections/0/conditions/0/criteria/criterions/0/cpe/cpe_matches/0",
					Message: `detection cpe: condition "vulnerable": criterion cpe "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*" and cpe_match "cpe:2.3:o:other:product:1.0.0:*:*:*:*:*:*:*" disagree on vendor: "vendor" != "other"`,
				},
			},
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
			want: []Violation{
				{
					Pointer: "/detections/0/conditions/0/criteria/criterions/0/cpe/cpe",
					Message: `detection cpe: condition "vulnerable": unbind criterion cpe "not-a-cpe" to WFN: Error: Formatted String must start with "cpe:2.3". Given: not-a-cpe: Parse error`,
				},
			},
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
			want: []Violation{
				{
					Pointer: "/detections/0/conditions/0/criteria/criterions/0/cpe/cpe_matches/0",
					Message: `detection cpe: condition "vulnerable": criterion cpe "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*": unbind cpe_match "not-a-cpe" to WFN: Error: Formatted String must start with "cpe:2.3". Given: not-a-cpe: Parse error`,
				},
			},
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
		},
		{
			name: "non-cpe criterion is ignored",
			data: cpeData(criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeVersion,
			}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, cpePVPRule.inspect(tt.data)); diff != "" {
				t.Errorf("cpePVPRule.inspect() (-expected +got):\n%s", diff)
			}
		})
	}
}
