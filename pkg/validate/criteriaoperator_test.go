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

func TestInspectCriteriaOperator(t *testing.T) {
	tests := []struct {
		name string
		data dataTypes.Data
		want []Violation
	}{
		{
			name: "ok",
			data: dataTypes.Data{
				ID: "CVE-2024-0001",
				Detections: []detectionTypes.Detection{
					{
						Ecosystem: ecosystemTypes.EcosystemTypeCPE,
						Conditions: []conditionTypes.Condition{
							{
								Criteria: criteriaTypes.Criteria{
									Operator: criteriaTypes.CriteriaOperatorTypeOR,
									Criterions: []criterionTypes.Criterion{
										{
											Type: criterionTypes.CriterionTypeCPE,
											CPE: &cpecriterionTypes.Criterion{
												Vulnerable: true,
												CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
											},
										},
									},
								},
								Tag: "vulnerable",
							},
						},
					},
				},
			},
		},
		{
			name: "criteria with children but no operator",
			data: dataTypes.Data{
				ID: "CVE-2024-0001",
				Detections: []detectionTypes.Detection{
					{
						Ecosystem: ecosystemTypes.EcosystemTypeCPE,
						Conditions: []conditionTypes.Condition{
							{
								Criteria: criteriaTypes.Criteria{
									Criterions: []criterionTypes.Criterion{
										{
											Type: criterionTypes.CriterionTypeCPE,
											CPE: &cpecriterionTypes.Criterion{
												Vulnerable: true,
												CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
											},
										},
									},
								},
								Tag: "vulnerable",
							},
						},
					},
				},
			},
			want: []Violation{
				{Pointer: "/detections/0/conditions/0/criteria", Message: `detection cpe: condition "vulnerable": criteria: no operator`},
			},
		},
		{
			name: "nested criteria without operator",
			data: dataTypes.Data{
				ID: "CVE-2024-0001",
				Detections: []detectionTypes.Detection{
					{
						Ecosystem: ecosystemTypes.EcosystemTypeCPE,
						Conditions: []conditionTypes.Condition{
							{
								Criteria: criteriaTypes.Criteria{
									Operator: criteriaTypes.CriteriaOperatorTypeAND,
									Criterias: []criteriaTypes.Criteria{
										{
											Criterions: []criterionTypes.Criterion{
												{
													Type: criterionTypes.CriterionTypeCPE,
													CPE: &cpecriterionTypes.Criterion{
														Vulnerable: true,
														CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
													},
												},
											},
										},
									},
								},
								Tag: "vulnerable",
							},
						},
					},
				},
			},
			want: []Violation{
				{Pointer: "/detections/0/conditions/0/criteria/criterias/0", Message: `detection cpe: condition "vulnerable": criteria: criterias[0]: no operator`},
			},
		},
		{
			name: "empty criteria is not this rule's concern",
			data: dataTypes.Data{
				ID: "CVE-2024-0001",
				Detections: []detectionTypes.Detection{
					{
						Ecosystem: ecosystemTypes.EcosystemTypeCPE,
						Conditions: []conditionTypes.Condition{
							{Tag: "vulnerable"},
						},
					},
				},
			},
		},
		{
			name: "no detections",
			data: dataTypes.Data{ID: "CVE-2024-0001"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, criteriaOperatorRule.inspect(tt.data)); diff != "" {
				t.Errorf("criteriaOperatorRule.inspect() (-expected +got):\n%s", diff)
			}
		})
	}
}
