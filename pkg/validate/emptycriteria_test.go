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

func TestInspectEmptyCriteria(t *testing.T) {
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
			name: "detection without conditions",
			data: dataTypes.Data{
				ID: "CVE-2024-0001",
				Detections: []detectionTypes.Detection{
					{Ecosystem: ecosystemTypes.EcosystemTypeCPE},
				},
			},
			want: []Violation{
				{Pointer: "/detections/0", Message: "detection cpe: no conditions"},
			},
		},
		{
			name: "condition with empty criteria",
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
			want: []Violation{
				{Pointer: "/detections/0/conditions/0/criteria", Message: `detection cpe: condition "vulnerable": criteria: no criterias and no criterions`},
			},
		},
		{
			name: "nested empty criteria",
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
										{Operator: criteriaTypes.CriteriaOperatorTypeOR},
									},
								},
								Tag: "vulnerable",
							},
						},
					},
				},
			},
			want: []Violation{
				{Pointer: "/detections/0/conditions/0/criteria/criterias/1", Message: `detection cpe: condition "vulnerable": criteria: criterias[1]: no criterias and no criterions`},
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
			name: "no detections",
			data: dataTypes.Data{ID: "CVE-2024-0001"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, inspectEmptyCriteria(tt.data)); diff != "" {
				t.Errorf("inspectEmptyCriteria() (-expected +got):\n%s", diff)
			}
		})
	}
}
