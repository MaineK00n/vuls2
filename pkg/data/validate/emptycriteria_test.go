package validate

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

func TestDetectEmptyCriteria(t *testing.T) {
	criterion := criterionTypes.Criterion{
		Type: criterionTypes.CriterionTypeCPE,
		CPE: &cpecriterionTypes.Criterion{
			Vulnerable: true,
			CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
		},
	}

	tests := []struct {
		name string
		data dataTypes.Data
		want int
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
									Operator:   criteriaTypes.CriteriaOperatorTypeOR,
									Criterions: []criterionTypes.Criterion{criterion},
								},
								Tag: "vulnerable",
							},
						},
					},
				},
			},
			want: 0,
		},
		{
			name: "detection without conditions",
			data: dataTypes.Data{
				ID: "CVE-2024-0001",
				Detections: []detectionTypes.Detection{
					{Ecosystem: ecosystemTypes.EcosystemTypeCPE},
				},
			},
			want: 1,
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
			want: 1,
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
											Operator:   criteriaTypes.CriteriaOperatorTypeOR,
											Criterions: []criterionTypes.Criterion{criterion},
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
			want: 1,
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
									Criterions: []criterionTypes.Criterion{criterion},
								},
								Tag: "vulnerable",
							},
						},
					},
				},
			},
			want: 1,
		},
		{
			name: "no detections",
			data: dataTypes.Data{ID: "CVE-2024-0001"},
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := detectEmptyCriteria(tt.data); len(got) != tt.want {
				t.Errorf("detectEmptyCriteria() = %q, want %d finding(s)", got, tt.want)
			}
		})
	}
}
