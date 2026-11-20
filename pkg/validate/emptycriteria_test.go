package validate_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"

	"github.com/MaineK00n/vuls2/pkg/validate"
)

func TestInspectNoConditions(t *testing.T) {
	type args struct {
		ctx validate.CriteriaContext
		d   detectionTypes.Detection
	}
	tests := []struct {
		name string
		args args
		want []validate.Violation
	}{
		{
			name: "with conditions",
			args: args{
				ctx: validate.CriteriaContext{
					Pointer:   "/detections/0",
					At:        "detection cpe",
					Ecosystem: ecosystemTypes.EcosystemTypeCPE,
				},
				d: detectionTypes.Detection{
					Ecosystem:  ecosystemTypes.EcosystemTypeCPE,
					Conditions: []conditionTypes.Condition{{Tag: "vulnerable"}},
				},
			},
		},
		{
			name: "without conditions",
			args: args{
				ctx: validate.CriteriaContext{
					Pointer:   "/detections/0",
					At:        "detection cpe",
					Ecosystem: ecosystemTypes.EcosystemTypeCPE,
				},
				d: detectionTypes.Detection{Ecosystem: ecosystemTypes.EcosystemTypeCPE},
			},
			want: []validate.Violation{
				{Pointer: "/detections/0", Message: "detection cpe: no conditions"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, validate.InspectNoConditions(tt.args.ctx, tt.args.d)); diff != "" {
				t.Errorf("InspectNoConditions() (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestInspectEmptyCriteria(t *testing.T) {
	type args struct {
		ctx validate.CriteriaContext
		ca  criteriaTypes.Criteria
	}
	tests := []struct {
		name string
		args args
		want []validate.Violation
	}{
		{
			name: "with criterions",
			args: args{
				ctx: validate.CriteriaContext{
					Pointer:   "/detections/0/conditions/0/criteria",
					At:        `detection cpe: condition "vulnerable": criteria`,
					Ecosystem: ecosystemTypes.EcosystemTypeCPE,
					Tag:       "vulnerable",
				},
				ca: criteriaTypes.Criteria{
					Operator:   criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: []criterionTypes.Criterion{{Type: criterionTypes.CriterionTypeVersion}},
				},
			},
		},
		{
			name: "with child criterias",
			args: args{
				ctx: validate.CriteriaContext{
					Pointer:   "/detections/0/conditions/0/criteria",
					At:        `detection cpe: condition "vulnerable": criteria`,
					Ecosystem: ecosystemTypes.EcosystemTypeCPE,
					Tag:       "vulnerable",
				},
				ca: criteriaTypes.Criteria{
					Operator:  criteriaTypes.CriteriaOperatorTypeAND,
					Criterias: []criteriaTypes.Criteria{{Operator: criteriaTypes.CriteriaOperatorTypeOR}},
				},
			},
		},
		{
			name: "no criterias and no criterions",
			args: args{
				ctx: validate.CriteriaContext{
					Pointer:   "/detections/0/conditions/0/criteria/criterias/1",
					At:        `detection cpe: condition "vulnerable": criteria: criterias[1]`,
					Ecosystem: ecosystemTypes.EcosystemTypeCPE,
					Tag:       "vulnerable",
				},
				ca: criteriaTypes.Criteria{Operator: criteriaTypes.CriteriaOperatorTypeOR},
			},
			want: []validate.Violation{
				{Pointer: "/detections/0/conditions/0/criteria/criterias/1", Message: `detection cpe: condition "vulnerable": criteria: criterias[1]: no criterias and no criterions`},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, validate.InspectEmptyCriteria(tt.args.ctx, tt.args.ca)); diff != "" {
				t.Errorf("InspectEmptyCriteria() (-expected +got):\n%s", diff)
			}
		})
	}
}
