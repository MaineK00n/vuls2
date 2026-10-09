package validate_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"

	"github.com/MaineK00n/vuls2/pkg/validate"
)

func TestInspectCriteriaOperator(t *testing.T) {
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
			name: "or with criterions",
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
			name: "and with child criterias",
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
			name: "children but no operator",
			args: args{
				ctx: validate.CriteriaContext{
					Pointer:   "/detections/0/conditions/0/criteria/criterias/0",
					At:        `detection cpe: condition "vulnerable": criteria: criterias[0]`,
					Ecosystem: ecosystemTypes.EcosystemTypeCPE,
					Tag:       "vulnerable",
				},
				ca: criteriaTypes.Criteria{
					Criterions: []criterionTypes.Criterion{{Type: criterionTypes.CriterionTypeVersion}},
				},
			},
			want: []validate.Violation{
				{Pointer: "/detections/0/conditions/0/criteria/criterias/0", Message: `detection cpe: condition "vulnerable": criteria: criterias[0]: no operator`},
			},
		},
		{
			name: "empty criteria is not this rule's concern",
			args: args{
				ctx: validate.CriteriaContext{
					Pointer:   "/detections/0/conditions/0/criteria",
					At:        `detection cpe: condition "vulnerable": criteria`,
					Ecosystem: ecosystemTypes.EcosystemTypeCPE,
					Tag:       "vulnerable",
				},
				ca: criteriaTypes.Criteria{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, validate.InspectCriteriaOperator(tt.args.ctx, tt.args.ca)); diff != "" {
				t.Errorf("InspectCriteriaOperator() (-expected +got):\n%s", diff)
			}
		})
	}
}
