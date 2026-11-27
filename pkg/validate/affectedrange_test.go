package validate_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	rangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"

	"github.com/MaineK00n/vuls2/pkg/validate"
)

func TestInspectAffectedRange(t *testing.T) {
	type args struct {
		ctx validate.CriteriaContext
		cn  criterionTypes.Criterion
	}
	tests := []struct {
		name string
		args args
		want []validate.Violation
	}{
		{
			name: "type with range",
			args: args{
				ctx: validate.CriteriaContext{
					Pointer:   "/detections/0/conditions/0/criteria/criterions/0",
					At:        `detection redhat:9: condition "vulnerable": criteria: criterions[0]`,
					Ecosystem: "redhat:9",
					Tag:       "vulnerable",
				},
				cn: criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeVersion,
					Version: &vcTypes.Criterion{
						Vulnerable: true,
						Affected: &affectedTypes.Affected{
							Type:  rangeTypes.RangeTypeRPM,
							Range: []rangeTypes.Range{{LessThan: "0:1.0.0-1.el9"}},
						},
					},
				},
			},
		},
		{
			name: "type but no range",
			args: args{
				ctx: validate.CriteriaContext{
					Pointer:   "/detections/0/conditions/0/criteria/criterions/0",
					At:        `detection redhat:9: condition "vulnerable": criteria: criterions[0]`,
					Ecosystem: "redhat:9",
					Tag:       "vulnerable",
				},
				cn: criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeVersion,
					Version: &vcTypes.Criterion{
						Vulnerable: true,
						Affected:   &affectedTypes.Affected{Type: rangeTypes.RangeTypeRPM},
					},
				},
			},
			want: []validate.Violation{
				{
					Pointer: "/detections/0/conditions/0/criteria/criterions/0/version/affected",
					Message: `detection redhat:9: condition "vulnerable": criteria: criterions[0]: affected: type "rpm" but no range`,
				},
			},
		},
		{
			name: "type with fixed only is still a violation",
			args: args{
				ctx: validate.CriteriaContext{
					Pointer:   "/detections/0/conditions/0/criteria/criterions/0",
					At:        `detection redhat:9: condition "vulnerable": criteria: criterions[0]`,
					Ecosystem: "redhat:9",
					Tag:       "vulnerable",
				},
				cn: criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeVersion,
					Version: &vcTypes.Criterion{
						Vulnerable: true,
						Affected: &affectedTypes.Affected{
							Type:  rangeTypes.RangeTypeRPM,
							Fixed: []string{"0:1.0.0-1.el9"},
						},
					},
				},
			},
			want: []validate.Violation{
				{
					Pointer: "/detections/0/conditions/0/criteria/criterions/0/version/affected",
					Message: `detection redhat:9: condition "vulnerable": criteria: criterions[0]: affected: type "rpm" but no range`,
				},
			},
		},
		{
			name: "no type is not this rule's concern",
			args: args{
				ctx: validate.CriteriaContext{
					Pointer:   "/detections/0/conditions/0/criteria/criterions/0",
					At:        `detection redhat:9: condition "vulnerable": criteria: criterions[0]`,
					Ecosystem: "redhat:9",
					Tag:       "vulnerable",
				},
				cn: criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeVersion,
					Version: &vcTypes.Criterion{
						Vulnerable: true,
						Affected:   &affectedTypes.Affected{},
					},
				},
			},
		},
		{
			name: "no affected",
			args: args{
				ctx: validate.CriteriaContext{
					Pointer:   "/detections/0/conditions/0/criteria/criterions/0",
					At:        `detection redhat:9: condition "vulnerable": criteria: criterions[0]`,
					Ecosystem: "redhat:9",
					Tag:       "vulnerable",
				},
				cn: criterionTypes.Criterion{
					Type:    criterionTypes.CriterionTypeVersion,
					Version: &vcTypes.Criterion{Vulnerable: true},
				},
			},
		},
		{
			name: "non-version criterion is ignored",
			args: args{
				ctx: validate.CriteriaContext{
					Pointer:   "/detections/0/conditions/0/criteria/criterions/0",
					At:        `detection cpe: condition "vulnerable": criteria: criterions[0]`,
					Ecosystem: ecosystemTypes.EcosystemTypeCPE,
					Tag:       "vulnerable",
				},
				cn: criterionTypes.Criterion{Type: criterionTypes.CriterionTypeCPE},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, validate.InspectAffectedRange(tt.args.ctx, tt.args.cn)); diff != "" {
				t.Errorf("InspectAffectedRange() (-expected +got):\n%s", diff)
			}
		})
	}
}
