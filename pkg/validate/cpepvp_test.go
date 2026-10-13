package validate_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	cpecriterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"

	"github.com/MaineK00n/vuls2/pkg/validate"
)

func TestInspectCPEPVP(t *testing.T) {
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
			name: "match",
			args: args{
				ctx: validate.CriteriaContext{
					Pointer:   "/detections/0/conditions/0/criteria/criterions/0",
					Ecosystem: ecosystemTypes.EcosystemTypeCPE,
					Tag:       "vulnerable",
				},
				cn: criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeCPE,
					CPE: &cpecriterionTypes.Criterion{
						Vulnerable: true,
						CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
						CPEMatches: []cpecriterionTypes.CPE{"cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"},
					},
				},
			},
		},
		{
			name: "product mismatch",
			args: args{
				ctx: validate.CriteriaContext{
					Pointer:   "/detections/0/conditions/0/criteria/criterions/0",
					Ecosystem: ecosystemTypes.EcosystemTypeCPE,
					Tag:       "vulnerable",
				},
				cn: criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeCPE,
					CPE: &cpecriterionTypes.Criterion{
						Vulnerable: true,
						CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
						CPEMatches: []cpecriterionTypes.CPE{"cpe:2.3:a:vendor:other:1.0.0:*:*:*:*:*:*:*"},
					},
				},
			},
			want: []validate.Violation{
				{
					Pointer: "/detections/0/conditions/0/criteria/criterions/0/cpe/cpe_matches/0",
					Message: `detection cpe: condition "vulnerable": criterion cpe "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*" and cpe_match "cpe:2.3:a:vendor:other:1.0.0:*:*:*:*:*:*:*" disagree on product: "product" != "other"`,
				},
			},
		},
		{
			name: "part and vendor mismatch",
			args: args{
				ctx: validate.CriteriaContext{
					Pointer:   "/detections/0/conditions/0/criteria/criterions/0",
					Ecosystem: ecosystemTypes.EcosystemTypeCPE,
					Tag:       "vulnerable",
				},
				cn: criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeCPE,
					CPE: &cpecriterionTypes.Criterion{
						Vulnerable: true,
						CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
						CPEMatches: []cpecriterionTypes.CPE{"cpe:2.3:o:other:product:1.0.0:*:*:*:*:*:*:*"},
					},
				},
			},
			want: []validate.Violation{
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
			args: args{
				ctx: validate.CriteriaContext{
					Pointer:   "/detections/0/conditions/0/criteria/criterions/0",
					Ecosystem: ecosystemTypes.EcosystemTypeCPE,
					Tag:       "vulnerable",
				},
				cn: criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeCPE,
					CPE: &cpecriterionTypes.Criterion{
						Vulnerable: true,
						CPE:        "cpe:2.3:a:*:product:*:*:*:*:*:*:*:*",
						CPEMatches: []cpecriterionTypes.CPE{"cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"},
					},
				},
			},
		},
		{
			name: "invalid criterion cpe",
			args: args{
				ctx: validate.CriteriaContext{
					Pointer:   "/detections/0/conditions/0/criteria/criterions/0",
					Ecosystem: ecosystemTypes.EcosystemTypeCPE,
					Tag:       "vulnerable",
				},
				cn: criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeCPE,
					CPE: &cpecriterionTypes.Criterion{
						Vulnerable: true,
						CPE:        "not-a-cpe",
						CPEMatches: []cpecriterionTypes.CPE{"cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"},
					},
				},
			},
			want: []validate.Violation{
				{
					Pointer: "/detections/0/conditions/0/criteria/criterions/0/cpe/cpe",
					Message: `detection cpe: condition "vulnerable": unbind criterion cpe "not-a-cpe" to WFN: Error: Formatted String must start with "cpe:2.3". Given: not-a-cpe: Parse error`,
				},
			},
		},
		{
			name: "invalid cpe_match",
			args: args{
				ctx: validate.CriteriaContext{
					Pointer:   "/detections/0/conditions/0/criteria/criterions/0",
					Ecosystem: ecosystemTypes.EcosystemTypeCPE,
					Tag:       "vulnerable",
				},
				cn: criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeCPE,
					CPE: &cpecriterionTypes.Criterion{
						Vulnerable: true,
						CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
						CPEMatches: []cpecriterionTypes.CPE{"not-a-cpe"},
					},
				},
			},
			want: []validate.Violation{
				{
					Pointer: "/detections/0/conditions/0/criteria/criterions/0/cpe/cpe_matches/0",
					Message: `detection cpe: condition "vulnerable": criterion cpe "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*": unbind cpe_match "not-a-cpe" to WFN: Error: Formatted String must start with "cpe:2.3". Given: not-a-cpe: Parse error`,
				},
			},
		},
		{
			name: "no cpe_matches",
			args: args{
				ctx: validate.CriteriaContext{
					Pointer:   "/detections/0/conditions/0/criteria/criterions/0",
					Ecosystem: ecosystemTypes.EcosystemTypeCPE,
					Tag:       "vulnerable",
				},
				cn: criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeCPE,
					CPE: &cpecriterionTypes.Criterion{
						Vulnerable: true,
						CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
					},
				},
			},
		},
		{
			name: "non-cpe criterion is ignored",
			args: args{
				ctx: validate.CriteriaContext{
					Pointer:   "/detections/0/conditions/0/criteria/criterions/0",
					Ecosystem: ecosystemTypes.EcosystemTypeCPE,
					Tag:       "vulnerable",
				},
				cn: criterionTypes.Criterion{
					Type: criterionTypes.CriterionTypeVersion,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, validate.InspectCPEPVP(tt.args.ctx, tt.args.cn)); diff != "" {
				t.Errorf("InspectCPEPVP() (-expected +got):\n%s", diff)
			}
		})
	}
}
