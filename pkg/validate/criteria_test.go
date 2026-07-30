package validate_test

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"

	"github.com/MaineK00n/vuls2/pkg/validate"
)

// TestInspectCriteria pins the walk itself: the visit order, the JSON
// pointer and human label built at every position, the ecosystem/tag
// propagation, and the Rule stamping. The individual rule tests call their
// hooks directly and rely on this coverage for the coordinates.
func TestInspectCriteria(t *testing.T) {
	echo := func(ctx validate.CriteriaContext) []validate.Violation {
		return []validate.Violation{{Pointer: ctx.Pointer, Message: fmt.Sprintf("%s (ecosystem: %s, tag: %s)", ctx.At, ctx.Ecosystem, ctx.Tag)}}
	}
	rule := validate.CriteriaRule{
		Name:        "echo",
		Description: "test stub echoing every walk position",
		Detection: func(ctx validate.CriteriaContext, _ detectionTypes.Detection) []validate.Violation {
			return echo(ctx)
		},
		Node: func(ctx validate.CriteriaContext, _ criteriaTypes.Criteria) []validate.Violation {
			return echo(ctx)
		},
		Criterion: func(ctx validate.CriteriaContext, _ criterionTypes.Criterion) []validate.Violation {
			return echo(ctx)
		},
	}

	data := dataTypes.Data{
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
									Criterions: []criterionTypes.Criterion{{Type: criterionTypes.CriterionTypeVersion}},
								},
							},
							Criterions: []criterionTypes.Criterion{{Type: criterionTypes.CriterionTypeVersion}},
						},
						Tag: "vulnerable",
					},
				},
			},
		},
	}

	want := []validate.Violation{
		{Rule: "echo", Pointer: "/detections/0", Message: "detection cpe (ecosystem: cpe, tag: )"},
		{Rule: "echo", Pointer: "/detections/0/conditions/0/criteria", Message: `detection cpe: condition "vulnerable": criteria (ecosystem: cpe, tag: vulnerable)`},
		{Rule: "echo", Pointer: "/detections/0/conditions/0/criteria/criterias/0", Message: `detection cpe: condition "vulnerable": criteria: criterias[0] (ecosystem: cpe, tag: vulnerable)`},
		{Rule: "echo", Pointer: "/detections/0/conditions/0/criteria/criterias/0/criterions/0", Message: `detection cpe: condition "vulnerable": criteria: criterias[0]: criterions[0] (ecosystem: cpe, tag: vulnerable)`},
		{Rule: "echo", Pointer: "/detections/0/conditions/0/criteria/criterions/0", Message: `detection cpe: condition "vulnerable": criteria: criterions[0] (ecosystem: cpe, tag: vulnerable)`},
	}
	if diff := cmp.Diff(want, validate.InspectCriteria(data, []validate.CriteriaRule{rule})); diff != "" {
		t.Errorf("InspectCriteria() (-expected +got):\n%s", diff)
	}
}
