package validate

import (
	"fmt"

	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
)

var emptyCriteriaRule = CriteriaRule{
	Name:        "empty-criteria",
	Description: "detection: no empty conditions or empty criteria nodes",
	Detection:   inspectNoConditions,
	Node:        inspectEmptyCriteria,
}

// inspectNoConditions reports detections that carry no conditions at all.
func inspectNoConditions(ctx CriteriaContext, d detectionTypes.Detection) []Violation {
	if len(d.Conditions) > 0 {
		return nil
	}
	return []Violation{{Pointer: ctx.Pointer, Message: fmt.Sprintf("%s: no conditions", ctx.At)}}
}

// inspectEmptyCriteria reports criteria nodes (at any depth) with neither
// criterias nor criterions — nodes that can never match anything and usually
// mean the extractor dropped content on the floor. Operator validity of
// non-empty nodes is the criteria-operator rule's concern.
func inspectEmptyCriteria(ctx CriteriaContext, ca criteriaTypes.Criteria) []Violation {
	if len(ca.Criterias) > 0 || len(ca.Criterions) > 0 {
		return nil
	}
	return []Violation{{Pointer: ctx.Pointer, Message: fmt.Sprintf("%s: no criterias and no criterions", ctx.At)}}
}
