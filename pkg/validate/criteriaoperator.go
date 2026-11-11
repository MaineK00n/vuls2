package validate

import (
	"fmt"

	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
)

var criteriaOperatorRule = CriteriaRule{
	Name:        "criteria-operator",
	Description: "detection: every criteria node with children declares a valid operator",
	Node:        inspectCriteriaOperator,
}

// inspectCriteriaOperator reports criteria nodes that have children but no
// valid operator (OR/AND). Operators outside the enum vocabulary are
// rejected at unmarshal time, so the reachable case is an absent operator
// key. Empty nodes are the empty-criteria rule's concern, not this one's.
func inspectCriteriaOperator(ctx CriteriaContext, ca criteriaTypes.Criteria) []Violation {
	if len(ca.Criterias) == 0 && len(ca.Criterions) == 0 {
		return nil
	}

	switch ca.Operator {
	case criteriaTypes.CriteriaOperatorTypeOR, criteriaTypes.CriteriaOperatorTypeAND:
		return nil
	default:
		return []Violation{{Pointer: ctx.Pointer, Message: fmt.Sprintf("%s: no operator", ctx.At)}}
	}
}
