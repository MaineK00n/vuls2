package validate

import (
	"fmt"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
)

var criteriaOperatorRule = DataRule{
	Name:        "criteria-operator",
	Description: "detection: every criteria node with children declares a valid operator",
	Inspect:     inspectCriteriaOperator,
}

// inspectCriteriaOperator reports criteria nodes that have children but no
// valid operator (OR/AND). Operators outside the enum vocabulary are
// rejected at unmarshal time, so the reachable case is an absent operator
// key. Empty nodes are the empty-criteria rule's concern, not this one's.
func inspectCriteriaOperator(data dataTypes.Data) []Violation {
	var vs []Violation
	for di, d := range data.Detections {
		for ci, cond := range d.Conditions {
			vs = append(vs, operatorViolations(fmt.Sprintf("/detections/%d/conditions/%d/criteria", di, ci), fmt.Sprintf("detection %s: condition %q: criteria", d.Ecosystem, cond.Tag), cond.Criteria)...)
		}
	}
	return vs
}

func operatorViolations(ptr, at string, ca criteriaTypes.Criteria) []Violation {
	if len(ca.Criterias) == 0 && len(ca.Criterions) == 0 {
		return nil
	}

	var vs []Violation
	switch ca.Operator {
	case criteriaTypes.CriteriaOperatorTypeOR, criteriaTypes.CriteriaOperatorTypeAND:
	default:
		vs = append(vs, Violation{Pointer: ptr, Message: fmt.Sprintf("%s: no operator", at)})
	}
	for i, child := range ca.Criterias {
		vs = append(vs, operatorViolations(fmt.Sprintf("%s/criterias/%d", ptr, i), fmt.Sprintf("%s: criterias[%d]", at, i), child)...)
	}
	return vs
}
