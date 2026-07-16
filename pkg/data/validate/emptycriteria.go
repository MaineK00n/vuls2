package validate

import (
	"fmt"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
)

var emptyCriteriaCheck = Check{
	Name:        "empty-criteria",
	Description: "detection: no empty conditions or empty/operator-less criteria nodes",
	Detect:      detectEmptyCriteria,
}

// detectEmptyCriteria reports detection tree nodes that are structurally
// present but semantically empty: detections without conditions, criteria
// nodes (at any depth) with neither criterias nor criterions, and criteria
// nodes that have children but no valid operator.
func detectEmptyCriteria(data dataTypes.Data) []string {
	var msgs []string
	for _, d := range data.Detections {
		if len(d.Conditions) == 0 {
			msgs = append(msgs, fmt.Sprintf("detection %s: no conditions", d.Ecosystem))
		}
		for _, cond := range d.Conditions {
			msgs = append(msgs, emptyCriteriaNodes(fmt.Sprintf("detection %s: condition %q: criteria", d.Ecosystem, cond.Tag), cond.Criteria)...)
		}
	}
	return msgs
}

func emptyCriteriaNodes(at string, ca criteriaTypes.Criteria) []string {
	if len(ca.Criterias) == 0 && len(ca.Criterions) == 0 {
		return []string{fmt.Sprintf("%s: no criterias and no criterions", at)}
	}

	var msgs []string
	switch ca.Operator {
	case criteriaTypes.CriteriaOperatorTypeOR, criteriaTypes.CriteriaOperatorTypeAND:
	default:
		msgs = append(msgs, fmt.Sprintf("%s: no operator", at))
	}
	for i, child := range ca.Criterias {
		msgs = append(msgs, emptyCriteriaNodes(fmt.Sprintf("%s: criterias[%d]", at, i), child)...)
	}
	return msgs
}
