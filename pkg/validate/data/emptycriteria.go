package data

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
func detectEmptyCriteria(data dataTypes.Data) []Detected {
	var ds []Detected
	for di, d := range data.Detections {
		if len(d.Conditions) == 0 {
			ds = append(ds, Detected{
				Pointer: fmt.Sprintf("/detections/%d", di),
				Message: fmt.Sprintf("detection %s: no conditions", d.Ecosystem),
			})
		}
		for ci, cond := range d.Conditions {
			ds = append(ds, emptyCriteriaNodes(fmt.Sprintf("/detections/%d/conditions/%d/criteria", di, ci), fmt.Sprintf("detection %s: condition %q: criteria", d.Ecosystem, cond.Tag), cond.Criteria)...)
		}
	}
	return ds
}

func emptyCriteriaNodes(ptr, at string, ca criteriaTypes.Criteria) []Detected {
	if len(ca.Criterias) == 0 && len(ca.Criterions) == 0 {
		return []Detected{{Pointer: ptr, Message: fmt.Sprintf("%s: no criterias and no criterions", at)}}
	}

	var ds []Detected
	switch ca.Operator {
	case criteriaTypes.CriteriaOperatorTypeOR, criteriaTypes.CriteriaOperatorTypeAND:
	default:
		ds = append(ds, Detected{Pointer: ptr, Message: fmt.Sprintf("%s: no operator", at)})
	}
	for i, child := range ca.Criterias {
		ds = append(ds, emptyCriteriaNodes(fmt.Sprintf("%s/criterias/%d", ptr, i), fmt.Sprintf("%s: criterias[%d]", at, i), child)...)
	}
	return ds
}
