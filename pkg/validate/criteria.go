package validate

import (
	"fmt"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
)

// CriteriaRule is a per-file rule evaluated position-by-position during the
// single shared walk of the detection criteria trees, instead of walking on
// its own like a DataRule. Hooks are optional; nil hooks are skipped.
type CriteriaRule struct {
	Name        string
	Description string
	Detection   func(ctx CriteriaContext, d detectionTypes.Detection) []Violation
	Node        func(ctx CriteriaContext, ca criteriaTypes.Criteria) []Violation
	Criterion   func(ctx CriteriaContext, cn criterionTypes.Criterion) []Violation
}

// CriteriaContext is the walk position handed to CriteriaRule hooks.
type CriteriaContext struct {
	Pointer   string                    // RFC 6901 JSON pointer of the current element
	At        string                    // human label of the current element ("detection cpe: condition \"x\": criteria: criterias[0]")
	Ecosystem ecosystemTypes.Ecosystem  // detection ecosystem
	Tag       segmentTypes.DetectionTag // condition tag; zero at detection level
}

// CriteriaRules returns the registered criteria-walking rule table.
func CriteriaRules() []CriteriaRule {
	return []CriteriaRule{cpePVPRule, criteriaOperatorRule, emptyCriteriaRule}
}

// attributed pairs a violation with the name of the rule that reported it.
type attributed struct {
	rule string
	Violation
}

// inspectCriteria walks the detection criteria trees of data once and runs
// every hook of every rule at each position.
func inspectCriteria(data dataTypes.Data, rules []CriteriaRule) []attributed {
	var vs []attributed
	for di, d := range data.Detections {
		ctx := CriteriaContext{
			Pointer:   fmt.Sprintf("/detections/%d", di),
			At:        fmt.Sprintf("detection %s", d.Ecosystem),
			Ecosystem: d.Ecosystem,
		}
		for _, r := range rules {
			if r.Detection == nil {
				continue
			}
			for _, v := range r.Detection(ctx, d) {
				vs = append(vs, attributed{rule: r.Name, Violation: v})
			}
		}

		for ci, cond := range d.Conditions {
			walkCriteriaNode(CriteriaContext{
				Pointer:   fmt.Sprintf("%s/conditions/%d/criteria", ctx.Pointer, ci),
				At:        fmt.Sprintf("detection %s: condition %q: criteria", d.Ecosystem, cond.Tag),
				Ecosystem: d.Ecosystem,
				Tag:       cond.Tag,
			}, cond.Criteria, rules, &vs)
		}
	}
	return vs
}

func walkCriteriaNode(ctx CriteriaContext, ca criteriaTypes.Criteria, rules []CriteriaRule, vs *[]attributed) {
	for _, r := range rules {
		if r.Node == nil {
			continue
		}
		for _, v := range r.Node(ctx, ca) {
			*vs = append(*vs, attributed{rule: r.Name, Violation: v})
		}
	}

	for i, child := range ca.Criterias {
		walkCriteriaNode(CriteriaContext{
			Pointer:   fmt.Sprintf("%s/criterias/%d", ctx.Pointer, i),
			At:        fmt.Sprintf("%s: criterias[%d]", ctx.At, i),
			Ecosystem: ctx.Ecosystem,
			Tag:       ctx.Tag,
		}, child, rules, vs)
	}
	for i, cn := range ca.Criterions {
		cctx := CriteriaContext{
			Pointer:   fmt.Sprintf("%s/criterions/%d", ctx.Pointer, i),
			At:        fmt.Sprintf("%s: criterions[%d]", ctx.At, i),
			Ecosystem: ctx.Ecosystem,
			Tag:       ctx.Tag,
		}
		for _, r := range rules {
			if r.Criterion == nil {
				continue
			}
			for _, v := range r.Criterion(cctx, cn) {
				*vs = append(*vs, attributed{rule: r.Name, Violation: v})
			}
		}
	}
}

// inspect runs the shared walk with only this rule; test helper.
func (r CriteriaRule) inspect(data dataTypes.Data) []Violation {
	var vs []Violation
	for _, a := range inspectCriteria(data, []CriteriaRule{r}) {
		vs = append(vs, a.Violation)
	}
	return vs
}
