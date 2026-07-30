package validate

import (
	"fmt"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"

	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
)

var cpePVPRule = CriteriaRule{
	Name:        "cpe-pvp",
	Description: "cpe criterion: criterion cpe and cpe_matches agree on part:vendor:product",
	Criterion:   inspectCPEPVP,
}

// inspectCPEPVP reports cpe criterions whose cpe_matches entries disagree
// with the criterion CPE on the part, vendor or product WFN attribute. A
// logical value (ANY, NA) on either side is treated as compatible; only two
// concrete, differing values are a mismatch.
func inspectCPEPVP(ctx CriteriaContext, cn criterionTypes.Criterion) []Violation {
	if cn.Type != criterionTypes.CriterionTypeCPE || cn.CPE == nil {
		return nil
	}

	cWFN, err := naming.UnbindFS(string(cn.CPE.CPE))
	if err != nil {
		return []Violation{{
			Pointer: ctx.Pointer + "/cpe/cpe",
			Message: fmt.Sprintf("detection %s: condition %q: unbind criterion cpe %q to WFN: %v", ctx.Ecosystem, ctx.Tag, cn.CPE.CPE, err),
		}}
	}

	var vs []Violation
	for mi, m := range cn.CPE.CPEMatches {
		mWFN, err := naming.UnbindFS(string(m))
		if err != nil {
			vs = append(vs, Violation{
				Pointer: fmt.Sprintf("%s/cpe/cpe_matches/%d", ctx.Pointer, mi),
				Message: fmt.Sprintf("detection %s: condition %q: criterion cpe %q: unbind cpe_match %q to WFN: %v", ctx.Ecosystem, ctx.Tag, cn.CPE.CPE, m, err),
			})
			continue
		}

		for _, attr := range []string{common.AttributePart, common.AttributeVendor, common.AttributeProduct} {
			if _, ok := cWFN.Get(attr).(common.LogicalValue); ok {
				continue
			}
			if _, ok := mWFN.Get(attr).(common.LogicalValue); ok {
				continue
			}
			if cv, mv := cWFN.GetString(attr), mWFN.GetString(attr); cv != mv {
				vs = append(vs, Violation{
					Pointer: fmt.Sprintf("%s/cpe/cpe_matches/%d", ctx.Pointer, mi),
					Message: fmt.Sprintf("detection %s: condition %q: criterion cpe %q and cpe_match %q disagree on %s: %q != %q", ctx.Ecosystem, ctx.Tag, cn.CPE.CPE, m, attr, cv, mv),
				})
			}
		}
	}
	return vs
}
