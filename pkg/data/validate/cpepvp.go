package validate

import (
	"fmt"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
)

var cpePVPCheck = Check{
	Name:        "cpe-pvp",
	Description: "cpe criterion: criterion cpe and cpe_matches agree on part:vendor:product",
	Detect:      detectCPEPVP,
}

// detectCPEPVP reports cpe criterions whose cpe_matches entries disagree
// with the criterion CPE on the part, vendor or product WFN attribute. A
// logical value (ANY, NA) on either side is treated as compatible; only two
// concrete, differing values are a mismatch.
func detectCPEPVP(data dataTypes.Data) []string {
	var msgs []string
	for _, d := range data.Detections {
		for _, cond := range d.Conditions {
			walkCriteria(cond.Criteria, func(cn criterionTypes.Criterion) {
				if cn.Type != criterionTypes.CriterionTypeCPE || cn.CPE == nil {
					return
				}

				cWFN, err := naming.UnbindFS(string(cn.CPE.CPE))
				if err != nil {
					msgs = append(msgs, fmt.Sprintf("detection %s: condition %q: unbind criterion cpe %q to WFN: %v", d.Ecosystem, cond.Tag, cn.CPE.CPE, err))
					return
				}

				for _, m := range cn.CPE.CPEMatches {
					mWFN, err := naming.UnbindFS(string(m))
					if err != nil {
						msgs = append(msgs, fmt.Sprintf("detection %s: condition %q: criterion cpe %q: unbind cpe_match %q to WFN: %v", d.Ecosystem, cond.Tag, cn.CPE.CPE, m, err))
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
							msgs = append(msgs, fmt.Sprintf("detection %s: condition %q: criterion cpe %q and cpe_match %q disagree on %s: %q != %q", d.Ecosystem, cond.Tag, cn.CPE.CPE, m, attr, cv, mv))
						}
					}
				}
			})
		}
	}
	return msgs
}
