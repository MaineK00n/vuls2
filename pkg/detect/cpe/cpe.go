package cpe

import (
	"fmt"
	"iter"
	"maps"
	"slices"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	ccTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	"github.com/MaineK00n/vuls2/pkg/db/session"
	"github.com/MaineK00n/vuls2/pkg/detect/util"
	scanTypes "github.com/MaineK00n/vuls2/pkg/scan/types"
)

// Detect yields each rootID's detection with its full criteria trees as
// it is produced. Consumers that derive per-root projections (e.g. vuls0's
// verified-product suppression inputs) can fold each element and drop the
// tree instead of holding every candidate root's tree at once. A yielded
// non-nil error is terminal. An empty sr.CPE yields nothing.
//
// The sequence is lazy — nothing runs until it is iterated, matching the
// session-layer iterators (e.g. GetVulnerabilityDataByPackage).
func Detect(s session.Storage, sr scanTypes.ScanResult, concurrency int) iter.Seq2[util.RootDetection, error] {
	return func(yield func(util.RootDetection, error) bool) {
		if len(sr.CPE) == 0 {
			return
		}

		qm := make(map[string][]int)
		for i, cpe := range sr.CPE {
			wfn, err := naming.UnbindFS(cpe)
			if err != nil {
				yield(util.RootDetection{}, errors.Wrapf(err, "unbind %q to WFN", cpe))
				return
			}
			key := fmt.Sprintf("%s:%s:%s", wfn.GetString(common.AttributePart), wfn.GetString(common.AttributeVendor), wfn.GetString(common.AttributeProduct))
			qm[key] = append(qm[key], i)
		}

		util.Detect(s, ecosystemTypes.EcosystemTypeCPE, slices.Collect(maps.Keys(qm)), func(rootID dataTypes.RootID, queries []string) util.Request {
			var (
				qs    []ccTypes.Query
				idxes []int
			)
			for _, q := range queries {
				for _, idx := range qm[q] {
					qs = append(qs, ccTypes.Query{CPE: sr.CPE[idx]})
				}
				idxes = append(idxes, qm[q]...)
			}
			return util.Request{
				RootID:  rootID,
				Query:   criterionTypes.Query{CPE: qs},
				Indexes: idxes,
			}
		}, concurrency)(yield)
	}
}
