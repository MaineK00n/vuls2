package cpe

import (
	"fmt"
	"maps"
	"slices"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	db "github.com/MaineK00n/vuls2/pkg/db/common"
	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"
	"github.com/MaineK00n/vuls2/pkg/detect/util"
	scanTypes "github.com/MaineK00n/vuls2/pkg/scan/types"
)

func Detect(dbc db.DB, sr scanTypes.ScanResult, concurrency int) (map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection, error) {
	qm := make(map[string][]int)
	for i, cpe := range sr.CPE {
		wfn, err := naming.UnbindFS(cpe)
		if err != nil {
			return nil, errors.Wrapf(err, "unbind %q to WFN", cpe)
		}
		qm[fmt.Sprintf("%s:%s", wfn.GetString(common.AttributeVendor), wfn.GetString(common.AttributeProduct))] = append(qm[fmt.Sprintf("%s:%s", wfn.GetString(common.AttributeVendor), wfn.GetString(common.AttributeProduct))], i)
	}

	dm, err := util.Detect(dbc, ecosystemTypes.EcosystemTypeCPE, slices.Collect(maps.Keys(qm)), func(rootID dataTypes.RootID, queries []string) util.Request {
		var (
			qs    []vcTypes.Query
			idxes []int
		)
		for _, q := range queries {
			for _, idx := range qm[q] {
				qs = append(qs, vcTypes.Query{CPE: &sr.CPE[idx]})
			}
			idxes = append(idxes, qm[q]...)
		}
		return util.Request{
			RootID:  rootID,
			Query:   criterionTypes.Query{Version: qs},
			Indexes: idxes,
		}
	}, concurrency)
	if err != nil {
		return nil, errors.Wrap(err, "detect")
	}
	return dm, nil
}
