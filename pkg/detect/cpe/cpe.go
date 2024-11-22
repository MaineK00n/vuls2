package cpe

import (
	"fmt"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	db "github.com/MaineK00n/vuls2/pkg/db/common"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/common/types"
	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"
	scanTypes "github.com/MaineK00n/vuls2/pkg/scan/types"
)

func Detect(dbc db.DB, sr scanTypes.ScanResult) (detectTypes.VulnerabilityDataDetection, error) {
	qm := make(map[string][]int)
	for i, cpe := range sr.CPE {
		wfn, err := naming.UnbindFS(cpe)
		if err != nil {
			return detectTypes.VulnerabilityDataDetection{}, errors.Wrapf(err, "unbind %q to WFN", cpe)
		}

		qm[fmt.Sprintf("%s:%s", wfn.GetString(common.AttributeVendor), wfn.GetString(common.AttributeProduct))] = append(qm[fmt.Sprintf("%s:%s", wfn.GetString(common.AttributeVendor), wfn.GetString(common.AttributeProduct))], i)
	}

	type prefiltered struct {
		condition conditionTypes.Condition
		indexes   []int
	}
	pfm := make(map[dataTypes.RootID]map[sourceTypes.SourceID]prefiltered)
	for vp, indexes := range qm {
		if err := func() error {
			resCh, errCh := dbc.GetVulnerabilityDetections(dbTypes.SearchDetectionPkg, string(ecosystemTypes.EcosystemTypeCPE), vp)
			for {
				select {
				case item, ok := <-resCh:
					if !ok {
						return nil
					}
					for rootID, m := range item.Contents {
						for sourceID, conds := range m {
							for _, cond := range conds {
								for _, idx := range indexes {
									isContained, err := cond.Criteria.Contains(ecosystemTypes.EcosystemTypeCPE, criterionTypes.Query{CPE: &sr.CPE[idx]})
									if err != nil {
										return errors.Wrap(err, "criteria contains")
									}

									if isContained {
										if pfm[rootID] == nil {
											pfm[rootID] = make(map[sourceTypes.SourceID]prefiltered)
										}
										pf, ok := pfm[rootID][sourceID]
										if !ok {
											pf = prefiltered{condition: cond}
										}
										pf.indexes = append(pf.indexes, idx)
										pfm[rootID][sourceID] = pf
									}
								}
							}
						}
					}
				case err, ok := <-errCh:
					if ok {
						return errors.Wrap(err, "get detection")
					}
				}
			}
		}(); err != nil {
			return detectTypes.VulnerabilityDataDetection{}, errors.Wrapf(err, "detect cpe: %s %s", ecosystemTypes.EcosystemTypeCPE, vp)
		}
	}

	contents := make(map[dataTypes.RootID]map[sourceTypes.SourceID]conditionTypes.FilteredCondition)
	for rootID, m := range pfm {
		for sourceID, pf := range m {
			qs := make([]criterionTypes.Query, 0, len(pf.indexes))
			for _, idx := range pf.indexes {
				qs = append(qs, criterionTypes.Query{CPE: &sr.CPE[idx]})
			}

			fcond, err := pf.condition.Accept(ecosystemTypes.EcosystemTypeCPE, qs)
			if err != nil {
				return detectTypes.VulnerabilityDataDetection{}, errors.Wrap(err, "criteria accept")
			}

			isAffected, err := fcond.Affected()
			if err != nil {
				return detectTypes.VulnerabilityDataDetection{}, errors.Wrap(err, "criteria affected")
			}
			if isAffected {
				if contents[rootID] == nil {
					contents[rootID] = make(map[sourceTypes.SourceID]conditionTypes.FilteredCondition)
				}
				fcond.Criteria = replaceIndexes(fcond.Criteria, pf.indexes)
				contents[rootID][sourceID] = fcond
			}
		}
	}

	return detectTypes.VulnerabilityDataDetection{
		Ecosystem: ecosystemTypes.EcosystemTypeCPE,
		Contents:  contents,
	}, nil
}

func replaceIndexes(ac criteriaTypes.FilteredCriteria, indexes []int) criteriaTypes.FilteredCriteria {
	replaced := criteriaTypes.FilteredCriteria{Operator: ac.Operator}

	for _, ca := range ac.Criterias {
		rca := replaceIndexes(ca, indexes)
		if len(rca.Criterias) == 0 && len(rca.Criterions) == 0 {
			continue
		}
		replaced.Criterias = append(replaced.Criterias, rca)
	}

	var cns []criteriaTypes.FilteredCriterion
	for _, cn := range ac.Criterions {
		if len(cn.Accepts) == 0 {
			continue
		}

		is := make([]int, 0, len(cn.Accepts))
		for _, a := range cn.Accepts {
			is = append(is, indexes[a])
		}
		cn.Accepts = is
		cns = append(cns, cn)
	}
	replaced.Criterions = cns

	return replaced
}
