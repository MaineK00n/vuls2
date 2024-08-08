package cpe

import (
	"fmt"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"

	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria/criterion"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/ecosystem"
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

	type filtered struct {
		criteria criteriaTypes.Criteria
		indexes  []int
	}
	cm := make(map[string]map[sourceTypes.SourceID]filtered)
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
						for sourceID, ca := range m {
							for _, idx := range indexes {
								isContains, err := ca.Contains(ecosystemTypes.EcosystemTypeCPE, criterionTypes.Query{CPE: &sr.CPE[idx]})
								if err != nil {
									return errors.Wrap(err, "criteria contains")
								}

								if isContains {
									if cm[rootID] == nil {
										cm[rootID] = make(map[sourceTypes.SourceID]filtered)
									}
									base, ok := cm[rootID][sourceID]
									if !ok {
										base = filtered{criteria: ca}
									}
									base.indexes = append(base.indexes, idx)
									cm[rootID][sourceID] = base
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
			return detectTypes.VulnerabilityDataDetection{}, errors.Wrapf(err, "detect cpe: %s %s", string(ecosystemTypes.EcosystemTypeCPE), vp)
		}
	}

	contents := make(map[string]map[sourceTypes.SourceID]criteriaTypes.FilteredCriteria)
	for rootID, m := range cm {
		for sourceID, fca := range m {
			qs := make([]criterionTypes.Query, 0, len(fca.indexes))
			for _, idx := range fca.indexes {
				qs = append(qs, criterionTypes.Query{CPE: &sr.CPE[idx]})
			}

			ac, err := fca.criteria.Accept(ecosystemTypes.EcosystemTypeCPE, qs)
			if err != nil {
				return detectTypes.VulnerabilityDataDetection{}, errors.Wrap(err, "criteria accept")
			}

			isAffected, err := ac.Affected()
			if err != nil {
				return detectTypes.VulnerabilityDataDetection{}, errors.Wrap(err, "criteria affected")
			}
			if isAffected {
				if contents[rootID] == nil {
					contents[rootID] = make(map[sourceTypes.SourceID]criteriaTypes.FilteredCriteria)
				}
				contents[rootID][sourceID] = replaceIndexes(ac, fca.indexes)
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

	var cos []criteriaTypes.FilteredCriterion
	for _, co := range ac.Criterions {
		if len(co.Accepts) == 0 {
			continue
		}

		is := make([]int, 0, len(co.Accepts))
		for _, a := range co.Accepts {
			is = append(is, indexes[a])
		}
		co.Accepts = is
		cos = append(cos, co)
	}
	replaced.Criterions = cos

	return replaced
}
