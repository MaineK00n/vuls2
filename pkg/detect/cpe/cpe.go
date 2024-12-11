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
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	db "github.com/MaineK00n/vuls2/pkg/db/common"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/common/types"
	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"
	scanTypes "github.com/MaineK00n/vuls2/pkg/scan/types"
)

func Detect(dbc db.DB, sr scanTypes.ScanResult) (map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection, error) {
	qm := make(map[string][]int)
	for i, cpe := range sr.CPE {
		wfn, err := naming.UnbindFS(cpe)
		if err != nil {
			return nil, errors.Wrapf(err, "unbind %q to WFN", cpe)
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
			done := make(chan struct{})
			defer close(done)
			resCh, errCh := dbc.GetVulnerabilityDetections(done, dbTypes.SearchDetectionPkg, string(ecosystemTypes.EcosystemTypeCPE), vp)
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
									isContained, err := cond.Criteria.Contains(criterionTypes.Query{
										Version: []vcTypes.Query{{CPE: &sr.CPE[idx]}},
									})
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
			return nil, errors.Wrapf(err, "detect cpe: %s %s", ecosystemTypes.EcosystemTypeCPE, vp)
		}
	}

	dm := make(map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection)
	for rootID, m := range pfm {
		for sourceID, pf := range m {
			fcond, err := pf.condition.Accept(func() criterionTypes.Query {
				return criterionTypes.Query{
					Version: func() []vcTypes.Query {
						qs := make([]vcTypes.Query, 0, len(pf.indexes))
						for _, idx := range pf.indexes {
							qs = append(qs, vcTypes.Query{CPE: &sr.CPE[idx]})
						}
						return qs
					}(),
				}
			}())
			if err != nil {
				return nil, errors.Wrap(err, "criteria accept")
			}

			isAffected, err := fcond.Affected()
			if err != nil {
				return nil, errors.Wrap(err, "criteria affected")
			}
			if isAffected {
				d, ok := dm[rootID]
				if !ok {
					d = detectTypes.VulnerabilityDataDetection{
						Ecosystem: ecosystemTypes.EcosystemTypeCPE,
						Contents:  make(map[sourceTypes.SourceID][]conditionTypes.FilteredCondition),
					}
				}
				fcond.Criteria, err = replaceIndexes(fcond.Criteria, pf.indexes)
				if err != nil {
					return nil, errors.Wrap(err, "replace indexes")
				}
				d.Contents[sourceID] = append(d.Contents[sourceID], fcond)
				dm[rootID] = d
			}
		}
	}

	return dm, nil
}

func replaceIndexes(fca criteriaTypes.FilteredCriteria, indexes []int) (criteriaTypes.FilteredCriteria, error) {
	replaced := criteriaTypes.FilteredCriteria{Operator: fca.Operator}

	for _, ca := range fca.Criterias {
		rca, err := replaceIndexes(ca, indexes)
		if err != nil {
			return criteriaTypes.FilteredCriteria{}, errors.Wrap(err, "replace indexes")
		}
		if len(rca.Criterias) == 0 && len(rca.Criterions) == 0 {
			continue
		}
		replaced.Criterias = append(replaced.Criterias, rca)
	}

	var cns []criterionTypes.FilteredCriterion
	for _, cn := range fca.Criterions {
		isAffected, err := cn.Affected()
		if err != nil {
			return criteriaTypes.FilteredCriteria{}, errors.Wrap(err, "criterion affected")
		}
		if !isAffected {
			continue
		}

		switch cn.Criterion.Type {
		case criterionTypes.CriterionTypeVersion:
			is := make([]int, 0, len(cn.Accepts.Version))
			for _, a := range cn.Accepts.Version {
				is = append(is, indexes[a])
			}
			cn.Accepts.Version = is
			cns = append(cns, cn)
		case criterionTypes.CriterionTypeNoneExist:
			cns = append(cns, cn)
		default:
			return criteriaTypes.FilteredCriteria{}, errors.Errorf("unexpected criterion type. expected: %q, actual: %q", []criterionTypes.CriterionType{criterionTypes.CriterionTypeVersion, criterionTypes.CriterionTypeNoneExist}, cn.Criterion.Type)
		}
	}
	replaced.Criterions = cns

	return replaced, nil
}
