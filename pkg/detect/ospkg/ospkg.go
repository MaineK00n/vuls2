package ospkg

import (
	"fmt"
	"slices"
	"strings"

	"github.com/pkg/errors"

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
	ecosystem, err := ecosystemTypes.GetEcosystem(sr.Family, sr.Release)
	if err != nil {
		return detectTypes.VulnerabilityDataDetection{}, errors.Wrapf(err, "get ecosystem. family: %s, release: %s", sr.Family, sr.Release)
	}

	pkgnameFunc := func(pkgname, modularitylabel string) (string, error) {
		if modularitylabel != "" {
			lhs, _, _ := strings.Cut(modularitylabel, "/")
			ss := strings.Split(lhs, ":")
			if len(ss) < 2 {
				return "", errors.Errorf("unexpected modularitylabel format. expected: %q, actual: %q", "NAME:STREAM(:VERSION:CONTEXT:ARCH/PROFILE)", modularitylabel)
			}
			return fmt.Sprintf("%s:%s::%s", ss[0], ss[1], pkgname), nil
		}
		return pkgname, nil
	}

	qpkgs := make([]criterionTypes.QueryPackage, 0, len(sr.OSPackages))
	for _, p := range sr.OSPackages {
		bn, err := pkgnameFunc(p.Name, p.ModularityLabel)
		if err != nil {
			return detectTypes.VulnerabilityDataDetection{}, err
		}
		sn, err := pkgnameFunc(p.SrcName, p.ModularityLabel)
		if err != nil {
			return detectTypes.VulnerabilityDataDetection{}, err
		}

		qpkgs = append(qpkgs, criterionTypes.QueryPackage{
			Name: bn,
			Version: func() string {
				if p.Version == "" {
					return ""
				}
				if p.Release == "" {
					return p.Version
				}
				return fmt.Sprintf("%s-%s", p.Version, p.Release)
			}(),
			SrcName: sn,
			SrcVersion: func() string {
				if p.SrcVersion == "" {
					return ""
				}
				if p.SrcRelease == "" {
					return p.SrcVersion
				}
				return fmt.Sprintf("%s-%s", p.SrcVersion, p.SrcRelease)
			}(),
			Arch:       p.Arch,
			Repository: p.Repository,
		})
	}

	qm := make(map[string][]int)
	for i, p := range qpkgs {
		if !slices.Contains(qm[p.Name], i) {
			qm[p.Name] = append(qm[p.Name], i)
		}
		if p.SrcName != "" && p.Name != p.SrcName && !slices.Contains(qm[p.SrcName], i) {
			qm[p.SrcName] = append(qm[p.SrcName], i)
		}
	}

	type prefiltered struct {
		condition conditionTypes.Condition
		indexes   []int
	}
	pfm := make(map[string]map[sourceTypes.SourceID]prefiltered)
	for name, indexes := range qm {
		if err := func() error {
			resCh, errCh := dbc.GetVulnerabilityDetections(dbTypes.SearchDetectionPkg, string(ecosystem), name)
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
									isContained, err := cond.Contains(ecosystem, criterionTypes.Query{Package: &qpkgs[idx]})
									if err != nil {
										return errors.Wrap(err, "condition contains")
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
			return detectTypes.VulnerabilityDataDetection{}, errors.Wrapf(err, "detect pkg: %s %s", string(ecosystem), name)
		}
	}

	contents := make(map[string]map[sourceTypes.SourceID]conditionTypes.FilteredCondition)
	for rootID, m := range pfm {
		for sourceID, pf := range m {
			qs := make([]criterionTypes.Query, 0, len(pf.indexes))
			for _, idx := range pf.indexes {
				qs = append(qs, criterionTypes.Query{Package: &qpkgs[idx]})
			}

			fcond, err := pf.condition.Accept(ecosystem, qs)
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
		Ecosystem: ecosystem,
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
