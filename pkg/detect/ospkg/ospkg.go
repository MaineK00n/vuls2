package ospkg

import (
	"fmt"
	"slices"
	"strings"

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

	type filtered struct {
		criteria criteriaTypes.Criteria
		indexes  []int
	}
	cm := make(map[string]map[sourceTypes.SourceID]filtered)
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
						for sourceID, ca := range m {
							for _, idx := range indexes {
								isContains, err := ca.Contains(ecosystem, criterionTypes.Query{Package: &qpkgs[idx]})
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
			return detectTypes.VulnerabilityDataDetection{}, errors.Wrapf(err, "detect pkg: %s %s", string(ecosystem), name)
		}
	}

	contents := make(map[string]map[sourceTypes.SourceID]criteriaTypes.FilteredCriteria)
	for rootID, m := range cm {
		for sourceID, fca := range m {
			qs := make([]criterionTypes.Query, 0, len(fca.indexes))
			for _, idx := range fca.indexes {
				qs = append(qs, criterionTypes.Query{Package: &qpkgs[idx]})
			}

			ac, err := fca.criteria.Accept(ecosystem, qs)
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
