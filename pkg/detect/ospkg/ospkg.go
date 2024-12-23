package ospkg

import (
	"fmt"
	"slices"
	"strings"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	necTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion"
	necBinaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion/binary"
	necSourcePackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion/source"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	db "github.com/MaineK00n/vuls2/pkg/db/common"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/common/types"
	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"
	scanTypes "github.com/MaineK00n/vuls2/pkg/scan/types"
)

func Detect(dbc db.DB, sr scanTypes.ScanResult) (map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection, error) {
	ecosystem, err := ecosystemTypes.GetEcosystem(string(sr.Family), sr.Release)
	if err != nil {
		return nil, errors.Wrapf(err, "get ecosystem. family: %s, release: %s", sr.Family, sr.Release)
	}

	vcpkgs := make([]vcTypes.Query, 0, len(sr.OSPackages))
	vcm := make(map[string][]int)
	var necq necTypes.Query
	for i, p := range sr.OSPackages {
		converted, err := convertVCQueryPackage(sr.Family, p)
		if err != nil {
			return nil, errors.Wrap(err, "convert version criterion package")
		}
		vcpkgs = append(vcpkgs, converted)

		if converted.Binary != nil && !slices.Contains(vcm[converted.Binary.Name], i) {
			vcm[converted.Binary.Name] = append(vcm[converted.Binary.Name], i)
		}
		if converted.Source != nil && !slices.Contains(vcm[converted.Source.Name], i) {
			vcm[converted.Source.Name] = append(vcm[converted.Source.Name], i)
		}

		if converted.Binary != nil && !slices.Contains(necq.Binaries, necBinaryPackageTypes.Query{
			Name:       converted.Binary.Name,
			Arch:       converted.Binary.Arch,
			Repository: converted.Binary.Repository,
		}) {
			necq.Binaries = append(necq.Binaries, necBinaryPackageTypes.Query{
				Name:       converted.Binary.Name,
				Arch:       converted.Binary.Arch,
				Repository: converted.Binary.Repository,
			})
		}
		if converted.Source != nil && !slices.Contains(necq.Sources, necSourcePackageTypes.Query{
			Name:       converted.Source.Name,
			Repository: converted.Source.Repository,
		}) {
			necq.Sources = append(necq.Sources, necSourcePackageTypes.Query{
				Name:       converted.Source.Name,
				Repository: converted.Source.Repository,
			})
		}
	}

	type prefiltered struct {
		condition conditionTypes.Condition
		indexes   []int
	}
	pfmm := make(map[dataTypes.RootID]map[sourceTypes.SourceID][]prefiltered)
	for name, indexes := range vcm {
		if err := func() error {
			done := make(chan struct{})
			defer close(done)
			resCh, errCh := dbc.GetVulnerabilityDetections(done, dbTypes.SearchDetectionPkg, string(ecosystem), name)
			for {
				select {
				case item, ok := <-resCh:
					if !ok {
						return nil
					}
					for rootID, m := range item.Contents {
						for sourceID, conds := range m {
							for _, cond := range conds {
								containedIndexes := make([]int, 0, len(indexes))
								for _, idx := range indexes {
									isContained, err := cond.Contains(criterionTypes.Query{
										Version:   []vcTypes.Query{vcpkgs[idx]},
										NoneExist: &necq,
									})
									if err != nil {
										return errors.Wrap(err, "condition contains")
									}

									if isContained {
										containedIndexes = append(containedIndexes, idx)
									}
								}
								if len(containedIndexes) > 0 {
									if pfmm[rootID] == nil {
										pfmm[rootID] = make(map[sourceTypes.SourceID][]prefiltered)
									}
									pfmm[rootID][sourceID] = append(pfmm[rootID][sourceID], prefiltered{
										condition: cond,
										indexes:   containedIndexes,
									})
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
			return nil, errors.Wrapf(err, "detect pkg: %s %s", ecosystem, name)
		}
	}

	dm := make(map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection)
	for rootID, pfm := range pfmm {
		for sourceID, pfs := range pfm {
			for _, pf := range pfs {
				fcond, err := pf.condition.Accept(func() criterionTypes.Query {
					return criterionTypes.Query{
						Version: func() []vcTypes.Query {
							qs := make([]vcTypes.Query, 0, len(pf.indexes))
							for _, idx := range pf.indexes {
								qs = append(qs, vcpkgs[idx])
							}
							return qs
						}(),
						NoneExist: &necq,
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
							Ecosystem: ecosystem,
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
	}

	return dm, nil
}

func convertVCQueryPackage(family ecosystemTypes.Ecosystem, p scanTypes.OSPackage) (vcTypes.Query, error) {
	pnfn := func(pkgname, modularitylabel string) (string, error) {
		if pkgname == "" {
			return "", errors.New("name is empty")
		}
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

	pvfn := func(epoch *int, version, release string) (string, error) {
		if version == "" {
			return "", errors.New("version is empty")
		}

		var sb strings.Builder
		if epoch != nil {
			if _, err := sb.WriteString(fmt.Sprintf("%d:", *epoch)); err != nil {
				return "", errors.Wrap(err, "append epoch")
			}
		}
		if _, err := sb.WriteString(version); err != nil {
			return "", errors.Wrap(err, "append version")
		}
		if release != "" {
			if _, err := sb.WriteString(fmt.Sprintf("-%s", release)); err != nil {
				return "", errors.Wrap(err, "append release")
			}
		}
		return sb.String(), nil
	}

	bn, err := pnfn(p.Name, p.ModularityLabel)
	if err != nil {
		return vcTypes.Query{}, errors.Wrap(err, "form binary package name")
	}

	bv, err := pvfn(p.Epoch, p.Version, p.Release)
	if err != nil {
		return vcTypes.Query{}, errors.Wrap(err, "form binary package version")
	}

	var (
		sn string
		sv string
	)
	if p.SrcName != "" && p.SrcVersion != "" {
		sn, err = pnfn(p.SrcName, p.ModularityLabel)
		if err != nil {
			return vcTypes.Query{}, errors.Wrap(err, "form source package name")
		}

		sv, err = pvfn(p.SrcEpoch, p.SrcVersion, p.SrcRelease)
		if err != nil {
			return vcTypes.Query{}, errors.Wrap(err, "form source package version")
		}
	}

	return vcTypes.Query{
		Binary: &vcTypes.QueryBinary{
			Family:     family,
			Name:       bn,
			Version:    bv,
			Arch:       p.Arch,
			Repository: p.Repository,
		},
		Source: func() *vcTypes.QuerySource {
			if sn != "" && sv != "" {
				return &vcTypes.QuerySource{
					Family:     family,
					Name:       sn,
					Version:    sv,
					Repository: p.Repository,
				}
			}
			return nil
		}(),
	}, nil
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
