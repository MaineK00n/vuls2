package ospkg

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	necTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion"
	necBinaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion/binary"
	necSourcePackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion/source"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	db "github.com/MaineK00n/vuls2/pkg/db/common"
	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"
	"github.com/MaineK00n/vuls2/pkg/detect/util"
	scanTypes "github.com/MaineK00n/vuls2/pkg/scan/types"
)

func Detect(dbc db.DB, sr scanTypes.ScanResult, concurrency int) (map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection, error) {
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

	dm, err := util.Detect(dbc, ecosystem, slices.Collect(maps.Keys(vcm)), func(rootID dataTypes.RootID, queries []string) util.Request {
		var (
			qs    []vcTypes.Query
			idxes []int
		)
		for _, q := range queries {
			for _, idx := range vcm[q] {
				qs = append(qs, vcpkgs[idx])
			}
			idxes = append(idxes, vcm[q]...)
		}
		return util.Request{
			RootID: rootID,
			Query: criterionTypes.Query{
				Version:   qs,
				NoneExist: &necq,
			},
			Indexes: idxes,
		}
	}, concurrency)
	if err != nil {
		return nil, errors.Wrap(err, "detect")
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
	switch family {
	case ecosystemTypes.EcosystemTypeRedHat, ecosystemTypes.EcosytemCentOS:
		// TODO: Theoretically, we should check non-emptiess of p.SrcVersion here too. However, for workaround
		// in RHEL oval v2 -> vex transition, we accept empty SrcVersion and skip validation at the moment.
		// This switch MUST BE removed soon.
		if p.SrcName != "" {
			sn, err = pnfn(p.SrcName, p.ModularityLabel)
			if err != nil {
				return vcTypes.Query{}, errors.Wrap(err, "form source package name")
			}

			if p.SrcVersion != "" {
				sv, err = pvfn(p.SrcEpoch, p.SrcVersion, p.SrcRelease)
				if err != nil {
					return vcTypes.Query{}, errors.Wrap(err, "form source package version")
				}
			}
		}
	default:
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
			switch family {
			case ecosystemTypes.EcosystemTypeRedHat, ecosystemTypes.EcosytemCentOS:
				// TODO: This switch should also be removed soon as well as the above one.
				if sn != "" {
					return &vcTypes.QuerySource{
						Family:     family,
						Name:       sn,
						Version:    sv,
						Repository: p.Repository,
					}
				}
				return nil
			default:
				if sn != "" && sv != "" {
					return &vcTypes.QuerySource{
						Family:     family,
						Name:       sn,
						Version:    sv,
						Repository: p.Repository,
					}
				}
				return nil
			}
		}(),
	}, nil
}
