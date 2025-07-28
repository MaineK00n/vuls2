package ospkg

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
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

	bn, bv, err := func() (string, string, error) {
		bn, err := pnfn(p.Name, p.ModularityLabel)
		if err != nil {
			return "", "", errors.Wrap(err, "form binary package name")
		}

		bv, err := pvfn(p.Epoch, p.Version, p.Release)
		if err != nil {
			return "", "", errors.Wrap(err, "form binary package version")
		}

		return bn, bv, nil
	}()
	if err != nil {
		return vcTypes.Query{}, errors.Wrap(err, "form binary package")
	}

	sn, sv, err := func() (string, string, error) {
		switch family {
		case ecosystemTypes.EcosystemTypeRedHat, ecosystemTypes.EcosytemCentOS:
			// TODO: Theoretically, we should check non-emptiness of p.SrcVersion here too. However, for workaround
			// in RHEL oval v2 -> vex transition, we accept empty SrcVersion and skip validation at the moment.
			// This switch MUST BE removed soon.
			if p.SrcName == "" {
				return "", "", nil
			}
			sn, err := pnfn(p.SrcName, p.ModularityLabel)
			if err != nil {
				return "", "", errors.Wrap(err, "form source package name")
			}

			if p.SrcVersion == "" {
				return sn, "", nil
			}
			sv, err := pvfn(p.SrcEpoch, p.SrcVersion, p.SrcRelease)
			if err != nil {
				return "", "", errors.Wrap(err, "form source package version")
			}

			return sn, sv, nil
		case ecosystemTypes.EcosystemTypeDebian, ecosystemTypes.EcosystemTypeUbuntu:
			if p.SrcName == "" || p.SrcVersion == "" {
				return "", "", nil
			}

			n := p.SrcName
			if isKernelPackage(family, p.SrcName) {
				n = rename(family, p.SrcName)
			}

			sn, err := pnfn(n, "")
			if err != nil {
				return "", "", errors.Wrap(err, "form source package name")
			}

			sv, err := pvfn(p.SrcEpoch, p.SrcVersion, p.SrcRelease)
			if err != nil {
				return "", "", errors.Wrap(err, "form source package version")
			}

			return sn, sv, nil
		default:
			if p.SrcName == "" || p.SrcVersion == "" {
				return "", "", nil
			}

			sn, err := pnfn(p.SrcName, p.ModularityLabel)
			if err != nil {
				return "", "", errors.Wrap(err, "form source package name")
			}

			sv, err := pvfn(p.SrcEpoch, p.SrcVersion, p.SrcRelease)
			if err != nil {
				return "", "", errors.Wrap(err, "form source package version")
			}

			return sn, sv, nil
		}
	}()
	if err != nil {
		return vcTypes.Query{}, errors.Wrap(err, "form source package")
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
				if sn == "" {
					return nil
				}
				return &vcTypes.QuerySource{
					Family:     family,
					Name:       sn,
					Version:    sv,
					Repository: p.Repository,
				}
			default:
				if sn == "" || sv == "" {
					return nil
				}
				return &vcTypes.QuerySource{
					Family:     family,
					Name:       sn,
					Version:    sv,
					Repository: p.Repository,
				}
			}
		}(),
	}, nil
}

func rename(family ecosystemTypes.Ecosystem, name string) string {
	switch family {
	case ecosystemTypes.EcosystemTypeDebian:
		return strings.NewReplacer("linux-signed", "linux", "linux-latest", "linux", "-amd64", "", "-arm64", "", "-i386", "").Replace(name)
	case ecosystemTypes.EcosystemTypeUbuntu:
		return strings.NewReplacer("linux-signed", "linux", "linux-meta", "linux").Replace(name)
	default:
		return name
	}
}

func isKernelPackage(family ecosystemTypes.Ecosystem, name string) bool {
	switch family {
	case ecosystemTypes.EcosystemTypeDebian:
		switch ss := strings.Split(rename(family, name), "-"); len(ss) {
		case 1:
			return ss[0] == "linux"
		case 2:
			if ss[0] != "linux" {
				return false
			}
			switch ss[1] {
			case "grsec":
				return true
			default:
				_, err := strconv.ParseFloat(ss[1], 64)
				return err == nil
			}
		default:
			return false
		}
	case ecosystemTypes.EcosystemTypeUbuntu:
		switch ss := strings.Split(rename(family, name), "-"); len(ss) {
		case 1:
			return ss[0] == "linux"
		case 2:
			if ss[0] != "linux" {
				return false
			}
			switch ss[1] {
			case "armadaxp", "mako", "manta", "flo", "goldfish", "joule", "raspi", "raspi2", "snapdragon", "allwinner", "aws", "azure", "bluefield", "dell300x", "gcp", "gke", "gkeop", "ibm", "iot", "laptop", "lowlatency", "kvm", "nvidia", "oem", "oracle", "euclid", "hwe", "riscv", "starfive", "realtime", "mtk":
				return true
			default:
				_, err := strconv.ParseFloat(ss[1], 64)
				return err == nil
			}
		case 3:
			if ss[0] != "linux" {
				return false
			}
			switch ss[1] {
			case "ti":
				return ss[2] == "omap4"
			case "raspi", "raspi2", "allwinner", "gke", "gkeop", "ibm", "oracle", "riscv", "starfive":
				_, err := strconv.ParseFloat(ss[2], 64)
				return err == nil
			case "aws":
				switch ss[2] {
				case "hwe", "edge":
					return true
				default:
					_, err := strconv.ParseFloat(ss[2], 64)
					return err == nil
				}
			case "azure":
				switch ss[2] {
				case "cvm", "fde", "edge":
					return true
				default:
					_, err := strconv.ParseFloat(ss[2], 64)
					return err == nil
				}
			case "gcp":
				switch ss[2] {
				case "edge":
					return true
				default:
					_, err := strconv.ParseFloat(ss[2], 64)
					return err == nil
				}
			case "intel":
				switch ss[2] {
				case "iotg", "opt":
					return true
				default:
					_, err := strconv.ParseFloat(ss[2], 64)
					return err == nil
				}
			case "oem":
				switch ss[2] {
				case "osp1":
					return true
				default:
					_, err := strconv.ParseFloat(ss[2], 64)
					return err == nil
				}
			case "lts":
				switch ss[2] {
				case "utopic", "vivid", "wily", "xenial":
					return true
				default:
					return false
				}
			case "hwe":
				switch ss[2] {
				case "edge":
					return true
				default:
					_, err := strconv.ParseFloat(ss[2], 64)
					return err == nil
				}
			case "xilinx":
				return ss[2] == "zynqmp"
			case "nvidia":
				switch ss[2] {
				case "tegra":
					return true
				default:
					_, err := strconv.ParseFloat(ss[2], 64)
					return err == nil
				}
			default:
				return false
			}
		case 4:
			if ss[0] != "linux" {
				return false
			}
			switch ss[1] {
			case "azure":
				if ss[2] != "fde" {
					return false
				}
				_, err := strconv.ParseFloat(ss[3], 64)
				return err == nil
			case "intel":
				if ss[2] != "iotg" {
					return false
				}
				_, err := strconv.ParseFloat(ss[3], 64)
				return err == nil
			case "lowlatency":
				if ss[2] != "hwe" {
					return false
				}
				_, err := strconv.ParseFloat(ss[3], 64)
				return err == nil
			case "nvidia":
				if ss[2] != "tegra" {
					return false
				}
				switch ss[3] {
				case "igx":
					return true
				default:
					_, err := strconv.ParseFloat(ss[3], 64)
					return err == nil
				}
			default:
				return false
			}
		default:
			return false
		}
	default:
		return false
	}
}
