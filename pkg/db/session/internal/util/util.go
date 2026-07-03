package util

import (
	"encoding/json/v2"
	"fmt"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"

	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	ccTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
	vcPackageType "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
)

func Marshal(v any) ([]byte, error) {
	bs, err := json.Marshal(v, json.Deterministic(true))
	if err != nil {
		return nil, errors.Wrap(err, "json marshal")
	}
	return bs, nil
}

func Unmarshal(data []byte, v any) error {
	if err := json.Unmarshal(data, v); err != nil {
		return errors.Wrap(err, "json unmarshal")
	}
	return nil
}

func WalkCriteria(ca criteriaTypes.Criteria) ([]string, error) {
	var pkgs []string

	for _, ca := range ca.Criterias {
		ps, err := WalkCriteria(ca)
		if err != nil {
			return nil, errors.Wrap(err, "walk criteria")
		}
		pkgs = append(pkgs, ps...)
	}

	for _, cn := range ca.Criterions {
		switch cn.Type {
		case criterionTypes.CriterionTypeVersion:
			switch cn.Version.Package.Type {
			case vcPackageType.PackageTypeBinary:
				pkgs = append(pkgs, cn.Version.Package.Binary.Name)
			case vcPackageType.PackageTypeSource:
				pkgs = append(pkgs, cn.Version.Package.Source.Name)
			case vcPackageType.PackageTypeLanguage:
				pkgs = append(pkgs, cn.Version.Package.Language.Name)
			default:
				return nil, errors.Errorf("unexpected version criterion package type. expected: %q, actual: %q", []vcPackageType.PackageType{vcPackageType.PackageTypeBinary, vcPackageType.PackageTypeSource, vcPackageType.PackageTypeLanguage}, cn.Version.Package.Type)
			}
		case criterionTypes.CriterionTypeNoneExist:
		case criterionTypes.CriterionTypeKB:
			if cn.KB != nil {
				pkgs = append(pkgs, cn.KB.Product)
			}
		case criterionTypes.CriterionTypeCPE:
			if cn.CPE == nil {
				continue
			}
			// cpecriterion.Accept can match on a CPEMatches entry alone, even
			// when its part:vendor:product differs from the main CPE (upstream
			// data mixes vendor spellings, e.g. paloaltonetworks vs
			// palo_alto_networks), so every PVP the criterion can accept must
			// be indexed, not just the main CPE's.
			for _, c := range append([]ccTypes.CPE{cn.CPE.CPE}, cn.CPE.CPEMatches...) {
				wfn, err := naming.UnbindFS(string(c))
				if err != nil {
					return nil, errors.Wrapf(err, "unbind %q", string(c))
				}
				pkgs = append(pkgs, fmt.Sprintf("%s:%s:%s", wfn.GetString(common.AttributePart), wfn.GetString(common.AttributeVendor), wfn.GetString(common.AttributeProduct)))
			}
		default:
			return nil, errors.Errorf("unexpected criterion type. expected: %q, actual: %q", []criterionTypes.CriterionType{criterionTypes.CriterionTypeVersion, criterionTypes.CriterionTypeNoneExist, criterionTypes.CriterionTypeKB, criterionTypes.CriterionTypeCPE}, cn.Type)
		}
	}

	return pkgs, nil
}
