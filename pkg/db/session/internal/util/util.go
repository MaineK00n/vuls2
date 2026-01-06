package util

import (
	"encoding/json/v2"
	"fmt"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"

	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
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
			case vcPackageType.PackageTypeCPE:
				wfn, err := naming.UnbindFS(string(*cn.Version.Package.CPE))
				if err != nil {
					return nil, errors.Wrapf(err, "unbind %q", string(*cn.Version.Package.CPE))
				}
				pkgs = append(pkgs, fmt.Sprintf("%s:%s", wfn.GetString(common.AttributeVendor), wfn.GetString(common.AttributeProduct)))
			case vcPackageType.PackageTypeLanguage:
				pkgs = append(pkgs, cn.Version.Package.Language.Name)
			default:
				return nil, errors.Errorf("unexpected version criterion package type. expected: %q, actual: %q", []vcPackageType.PackageType{vcPackageType.PackageTypeBinary, vcPackageType.PackageTypeSource, vcPackageType.PackageTypeCPE, vcPackageType.PackageTypeLanguage}, cn.Version.Package.Type)
			}
		case criterionTypes.CriterionTypeNoneExist:
		default:
			return nil, errors.Errorf("unexpected criterion type. expected: %q, actual: %q", []criterionTypes.CriterionType{criterionTypes.CriterionTypeVersion, criterionTypes.CriterionTypeNoneExist}, cn.Type)
		}
	}

	return pkgs, nil
}
