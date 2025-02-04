package util

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"

	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	necPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion"
	vcPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
)

func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	je := json.NewEncoder(&buf)
	je.SetEscapeHTML(false)
	if err := je.Encode(v); err != nil {
		return nil, errors.Wrap(err, "json encode")
	}
	return buf.Bytes(), nil
}

func Unmarshal(data []byte, v any) error {
	if err := json.Unmarshal(data, v); err != nil {
		return errors.Wrap(err, "json unmarshal")
	}
	return nil
}

func ReplaceRepositories(conds []conditionTypes.Condition, repom map[string]string) error {
	var f func(ca criteriaTypes.Criteria, repom map[string]string) error
	f = func(ca criteriaTypes.Criteria, repom map[string]string) error {
		for i := range ca.Criterias {
			if err := f(ca.Criterias[i], repom); err != nil {
				return errors.Wrap(err, "walk criteria")
			}
		}

		for i := range ca.Criterions {
			switch ca.Criterions[i].Type {
			case criterionTypes.CriterionTypeVersion:
				switch ca.Criterions[i].Version.Package.Type {
				case vcPackageTypes.PackageTypeBinary:
					for j, r := range ca.Criterions[i].Version.Package.Binary.Repositories {
						k, ok := repom[r]
						if !ok {
							k = fmt.Sprintf("%d", len(repom))
							repom[r] = k
						}
						ca.Criterions[i].Version.Package.Binary.Repositories[j] = k
					}
				case vcPackageTypes.PackageTypeSource:
					for j, r := range ca.Criterions[i].Version.Package.Source.Repositories {
						k, ok := repom[r]
						if !ok {
							k = fmt.Sprintf("%d", len(repom))
							repom[r] = k
						}
						ca.Criterions[i].Version.Package.Source.Repositories[j] = k
					}
				case vcPackageTypes.PackageTypeCPE, vcPackageTypes.PackageTypeLanguage:
				default:
					return errors.Errorf("unexpected version criterion package type. expected: %q, actual: %q", []vcPackageTypes.PackageType{vcPackageTypes.PackageTypeBinary, vcPackageTypes.PackageTypeSource, vcPackageTypes.PackageTypeCPE, vcPackageTypes.PackageTypeLanguage}, ca.Criterions[i].Version.Package.Type)
				}
			case criterionTypes.CriterionTypeNoneExist:
				switch ca.Criterions[i].NoneExist.Type {
				case necPackageTypes.PackageTypeBinary:
					for j, r := range ca.Criterions[i].NoneExist.Binary.Repositories {
						k, ok := repom[r]
						if !ok {
							k = fmt.Sprintf("%d", len(repom))
							repom[r] = k
						}
						ca.Criterions[i].NoneExist.Binary.Repositories[j] = k
					}
				case necPackageTypes.PackageTypeSource:
					for j, r := range ca.Criterions[i].NoneExist.Source.Repositories {
						k, ok := repom[r]
						if !ok {
							k = fmt.Sprintf("%d", len(repom))
							repom[r] = k
						}
						ca.Criterions[i].NoneExist.Source.Repositories[j] = k
					}
				default:
					return errors.Errorf("unexpected none exist criterion package type. expected: %q, actual: %q", []necPackageTypes.PackageType{necPackageTypes.PackageTypeBinary, necPackageTypes.PackageTypeSource}, ca.Criterions[i].NoneExist.Type)
				}
			default:
				return errors.Errorf("unexpected criterion type. expected: %q, actual: %q", []criterionTypes.CriterionType{criterionTypes.CriterionTypeVersion, criterionTypes.CriterionTypeNoneExist}, ca.Criterions[i].Type)
			}
		}

		return nil
	}

	for i := range conds {
		if err := f(conds[i].Criteria, repom); err != nil {
			return errors.Wrap(err, "walk criteria")
		}
	}
	return nil
}

func CollectPkgName(conds []conditionTypes.Condition) ([]string, error) {
	var f func(ca criteriaTypes.Criteria) ([]string, error)
	f = func(ca criteriaTypes.Criteria) ([]string, error) {
		var pkgs []string

		for _, ca := range ca.Criterias {
			ps, err := f(ca)
			if err != nil {
				return nil, errors.Wrap(err, "walk criteria")
			}
			pkgs = append(pkgs, ps...)
		}

		for _, cn := range ca.Criterions {
			switch cn.Type {
			case criterionTypes.CriterionTypeVersion:
				switch cn.Version.Package.Type {
				case vcPackageTypes.PackageTypeBinary:
					pkgs = append(pkgs, cn.Version.Package.Binary.Name)
				case vcPackageTypes.PackageTypeSource:
					pkgs = append(pkgs, cn.Version.Package.Source.Name)
				case vcPackageTypes.PackageTypeCPE:
					wfn, err := naming.UnbindFS(string(*cn.Version.Package.CPE))
					if err != nil {
						return nil, errors.Wrapf(err, "unbind %q", string(*cn.Version.Package.CPE))
					}
					pkgs = append(pkgs, fmt.Sprintf("%s:%s", wfn.GetString(common.AttributeVendor), wfn.GetString(common.AttributeProduct)))
				case vcPackageTypes.PackageTypeLanguage:
					pkgs = append(pkgs, cn.Version.Package.Language.Name)
				default:
					return nil, errors.Errorf("unexpected version criterion package type. expected: %q, actual: %q", []vcPackageTypes.PackageType{vcPackageTypes.PackageTypeBinary, vcPackageTypes.PackageTypeSource, vcPackageTypes.PackageTypeCPE, vcPackageTypes.PackageTypeLanguage}, cn.Version.Package.Type)
				}
			case criterionTypes.CriterionTypeNoneExist:
			default:
				return nil, errors.Errorf("unexpected criterion type. expected: %q, actual: %q", []criterionTypes.CriterionType{criterionTypes.CriterionTypeVersion, criterionTypes.CriterionTypeNoneExist}, cn.Type)
			}
		}

		return pkgs, nil
	}

	m := make(map[string]struct{})
	for _, cond := range conds {
		ps, err := f(cond.Criteria)
		if err != nil {
			return nil, errors.Wrap(err, "walk criteria")
		}
		for _, p := range ps {
			m[p] = struct{}{}
		}
	}
	return slices.Collect(maps.Keys(m)), nil
}
