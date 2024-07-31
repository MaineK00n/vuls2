package util

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"

	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria"
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

func WalkCriteria(ca criteriaTypes.Criteria) []string {
	var pkgs []string

	for _, ca := range ca.Criterias {
		pkgs = append(pkgs, WalkCriteria(ca)...)
	}

	for _, co := range ca.Criterions {
		if !co.Vulnerable {
			continue
		}

		if co.Package.Name != "" {
			pkgs = append(pkgs, co.Package.Name)
		}
		if co.Package.CPE != "" {
			wfn, err := naming.UnbindFS(co.Package.CPE)
			if err != nil {
				slog.Warn("failed to unbind a formatted string to WFN", "input", co.Package.CPE)
				continue
			}
			pkgs = append(pkgs, fmt.Sprintf("%s:%s", wfn.GetString(common.AttributeVendor), wfn.GetString(common.AttributeProduct)))
		}
	}

	return pkgs
}
