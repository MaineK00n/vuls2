package microsoft

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	kbcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/kbcriterion"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	"github.com/MaineK00n/vuls2/pkg/db/session"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/session/types"
	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"
	"github.com/MaineK00n/vuls2/pkg/detect/util"
	scanTypes "github.com/MaineK00n/vuls2/pkg/scan/types"
)

func Detect(s session.Storage, ecosystem ecosystemTypes.Ecosystem, sr scanTypes.ScanResult, concurrency int) (map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection, error) {
	// Collect product names as index keys from installed packages and KB data.
	vcm := make(map[string][]int)

	// Build version queries from OS packages.
	// NOTE: Callers must include the OS release as a synthetic OSPackage
	// (Name=Release, Version=Kernel.Version) for kernel-version-based detection to work.
	var vcpkgs []vcTypes.Query
	// Maps each vcpkgs entry to its corresponding sr.OSPackages index.
	var vcpkgToOSIdx []int

	for i, p := range sr.OSPackages {
		if p.Name == "" || p.Version == "" {
			continue
		}

		// Normalize scan-reported package names to CVRF product names.
		names := normalizeMicrosoftPackageName(p.Name, sr.Release)
		if len(names) == 0 {
			// No mapping found; use the original name as-is.
			names = []string{p.Name}
		}
		for _, name := range names {
			vcm[name] = append(vcm[name], len(vcpkgs))
			vcpkgs = append(vcpkgs, vcTypes.Query{
				Binary: &vcTypes.QueryBinary{
					Name:    name,
					Version: p.Version,
				},
			})
			vcpkgToOSIdx = append(vcpkgToOSIdx, i)
		}
	}

	for _, kbid := range append(sr.MicrosoftKB.Applied, sr.MicrosoftKB.Unapplied...) {
		m, err := s.GetMicrosoftKB(kbid)
		if err != nil {
			if errors.Is(err, dbTypes.ErrNotFoundMicrosoftKB) {
				continue
			}
			return nil, errors.Wrapf(err, "get microsoft kb %s", kbid)
		}
		for _, kb := range m {
			for _, p := range kb.Products {
				if !filterMicrosoftKBProduct(p, sr.Release) {
					continue
				}
				if _, ok := vcm[p]; !ok {
					vcm[p] = nil
				}
			}
		}
	}

	unappliedKBs, err := computeUnappliedKBs(s, sr.MicrosoftKB.Applied, sr.MicrosoftKB.Unapplied)
	if err != nil {
		return nil, errors.Wrap(err, "compute unapplied KBs")
	}

	dm, err := util.Detect(s, ecosystem, slices.Collect(maps.Keys(vcm)), func(rootID dataTypes.RootID, queries []string) util.Request {
		var (
			qs    []vcTypes.Query
			idxes []int
		)
		for _, q := range queries {
			for _, idx := range vcm[q] {
				qs = append(qs, vcpkgs[idx])
				idxes = append(idxes, vcpkgToOSIdx[idx])
			}
		}

		query := criterionTypes.Query{
			Version: qs,
		}
		if len(unappliedKBs) > 0 {
			query.KB = &kbcTypes.Query{UnappliedKBs: unappliedKBs}
		}

		return util.Request{
			RootID:  rootID,
			Query:   query,
			Indexes: idxes,
		}
	}, concurrency)
	if err != nil {
		return nil, errors.Wrap(err, "detect")
	}
	return dm, nil
}

func computeUnappliedKBs(s session.Storage, applied []string, unapplied []string) ([]string, error) {
	appliedSet := make(map[string]struct{}, len(applied))
	for _, kb := range applied {
		appliedSet[kb] = struct{}{}
	}

	// Collect all reachable KBs by traversing SupersededBy chains forward
	// from both Applied and Unapplied. Any discovered KB not in Applied is unapplied.
	visited := make(map[string]struct{})
	unappliedSet := make(map[string]struct{})

	var walk func(kbid string) error
	walk = func(kbid string) error {
		if _, ok := visited[kbid]; ok {
			return nil
		}
		visited[kbid] = struct{}{}

		if _, ok := appliedSet[kbid]; !ok {
			unappliedSet[kbid] = struct{}{}
		}

		m, err := s.GetMicrosoftKB(kbid)
		if err != nil {
			if errors.Is(err, dbTypes.ErrNotFoundMicrosoftKB) {
				return nil
			}
			return errors.Wrapf(err, "get microsoft kb %s", kbid)
		}

		for _, kb := range m {
			for _, sup := range kb.SupersededBy {
				if sup.KBID == "" {
					continue
				}
				if err := walk(sup.KBID); err != nil {
					return err
				}
			}
			for _, u := range kb.Updates {
				for _, sup := range u.SupersededBy {
					if sup.KBID == "" {
						continue
					}
					if err := walk(sup.KBID); err != nil {
						return err
					}
				}
			}
		}

		return nil
	}

	for _, kbid := range applied {
		if err := walk(kbid); err != nil {
			return nil, errors.Wrapf(err, "walk supersession chain from applied KB: %s", kbid)
		}
	}
	for _, kbid := range unapplied {
		if err := walk(kbid); err != nil {
			return nil, errors.Wrapf(err, "walk supersession chain from unapplied KB: %s", kbid)
		}
	}

	return slices.Collect(maps.Keys(unappliedSet)), nil
}

func normalizeMicrosoftPackageName(name, release string) []string {
	for _, r := range microsoftPackageNameRules {
		if r.pattern.MatchString(name) {
			return r.normalize(name, release)
		}
	}
	return nil
}

type normalizeRule struct {
	pattern   *regexp.Regexp
	normalize func(name, release string) []string
}

var microsoftPackageNameRules = []normalizeRule{
	{
		pattern: regexp.MustCompile(`(?i)^Microsoft Edge$`),
		normalize: func(_, release string) []string {
			names := []string{
				"Microsoft Edge (Chromium-based)",
			}
			if release != "" {
				names = append(names,
					fmt.Sprintf("Microsoft Edge (Chromium-based) in IE Mode on %s", release),
					fmt.Sprintf("Microsoft Edge (EdgeHTML-based) on %s", release),
				)
			}
			return names
		},
	},
	{
		pattern: regexp.MustCompile(`(?i)^Microsoft Visual Studio Code`),
		normalize: func(_, _ string) []string {
			return []string{"Visual Studio Code"}
		},
	},
	{
		pattern: regexp.MustCompile(`(?i)^Microsoft Teams$`),
		normalize: func(_, _ string) []string {
			return []string{"Microsoft Teams", "Microsoft Teams for Desktop"}
		},
	},
}

func filterMicrosoftKBProduct(product, release string) bool {
	if release == "" {
		return true
	}
	suffix := extractOSSuffix(product)
	if suffix == "" {
		// Bare OS name (e.g. "Windows 10 Version 21H2 for x64-based Systems",
		// "Windows Server 2012 R2"). Must match release exactly to avoid
		// cross-product contamination from multi-product KBs.
		return product == release
	}
	return suffix == release
}

func extractOSSuffix(product string) string {
	if _, after, ok := strings.Cut(product, " installed on "); ok {
		return after
	}
	if _, after, ok := strings.Cut(product, " on "); ok {
		return after
	}
	return ""
}
