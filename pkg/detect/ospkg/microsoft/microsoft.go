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

	coveredKBs, unappliedKBs, err := classifyKBs(s, sr.MicrosoftKB.Applied, sr.MicrosoftKB.Unapplied)
	if err != nil {
		return nil, errors.Wrap(err, "classify KBs")
	}

	// Filter unapplied/covered KBs to only those whose products are relevant
	// to this host. Without this filter, supersession chain walking can discover
	// KBs for unrelated products (e.g., a Server 2012 KB reachable from a Win11
	// chain), causing the KB criterion to match cross-product conditions.
	coveredKBs, err = filterKBIDsByRelease(s, coveredKBs, sr.Release)
	if err != nil {
		return nil, errors.Wrap(err, "filter covered KBs by release")
	}
	unappliedKBs, err = filterKBIDsByRelease(s, unappliedKBs, sr.Release)
	if err != nil {
		return nil, errors.Wrap(err, "filter unapplied KBs by release")
	}

	vcmProducts := slices.Collect(maps.Keys(vcm))

	dm, err := util.Detect(s, ecosystem, vcmProducts, func(rootID dataTypes.RootID, queries []string) util.Request {
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
		if len(coveredKBs) > 0 || len(unappliedKBs) > 0 {
			query.KB = &kbcTypes.Query{
				AcceptProducts: vcmProducts,
				CoveredKBs:     coveredKBs,
				UnappliedKBs:   unappliedKBs,
			}
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

func classifyKBs(s session.Storage, applied []string, unapplied []string) (coveredKBs, unappliedKBs []string, _ error) {
	// Prefer unapplied when a KB appears in both lists because:
	// 1. QueryHistory may record a past successful install (Operation=1, ResultCode=2) even after
	//    the update was rolled back or never fully applied, causing a false "applied" entry.
	// 2. RebootRequired=1 KBs are intentionally placed in unapplied by the scanner, but other
	//    sources (e.g. Get-HotFix) may also add them to applied, masking the pending reboot state.
	appliedSet := make(map[string]struct{}, len(applied))
	for _, kb := range applied {
		appliedSet[kb] = struct{}{}
	}
	removedFromApplied := make(map[string]struct{})
	for _, kb := range unapplied {
		if _, ok := appliedSet[kb]; ok {
			removedFromApplied[kb] = struct{}{}
		}
		delete(appliedSet, kb)
	}

	// Collect all reachable KBs by traversing SupersededBy chains forward
	// from both Applied and Unapplied, and build a reverse edge map
	// (superseding KB → list of superseded KBs) for the coverage BFS.
	visited := make(map[string]struct{})
	revEdges := make(map[string][]string)

	var walk func(kbid string) error
	walk = func(kbid string) error {
		if _, ok := visited[kbid]; ok {
			return nil
		}
		visited[kbid] = struct{}{}

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
				revEdges[sup.KBID] = append(revEdges[sup.KBID], kbid)
				if err := walk(sup.KBID); err != nil {
					return errors.Wrapf(err, "walk supersession from KB %s to %s", kbid, sup.KBID)
				}
			}
			for _, u := range kb.Updates {
				for _, sup := range u.SupersededBy {
					if sup.KBID == "" {
						continue
					}
					revEdges[sup.KBID] = append(revEdges[sup.KBID], kbid)
					if err := walk(sup.KBID); err != nil {
						return errors.Wrapf(err, "walk supersession from KB %s to %s (via update)", kbid, sup.KBID)
					}
				}
			}
		}

		return nil
	}

	for _, kbid := range applied {
		if err := walk(kbid); err != nil {
			return nil, nil, errors.Wrapf(err, "walk supersession chain from applied KB: %s", kbid)
		}
	}
	for _, kbid := range unapplied {
		if err := walk(kbid); err != nil {
			return nil, nil, errors.Wrapf(err, "walk supersession chain from unapplied KB: %s", kbid)
		}
	}

	// Find all KBs covered by an applied superseding KB. BFS backwards from
	// appliedSet through reverse edges. Handles cycles via the covered set.
	covered := make(map[string]struct{}, len(appliedSet))
	queue := make([]string, 0, len(appliedSet))
	for kbid := range appliedSet {
		if _, ok := visited[kbid]; ok {
			covered[kbid] = struct{}{}
			queue = append(queue, kbid)
		}
	}
	for head := 0; head < len(queue); head++ {
		cur := queue[head]
		for _, pred := range revEdges[cur] {
			if _, ok := covered[pred]; !ok {
				covered[pred] = struct{}{}
				queue = append(queue, pred)
			}
		}
	}

	// A KB is unapplied if it was discovered (in visited) and either:
	//   - not covered by any applied superseding KB, or
	//   - removed from appliedSet by unapplied-preference (always treated as
	//     unapplied regardless of coverage, to honour the scanner's signal).
	for kbid := range visited {
		if _, ok := covered[kbid]; ok {
			if _, ok := removedFromApplied[kbid]; !ok {
				continue
			}
		}
		unappliedKBs = append(unappliedKBs, kbid)
	}

	for kbid := range covered {
		coveredKBs = append(coveredKBs, kbid)
	}

	return coveredKBs, unappliedKBs, nil
}

// filterKBIDsByRelease removes KBs whose products are all irrelevant to
// the given release. When release is empty, all KBs pass through unchanged.
// KBs not found in the DB are kept to avoid false negatives.
func filterKBIDsByRelease(s session.Storage, kbs []string, release string) ([]string, error) {
	if release == "" {
		return kbs, nil
	}

	filtered := make([]string, 0, len(kbs))
	for _, kbid := range kbs {
		m, err := s.GetMicrosoftKB(kbid)
		if err != nil {
			if errors.Is(err, dbTypes.ErrNotFoundMicrosoftKB) {
				filtered = append(filtered, kbid)
				continue
			}
			return nil, errors.Wrapf(err, "get microsoft kb %s", kbid)
		}
		if func() bool {
			for _, kb := range m {
				if slices.ContainsFunc(kb.Products, func(p string) bool {
					return filterMicrosoftKBProduct(p, release)
				}) {
					return true
				}
			}
			return false
		}() {
			filtered = append(filtered, kbid)
		}
	}
	return filtered, nil
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
