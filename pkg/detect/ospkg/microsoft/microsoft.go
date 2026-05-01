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
	// and Supersedes chains backward from both Applied and Unapplied, and
	// build a reverse edge map (superseding KB → list of superseded KBs) for
	// the coverage BFS. Walking both directions makes the graph discovery
	// robust against incomplete SupersededBy data: even if old→new links are
	// missing, new→old Supersedes links can bridge the gap. Edges are sourced
	// from both KB-level fields (e.g. CVRF) and per-Update fields (e.g. MSUC,
	// wsusscn2) to maximize coverage across data sources.
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
			// Forward direction: this KB is superseded by newer KBs.
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

			// Backward direction: this KB supersedes older KBs.
			for _, sub := range kb.Supersedes {
				if sub.KBID == "" {
					continue
				}
				revEdges[kbid] = append(revEdges[kbid], sub.KBID)
				if err := walk(sub.KBID); err != nil {
					return errors.Wrapf(err, "walk supersedes from KB %s to %s", kbid, sub.KBID)
				}
			}
			for _, u := range kb.Updates {
				for _, sub := range u.Supersedes {
					if sub.KBID == "" {
						continue
					}
					revEdges[kbid] = append(revEdges[kbid], sub.KBID)
					if err := walk(sub.KBID); err != nil {
						return errors.Wrapf(err, "walk supersedes from KB %s to %s (via update)", kbid, sub.KBID)
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

// filterMicrosoftKBProduct decides whether a KB's product is relevant to
// the given host release. Two cases:
//
//   - Suffix products ("... on <release>" / "... installed on <release>")
//     are kept iff their suffix equals release (cross-product safety).
//   - Bare products are kept iff either they name a cross-platform app
//     that we actively want KB-criterion-based detection to evaluate
//     (see isKBCriterionApp), or they exactly equal the host release.
//     The default-filter direction means OS-named bare products must
//     match release exactly, while niche/legacy app products that are
//     unlikely to be installed are dropped — which prevents KB-criterion
//     "covered" matches from contaminating detections via the
//     supersession graph (e.g. Win7 host falsely flagging old "Media
//     Center TV Pack" or "Microsoft Windows Script Host" bulletins).
//
// AcceptProducts (gated by scanner-observed installed packages and
// applied / unapplied KB targets) is still the final arbiter for cases
// where this filter passes a product through.
func filterMicrosoftKBProduct(product, release string) bool {
	if release == "" {
		return true
	}
	if suffix := extractOSSuffix(product); suffix != "" {
		return suffix == release
	}
	if isKBCriterionApp(product) {
		return true
	}
	return product == release
}

// isKBCriterionApp reports whether a bare product (no " on " suffix) is
// a cross-platform Microsoft application family that we want
// KB-criterion-based detection to evaluate regardless of host OS
// release. Products outside this allowlist are subject to strict
// release-equality filtering — that is the desired behaviour for both
// OS-named bare products (where release equality is the right test) and
// for niche/legacy apps that are unlikely to be present on most scanned
// hosts and would otherwise trigger false positives via the
// supersession-graph "covered" path. Examples currently filtered:
// "Media Center TV Pack for Windows Vista", "Microsoft Surface with
// Windows RT", "Windows Virtual PC", "Windows Live OneCare",
// "Windows Essentials", "Microsoft Windows Script Host".
//
// Note that several "Windows ..." prefixed product families are
// intentionally allowlisted because Microsoft still ships
// KB-criterion-based updates for them across multiple host releases —
// e.g. Windows Defender, Windows Admin Center, Windows Malicious
// Software Removal Tool, Windows Media Player, Internet Security and
// Acceleration Server. Treat these as cross-platform apps, not as
// host-OS products.
//
// Add an entry here when a Microsoft product family becomes a regular
// target for KB-criterion-based detection (Patch Tuesday, monthly
// security updates, or equivalent). Removing an entry strips silent
// detection from that family.
func isKBCriterionApp(product string) bool {
	p := strings.TrimPrefix(product, "Microsoft ")

	// Family allowlist. A product matches when, after the optional
	// "Microsoft " trim, it equals the family token or starts with the
	// token followed by " " / "," / ":" (covering naming variants like
	// "Office 2016 (32-bit edition)" / "SharePoint Server, Version ..."
	// / "Platform SDK Redistributable: GDI+").
	appFamilies := []string{
		// "Internet Explorer" is the only major Microsoft app without a
		// "Microsoft " vendor prefix in the DB; trim above is a no-op for
		// it, so listing the family here picks up "Internet Explorer 11"
		// / "Internet Explorer 6.0" naturally.
		"Internet Explorer",

		// "2007 Microsoft Office System" is a Microsoft 2007-only
		// marketing name where the family token is embedded in the middle
		// of the product string. The 2010+ generation reverted to
		// "Microsoft Office <year>", so this entry is closed and won't
		// grow. Prefix matching is intentional here: it covers both the
		// family itself and suite variants like
		// "2007 Microsoft Office System Service Pack 3" — both should be
		// evaluated against KB criteria.
		"2007 Microsoft Office System",

		// Office suite & individual apps.
		"Office", "Word", "Excel", "PowerPoint", "Outlook", "Access",
		"OneNote", "Publisher", "Visio", "Project", "InfoPath",
		"FrontPage", "Live Meeting", "Communicator",

		// SharePoint / collaboration.
		"SharePoint", "Sharepoint",
		"Windows SharePoint Services",
		"Groove", "Groove Server",
		"FAST Search Server",
		"Business Productivity Servers",

		// Mail / messaging / telephony.
		"Exchange", "Lync", "Skype",

		// Database servers and drivers.
		"SQL Server",
		"Data Access Components", "Data Engine",
		"OLE DB Driver", "OLE DB Provider",
		"Report Viewer Redistributable",

		// Web / mainframe / commerce / management servers.
		"Internet Information Services", "Internet Information Server",
		"Internet Security and Acceleration Server",
		"Host Integration Server",
		"Commerce Server", "Content Management Server",
		"Endpoint Configuration Manager",

		// Developer tooling and runtimes.
		"Visual Studio", "Visual Basic", "Visual C++", "Visual FoxPro",
		".NET", "ASP.NET", "ASP.NET Core",
		"Expression Web", "Expression Studio",
		"Platform SDK Redistributable",

		// Browsers and runtimes.
		"Edge", "Silverlight",
		"MSXML", "XML Core Services",

		// Business / management products.
		"Dynamics", "BizTalk", "Forefront", "System Center",

		// Office productivity suite (legacy).
		"Works", "Works Suite",

		// File-format converters.
		"Open XML File Format Converter",

		// Azure-prefixed cross-platform apps.
		"Azure File Sync", "Azure Pack",

		// "Windows "-prefixed apps (NOT OS releases) that we still want
		// KB-criterion-based detection to evaluate. Other "Windows "-
		// prefixed legacy apps without ongoing security updates (Live
		// OneCare, Essentials, Journal Viewer, Messenger, Script Host,
		// Media Player on EOL'd Windows, ...) deliberately stay outside
		// this list.
		"Windows Defender",
		"Windows Admin Center",
		"Windows Update Assistant",
		"Windows Malicious Software Removal Tool",
		"Windows Azure Pack",
		"Windows Media Player",
	}
	for _, fam := range appFamilies {
		if p == fam {
			return true
		}
		if len(p) > len(fam) {
			switch p[len(fam)] {
			case ' ', ',', ':':
				if strings.HasPrefix(p, fam) {
					return true
				}
			}
		}
	}
	return false
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
