package detection_test

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/pkg/errors"

	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"

	"github.com/MaineK00n/vuls2/pkg/diff/detection"
	"github.com/MaineK00n/vuls2/pkg/diff/threshold"
)

func TestSubtract(t *testing.T) {
	type args struct {
		a []string
		b []string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "no diff",
			args: args{
				a: []string{"CVE-2026-0001", "CVE-2026-0002"},
				b: []string{"CVE-2026-0001", "CVE-2026-0002"},
			},
			want: nil,
		},
		{
			name: "a has extras",
			args: args{
				a: []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"},
				b: []string{"CVE-2026-0001"},
			},
			want: []string{"CVE-2026-0002", "CVE-2026-0003"},
		},
		{
			name: "b has extras",
			args: args{
				a: []string{"CVE-2026-0001"},
				b: []string{"CVE-2026-0001", "CVE-2026-0002"},
			},
			want: nil,
		},
		{
			name: "empty a",
			args: args{
				a: nil,
				b: []string{"CVE-2026-0001"},
			},
			want: nil,
		},
		{
			name: "empty b",
			args: args{
				a: []string{"CVE-2026-0001"},
				b: nil,
			},
			want: []string{"CVE-2026-0001"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detection.Subtract(tt.args.a, tt.args.b)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Subtract() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCollectSources(t *testing.T) {
	type args struct {
		scannedCves map[string]detection.VulnInfo
	}
	tests := []struct {
		name    string
		args    args
		want    map[sourceTypes.SourceID][]string
		wantErr bool
	}{
		{
			name: "empty",
			args: args{scannedCves: map[string]detection.VulnInfo{}},
			want: map[sourceTypes.SourceID][]string{},
		},
		{
			// Sibling feed variants (fortinet-csaf vs fortinet-cvrf) map to
			// the SAME cveContents type in vuls0, so only the vuls2-sources
			// marker can keep them apart — the very reason the marker is the
			// grouping key.
			name: "sibling sources under one content type stay distinct",
			args: args{
				scannedCves: map[string]detection.VulnInfo{
					"CVE-2026-0001": {CveContents: map[string][]detection.CveContent{
						"fortinet": {
							{Optional: map[string]string{"vuls2-sources": `[{"source_id":"fortinet-csaf"}]`}},
							{Optional: map[string]string{"vuls2-sources": `[{"source_id":"fortinet-cvrf"}]`}},
						},
					}},
					"CVE-2026-0002": {CveContents: map[string][]detection.CveContent{
						"fortinet": {
							{Optional: map[string]string{"vuls2-sources": `[{"source_id":"fortinet-csaf"}]`}},
						},
					}},
				},
			},
			want: map[sourceTypes.SourceID][]string{
				"fortinet-csaf": {"CVE-2026-0001", "CVE-2026-0002"},
				"fortinet-cvrf": {"CVE-2026-0001"},
			},
		},
		{
			// A merged content carries a multi-element source list (vuls0
			// merges contents of the same type, e.g. the NVD feed and API
			// sources both surface as "nvd"); every element counts, deduped
			// against other contents of the same CVE.
			name: "merged multi-source marker",
			args: args{
				scannedCves: map[string]detection.VulnInfo{
					"CVE-2026-0001": {CveContents: map[string][]detection.CveContent{
						"nvd": {
							{Optional: map[string]string{"vuls2-sources": `[{"source_id":"nvd-feed-cve-v2","root_id":"CVE-2026-0001"},{"source_id":"nvd-api-cve"}]`}},
						},
						"cisco": {
							{Optional: map[string]string{"vuls2-sources": `[{"source_id":"cisco-json"}]`}},
						},
					}},
				},
			},
			want: map[sourceTypes.SourceID][]string{
				"nvd-feed-cve-v2": {"CVE-2026-0001"},
				"nvd-api-cve":     {"CVE-2026-0001"},
				"cisco-json":      {"CVE-2026-0001"},
			},
		},
		{
			// Enrichment-added contents carry no vuls2-sources marker and must
			// not create a bucket — otherwise every CVE would also count under
			// the enrichment sources (NVD, MITRE, ...), coupling every file's
			// change rate to enrichment churn.
			name: "unmarked enrichment content ignored",
			args: args{
				scannedCves: map[string]detection.VulnInfo{
					"CVE-2026-0001": {CveContents: map[string][]detection.CveContent{
						"debian_security_tracker": {
							{Optional: map[string]string{"vuls2-sources": `[{"source_id":"debian-security-tracker-api"}]`}},
						},
						"nvd":   {{}},
						"mitre": {{Optional: map[string]string{"other-key": "x"}}},
					}},
				},
			},
			want: map[sourceTypes.SourceID][]string{
				"debian-security-tracker-api": {"CVE-2026-0001"},
			},
		},
		{
			// With a [vuls2]-only config every detected CVE comes from a
			// vuls2 detection path, which always attaches the marker — a CVE
			// without one signals a vuls0 bug, not a source to bucket.
			name: "no marked content errors",
			args: args{
				scannedCves: map[string]detection.VulnInfo{
					"CVE-2026-0001": {CveContents: map[string][]detection.CveContent{
						"nvd": {{}},
					}},
				},
			},
			wantErr: true,
		},
		{
			// A corrupt marker is a bug in the producing vuls0, not something
			// to paper over inside a CI guard.
			name: "corrupt marker errors",
			args: args{
				scannedCves: map[string]detection.VulnInfo{
					"CVE-2026-0001": {CveContents: map[string][]detection.CveContent{
						"nvd": {{Optional: map[string]string{"vuls2-sources": `not json`}}},
					}},
				},
			},
			wantErr: true,
		},
		{
			// vuls0 always writes at least one entry, so a well-formed but
			// empty list signals a marker format change and must fail
			// loudly.
			name: "empty marker list errors",
			args: args{
				scannedCves: map[string]detection.VulnInfo{
					"CVE-2026-0001": {CveContents: map[string][]detection.CveContent{
						"nvd": {{Optional: map[string]string{"vuls2-sources": `[]`}}},
					}},
				},
			},
			wantErr: true,
		},
		{
			// Same for an entry that parses but carries no source_id.
			name: "marker entry without source_id errors",
			args: args{
				scannedCves: map[string]detection.VulnInfo{
					"CVE-2026-0001": {CveContents: map[string][]detection.CveContent{
						"nvd": {{Optional: map[string]string{"vuls2-sources": `[{"root_id":"CVE-2026-0001"}]`}}},
					}},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := detection.CollectSources(tt.args.scannedCves)
			if (err != nil) != tt.wantErr {
				t.Fatalf("CollectSources() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			// ID lists carry no order guarantee (the report sorts for
			// presentation), so compare them order-insensitively.
			if diff := cmp.Diff(tt.want, got, cmpopts.SortSlices(func(a, b string) bool { return a < b })); diff != "" {
				t.Errorf("CollectSources() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDiffDetection(t *testing.T) {
	type args struct {
		name string
		ids  detection.CVEIDs
		th   threshold.Threshold
	}
	tests := []struct {
		name string
		args args
		want detection.FileDiff
	}{
		{
			name: "no change",
			args: args{
				name: "redhat_9",
				ids: detection.CVEIDs{
					Baseline: map[sourceTypes.SourceID][]string{"redhat-csaf": {"CVE-2026-0001", "CVE-2026-0002"}},
					Target:   map[sourceTypes.SourceID][]string{"redhat-csaf": {"CVE-2026-0001", "CVE-2026-0002"}},
				},
				th: threshold.Threshold{
					Default: threshold.Rates{threshold.Added: 10, threshold.Removed: 10},
				},
			},
			want: detection.FileDiff{
				Name: "redhat_9",
				Sources: []detection.SourceDiff{
					{
						SourceID:    "redhat-csaf",
						BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002"},
						TargetIDs:   []string{"CVE-2026-0001", "CVE-2026-0002"},
						Rates:       threshold.Rates{threshold.Added: 0, threshold.Removed: 0},
						Thresholds:  threshold.Rates{threshold.Added: 10, threshold.Removed: 10},
						Pass:        true,
					},
				},
				Pass: true,
			},
		},
		{
			// One ID swapped out of ten: 10% added and 10% removed, each
			// judged on its own axis.
			name: "small change within limit",
			args: args{
				name: "redhat_9",
				ids: detection.CVEIDs{
					Baseline: map[sourceTypes.SourceID][]string{"redhat-csaf": {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005",
						"CVE-2026-0006", "CVE-2026-0007", "CVE-2026-0008", "CVE-2026-0009", "CVE-2026-0010"}},
					Target: map[sourceTypes.SourceID][]string{"redhat-csaf": {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005",
						"CVE-2026-0006", "CVE-2026-0007", "CVE-2026-0008", "CVE-2026-0009", "CVE-2026-0011"}},
				},
				th: threshold.Threshold{
					Default: threshold.Rates{threshold.Added: 25, threshold.Removed: 25},
				},
			},
			want: detection.FileDiff{
				Name: "redhat_9",
				Sources: []detection.SourceDiff{
					{
						SourceID: "redhat-csaf",
						BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005",
							"CVE-2026-0006", "CVE-2026-0007", "CVE-2026-0008", "CVE-2026-0009", "CVE-2026-0010"},
						TargetIDs: []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005",
							"CVE-2026-0006", "CVE-2026-0007", "CVE-2026-0008", "CVE-2026-0009", "CVE-2026-0011"},
						Added:      []string{"CVE-2026-0011"},
						Removed:    []string{"CVE-2026-0010"},
						Rates:      threshold.Rates{threshold.Added: 10, threshold.Removed: 10},
						Thresholds: threshold.Rates{threshold.Added: 25, threshold.Removed: 25},
						Pass:       true,
					},
				},
				Pass: true,
			},
		},
		{
			name: "large removal exceeds limit",
			args: args{
				name: "ubuntu_22.04",
				ids: detection.CVEIDs{
					Baseline: map[sourceTypes.SourceID][]string{"ubuntu-oval": {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"}},
					Target:   map[sourceTypes.SourceID][]string{"ubuntu-oval": {"CVE-2026-0001"}},
				},
				th: threshold.Threshold{
					Default: threshold.Rates{threshold.Added: 10, threshold.Removed: 10},
				},
			},
			want: detection.FileDiff{
				Name: "ubuntu_22.04",
				Sources: []detection.SourceDiff{
					{
						SourceID:    "ubuntu-oval",
						BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"},
						TargetIDs:   []string{"CVE-2026-0001"},
						Removed:     []string{"CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"},
						Rates:       threshold.Rates{threshold.Added: 0, threshold.Removed: 75},
						Thresholds:  threshold.Rates{threshold.Added: 10, threshold.Removed: 10},
						Pass:        false,
					},
				},
				Pass: false,
			},
		},
		{
			// The point of the split: a generous added threshold lets a
			// backfill through while the strict removed threshold still
			// catches a single lost CVE.
			name: "additions tolerated while removals stay strict",
			args: args{
				name: "debian_13",
				ids: detection.CVEIDs{
					Baseline: map[sourceTypes.SourceID][]string{"debian-security-tracker-api": {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"}},
					Target:   map[sourceTypes.SourceID][]string{"debian-security-tracker-api": {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0005"}},
				},
				th: threshold.Threshold{
					Default: threshold.Rates{threshold.Added: 30, threshold.Removed: 0},
				},
			},
			want: detection.FileDiff{
				Name: "debian_13",
				Sources: []detection.SourceDiff{
					{
						SourceID:    "debian-security-tracker-api",
						BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"},
						TargetIDs:   []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0005"},
						Added:       []string{"CVE-2026-0005"},
						Removed:     []string{"CVE-2026-0004"},
						Rates:       threshold.Rates{threshold.Added: 25, threshold.Removed: 25},
						Thresholds:  threshold.Rates{threshold.Added: 30, threshold.Removed: 0},
						Pass:        false,
					},
				},
				Pass: false,
			},
		},
		{
			// A small source must not hide behind a big one: cisco-json
			// loses both of its IDs, which no other source of the file
			// reports, while NVD is unchanged. Against the file's union
			// (6 → 4) that is 33%; the per-source diff reports cisco-json
			// at 100% and fails loudly.
			name: "small source loss not masked by large source",
			args: args{
				name: "cpe_cisco",
				ids: detection.CVEIDs{
					Baseline: map[sourceTypes.SourceID][]string{
						"nvd-feed-cve-v2": {"CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005", "CVE-2026-0006"},
						"cisco-json":      {"CVE-2026-0001", "CVE-2026-0002"},
					},
					Target: map[sourceTypes.SourceID][]string{
						"nvd-feed-cve-v2": {"CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005", "CVE-2026-0006"},
					},
				},
				th: threshold.Threshold{
					Default: threshold.Rates{threshold.Added: 10, threshold.Removed: 10},
				},
			},
			want: detection.FileDiff{
				Name: "cpe_cisco",
				Sources: []detection.SourceDiff{
					{
						SourceID:    "cisco-json",
						BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002"},
						Removed:     []string{"CVE-2026-0001", "CVE-2026-0002"},
						Rates:       threshold.Rates{threshold.Added: 0, threshold.Removed: 100},
						Thresholds:  threshold.Rates{threshold.Added: 10, threshold.Removed: 10},
						Pass:        false,
					},
					{
						SourceID:    "nvd-feed-cve-v2",
						BaselineIDs: []string{"CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005", "CVE-2026-0006"},
						TargetIDs:   []string{"CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005", "CVE-2026-0006"},
						Rates:       threshold.Rates{threshold.Added: 0, threshold.Removed: 0},
						Thresholds:  threshold.Rates{threshold.Added: 10, threshold.Removed: 10},
						Pass:        true,
					},
				},
				Pass: false,
			},
		},
		{
			// A per-source, per-axis override lifts exactly that source's
			// axis while everything else stays on the default.
			name: "per-source threshold lifts only its source",
			args: args{
				name: "cpe_jvn",
				ids: detection.CVEIDs{
					Baseline: map[sourceTypes.SourceID][]string{
						"jvn-feed-rss":    {"CVE-2026-0001", "CVE-2026-0002"},
						"nvd-feed-cve-v2": {"CVE-2026-0001", "CVE-2026-0004"},
					},
					Target: map[sourceTypes.SourceID][]string{
						"jvn-feed-rss":    {"CVE-2026-0001", "CVE-2026-0003"},
						"nvd-feed-cve-v2": {"CVE-2026-0001", "CVE-2026-0004"},
					},
				},
				th: threshold.Threshold{
					Default: threshold.Rates{threshold.Added: 10, threshold.Removed: 10},
					Overrides: map[string]threshold.Rates{
						"cpe_jvn/jvn-feed-rss": {threshold.Added: 150, threshold.Removed: 50},
					},
				},
			},
			want: detection.FileDiff{
				Name: "cpe_jvn",
				Sources: []detection.SourceDiff{
					{
						SourceID:    "jvn-feed-rss",
						BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002"},
						TargetIDs:   []string{"CVE-2026-0001", "CVE-2026-0003"},
						Added:       []string{"CVE-2026-0003"},
						Removed:     []string{"CVE-2026-0002"},
						Rates:       threshold.Rates{threshold.Added: 50, threshold.Removed: 50},
						Thresholds:  threshold.Rates{threshold.Added: 150, threshold.Removed: 50},
						Pass:        true,
					},
					{
						SourceID:    "nvd-feed-cve-v2",
						BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0004"},
						TargetIDs:   []string{"CVE-2026-0001", "CVE-2026-0004"},
						Rates:       threshold.Rates{threshold.Added: 0, threshold.Removed: 0},
						Thresholds:  threshold.Rates{threshold.Added: 10, threshold.Removed: 10},
						Pass:        true,
					},
				},
				Pass: true,
			},
		},
		{
			// With an empty baseline, additions are reported as 100%.
			name: "source only in target triggers 100% added",
			args: args{
				name: "redhat_9",
				ids: detection.CVEIDs{
					Baseline: map[sourceTypes.SourceID][]string{},
					Target:   map[sourceTypes.SourceID][]string{"redhat-csaf": {"CVE-2026-0001", "CVE-2026-0002"}},
				},
				th: threshold.Threshold{
					Default: threshold.Rates{threshold.Added: 10, threshold.Removed: 10},
				},
			},
			want: detection.FileDiff{
				Name: "redhat_9",
				Sources: []detection.SourceDiff{
					{
						SourceID:   "redhat-csaf",
						TargetIDs:  []string{"CVE-2026-0001", "CVE-2026-0002"},
						Added:      []string{"CVE-2026-0001", "CVE-2026-0002"},
						Rates:      threshold.Rates{threshold.Added: 100, threshold.Removed: 0},
						Thresholds: threshold.Rates{threshold.Added: 10, threshold.Removed: 10},
						Pass:       false,
					},
				},
				Pass: false,
			},
		},
		{
			name: "both empty pass with no sources",
			args: args{
				name: "redhat_9",
				ids:  detection.CVEIDs{},
				th: threshold.Threshold{
					Default: threshold.Rates{threshold.Added: 10, threshold.Removed: 10},
				},
			},
			want: detection.FileDiff{
				Name:    "redhat_9",
				Sources: []detection.SourceDiff{},
				Pass:    true,
			},
		},
		{
			// A file-wide override on the added axis lifts a moderate
			// backfill above its rate.
			name: "high threshold lets a moderate rate pass",
			args: args{
				name: "debian_13",
				ids: detection.CVEIDs{
					Baseline: map[sourceTypes.SourceID][]string{"debian-security-tracker-api": {"CVE-2026-0001", "CVE-2026-0002"}},
					Target:   map[sourceTypes.SourceID][]string{"debian-security-tracker-api": {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"}},
				},
				th: threshold.Threshold{
					Default:   threshold.Rates{threshold.Added: 10, threshold.Removed: 10},
					Overrides: map[string]threshold.Rates{"debian_13": {threshold.Added: 80}},
				},
			},
			want: detection.FileDiff{
				Name: "debian_13",
				Sources: []detection.SourceDiff{
					{
						SourceID:    "debian-security-tracker-api",
						BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002"},
						TargetIDs:   []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"},
						Added:       []string{"CVE-2026-0003"},
						Rates:       threshold.Rates{threshold.Added: 50, threshold.Removed: 0},
						Thresholds:  threshold.Rates{threshold.Added: 80, threshold.Removed: 10},
						Pass:        true,
					},
				},
				Pass: true,
			},
		},
		{
			// The suppression pattern: NVD starts covering a product, so
			// vuls0 attributes two CVEs to NVD instead of VulnCheck. The
			// CVEs are still detected; on the VulnCheck row they are moves,
			// not removals, and the removed rate stays at 0.
			name: "move between sources is not a removal",
			args: args{
				name: "cpe_nvd",
				ids: detection.CVEIDs{
					Baseline: map[sourceTypes.SourceID][]string{
						"vulncheck-nist-nvd2": {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"},
						"nvd-feed-cve-v2": {"CVE-2026-0004", "CVE-2026-0005", "CVE-2026-0006", "CVE-2026-0007", "CVE-2026-0008",
							"CVE-2026-0009", "CVE-2026-0010", "CVE-2026-0011", "CVE-2026-0012", "CVE-2026-0013"},
					},
					Target: map[sourceTypes.SourceID][]string{
						"vulncheck-nist-nvd2": {"CVE-2026-0003"},
						"nvd-feed-cve-v2": {"CVE-2026-0004", "CVE-2026-0005", "CVE-2026-0006", "CVE-2026-0007", "CVE-2026-0008",
							"CVE-2026-0009", "CVE-2026-0010", "CVE-2026-0011", "CVE-2026-0012", "CVE-2026-0013", "CVE-2026-0001", "CVE-2026-0002"},
					},
				},
				th: threshold.Threshold{
					Default: threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
				},
			},
			want: detection.FileDiff{
				Name: "cpe_nvd",
				Sources: []detection.SourceDiff{
					{
						SourceID:    "vulncheck-nist-nvd2",
						BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"},
						TargetIDs:   []string{"CVE-2026-0003"},
						Moved: []detection.Move{
							{
								ID: "CVE-2026-0001",
								To: []sourceTypes.SourceID{"nvd-feed-cve-v2"},
							},
							{
								ID: "CVE-2026-0002",
								To: []sourceTypes.SourceID{"nvd-feed-cve-v2"},
							},
						},
						Rates:      threshold.Rates{threshold.Added: 0, threshold.Removed: 0},
						Thresholds: threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
						Pass:       true,
					},
					{
						SourceID: "nvd-feed-cve-v2",
						BaselineIDs: []string{"CVE-2026-0004", "CVE-2026-0005", "CVE-2026-0006", "CVE-2026-0007", "CVE-2026-0008",
							"CVE-2026-0009", "CVE-2026-0010", "CVE-2026-0011", "CVE-2026-0012", "CVE-2026-0013"},
						TargetIDs: []string{"CVE-2026-0004", "CVE-2026-0005", "CVE-2026-0006", "CVE-2026-0007", "CVE-2026-0008",
							"CVE-2026-0009", "CVE-2026-0010", "CVE-2026-0011", "CVE-2026-0012", "CVE-2026-0013", "CVE-2026-0001", "CVE-2026-0002"},
						Added:      []string{"CVE-2026-0001", "CVE-2026-0002"},
						Rates:      threshold.Rates{threshold.Added: 20, threshold.Removed: 0},
						Thresholds: threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
						Pass:       true,
					},
				},
				Pass: true,
			},
		},
		{
			// Of three lost IDs one moved to NVD and two vanished from the
			// file; only the two count, and 2/4 still trips the row.
			name: "loss and move on one source are judged apart",
			args: args{
				name: "cpe_nvd",
				ids: detection.CVEIDs{
					Baseline: map[sourceTypes.SourceID][]string{
						"vulncheck-nist-nvd2": {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"},
						"nvd-feed-cve-v2":     {"CVE-2026-0005", "CVE-2026-0006", "CVE-2026-0007", "CVE-2026-0008"},
					},
					Target: map[sourceTypes.SourceID][]string{
						"vulncheck-nist-nvd2": {"CVE-2026-0004"},
						"nvd-feed-cve-v2":     {"CVE-2026-0005", "CVE-2026-0006", "CVE-2026-0007", "CVE-2026-0008", "CVE-2026-0001"},
					},
				},
				th: threshold.Threshold{
					Default: threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
				},
			},
			want: detection.FileDiff{
				Name: "cpe_nvd",
				Sources: []detection.SourceDiff{
					{
						SourceID:    "vulncheck-nist-nvd2",
						BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"},
						TargetIDs:   []string{"CVE-2026-0004"},
						Removed:     []string{"CVE-2026-0002", "CVE-2026-0003"},
						Moved: []detection.Move{
							{
								ID: "CVE-2026-0001",
								To: []sourceTypes.SourceID{"nvd-feed-cve-v2"},
							},
						},
						Rates:      threshold.Rates{threshold.Added: 0, threshold.Removed: 50},
						Thresholds: threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
						Pass:       false,
					},
					{
						SourceID:    "nvd-feed-cve-v2",
						BaselineIDs: []string{"CVE-2026-0005", "CVE-2026-0006", "CVE-2026-0007", "CVE-2026-0008"},
						TargetIDs:   []string{"CVE-2026-0005", "CVE-2026-0006", "CVE-2026-0007", "CVE-2026-0008", "CVE-2026-0001"},
						Added:       []string{"CVE-2026-0001"},
						Rates:       threshold.Rates{threshold.Added: 25, threshold.Removed: 0},
						Thresholds:  threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
						Pass:        true,
					},
				},
				Pass: false,
			},
		},
		{
			// Two secondary sources lose the same ID to NVD at once; each
			// records the move on its own row, and neither is in the target.
			name: "same ID moves from two sources to one",
			args: args{
				name: "cpe_nvd",
				ids: detection.CVEIDs{
					Baseline: map[sourceTypes.SourceID][]string{
						"vulncheck-nist-nvd2": {"CVE-2026-0001"},
						"jvn-feed-rss":        {"CVE-2026-0001"},
						"nvd-feed-cve-v2":     {"CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005"},
					},
					Target: map[sourceTypes.SourceID][]string{
						"nvd-feed-cve-v2": {"CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005", "CVE-2026-0001"},
					},
				},
				th: threshold.Threshold{
					Default: threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
				},
			},
			want: detection.FileDiff{
				Name: "cpe_nvd",
				Sources: []detection.SourceDiff{
					{
						SourceID:    "jvn-feed-rss",
						BaselineIDs: []string{"CVE-2026-0001"},
						Moved: []detection.Move{
							{
								ID: "CVE-2026-0001",
								To: []sourceTypes.SourceID{"nvd-feed-cve-v2"},
							},
						},
						Rates:      threshold.Rates{threshold.Added: 0, threshold.Removed: 0},
						Thresholds: threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
						Pass:       true,
					},
					{
						SourceID:    "nvd-feed-cve-v2",
						BaselineIDs: []string{"CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005"},
						TargetIDs:   []string{"CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005", "CVE-2026-0001"},
						Added:       []string{"CVE-2026-0001"},
						Rates:       threshold.Rates{threshold.Added: 25, threshold.Removed: 0},
						Thresholds:  threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
						Pass:        true,
					},
					{
						SourceID:    "vulncheck-nist-nvd2",
						BaselineIDs: []string{"CVE-2026-0001"},
						Moved: []detection.Move{
							{
								ID: "CVE-2026-0001",
								To: []sourceTypes.SourceID{"nvd-feed-cve-v2"},
							},
						},
						Rates:      threshold.Rates{threshold.Added: 0, threshold.Removed: 0},
						Thresholds: threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
						Pass:       true,
					},
				},
				Pass: true,
			},
		},
		{
			// An ID picked up by two sources lists both destinations,
			// sorted, regardless of map iteration order.
			name: "move to several sources lists them sorted",
			args: args{
				name: "cpe_nvd",
				ids: detection.CVEIDs{
					Baseline: map[sourceTypes.SourceID][]string{
						"vulncheck-nist-nvd2": {"CVE-2026-0001"},
						"nvd-feed-cve-v2":     {"CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005"},
						"jvn-feed-rss":        {"CVE-2026-0006", "CVE-2026-0007", "CVE-2026-0008", "CVE-2026-0009"},
					},
					Target: map[sourceTypes.SourceID][]string{
						"nvd-feed-cve-v2": {"CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005", "CVE-2026-0001"},
						"jvn-feed-rss":    {"CVE-2026-0006", "CVE-2026-0007", "CVE-2026-0008", "CVE-2026-0009", "CVE-2026-0001"},
					},
				},
				th: threshold.Threshold{
					Default: threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
				},
			},
			want: detection.FileDiff{
				Name: "cpe_nvd",
				Sources: []detection.SourceDiff{
					{
						SourceID:    "jvn-feed-rss",
						BaselineIDs: []string{"CVE-2026-0006", "CVE-2026-0007", "CVE-2026-0008", "CVE-2026-0009"},
						TargetIDs:   []string{"CVE-2026-0006", "CVE-2026-0007", "CVE-2026-0008", "CVE-2026-0009", "CVE-2026-0001"},
						Added:       []string{"CVE-2026-0001"},
						Rates:       threshold.Rates{threshold.Added: 25, threshold.Removed: 0},
						Thresholds:  threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
						Pass:        true,
					},
					{
						SourceID:    "nvd-feed-cve-v2",
						BaselineIDs: []string{"CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005"},
						TargetIDs:   []string{"CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005", "CVE-2026-0001"},
						Added:       []string{"CVE-2026-0001"},
						Rates:       threshold.Rates{threshold.Added: 25, threshold.Removed: 0},
						Thresholds:  threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
						Pass:        true,
					},
					{
						SourceID:    "vulncheck-nist-nvd2",
						BaselineIDs: []string{"CVE-2026-0001"},
						Moved: []detection.Move{
							{
								ID: "CVE-2026-0001",
								To: []sourceTypes.SourceID{"jvn-feed-rss", "nvd-feed-cve-v2"},
							},
						},
						Rates:      threshold.Rates{threshold.Added: 0, threshold.Removed: 0},
						Thresholds: threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
						Pass:       true,
					},
				},
				Pass: true,
			},
		},
		{
			// The reverse direction (NVD drops a product, VulnCheck is no
			// longer suppressed) rides the same rule: a move on the NVD row,
			// a plain addition on the VulnCheck row.
			name: "move back from NVD is a move on the NVD row",
			args: args{
				name: "cpe_nvd",
				ids: detection.CVEIDs{
					Baseline: map[sourceTypes.SourceID][]string{
						"nvd-feed-cve-v2":     {"CVE-2026-0001"},
						"vulncheck-nist-nvd2": {"CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005"},
					},
					Target: map[sourceTypes.SourceID][]string{
						"vulncheck-nist-nvd2": {"CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005", "CVE-2026-0001"},
					},
				},
				th: threshold.Threshold{
					Default: threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
				},
			},
			want: detection.FileDiff{
				Name: "cpe_nvd",
				Sources: []detection.SourceDiff{
					{
						SourceID:    "nvd-feed-cve-v2",
						BaselineIDs: []string{"CVE-2026-0001"},
						Moved: []detection.Move{
							{
								ID: "CVE-2026-0001",
								To: []sourceTypes.SourceID{"vulncheck-nist-nvd2"},
							},
						},
						Rates:      threshold.Rates{threshold.Added: 0, threshold.Removed: 0},
						Thresholds: threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
						Pass:       true,
					},
					{
						SourceID:    "vulncheck-nist-nvd2",
						BaselineIDs: []string{"CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005"},
						TargetIDs:   []string{"CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005", "CVE-2026-0001"},
						Added:       []string{"CVE-2026-0001"},
						Rates:       threshold.Rates{threshold.Added: 25, threshold.Removed: 0},
						Thresholds:  threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
						Pass:        true,
					},
				},
				Pass: true,
			},
		},
		{
			// A source that vanishes from the target entirely still has its
			// lost IDs split: the one NVD picked up is a move, the other is
			// a removal, and 1/2 trips the row.
			name: "source absent from target still splits moves from removals",
			args: args{
				name: "cpe_nvd",
				ids: detection.CVEIDs{
					Baseline: map[sourceTypes.SourceID][]string{
						"vulncheck-nist-nvd2": {"CVE-2026-0001", "CVE-2026-0002"},
						"nvd-feed-cve-v2":     {"CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005", "CVE-2026-0006"},
					},
					Target: map[sourceTypes.SourceID][]string{
						"nvd-feed-cve-v2": {"CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005", "CVE-2026-0006", "CVE-2026-0001"},
					},
				},
				th: threshold.Threshold{
					Default: threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
				},
			},
			want: detection.FileDiff{
				Name: "cpe_nvd",
				Sources: []detection.SourceDiff{
					{
						SourceID:    "nvd-feed-cve-v2",
						BaselineIDs: []string{"CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005", "CVE-2026-0006"},
						TargetIDs:   []string{"CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005", "CVE-2026-0006", "CVE-2026-0001"},
						Added:       []string{"CVE-2026-0001"},
						Rates:       threshold.Rates{threshold.Added: 25, threshold.Removed: 0},
						Thresholds:  threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
						Pass:        true,
					},
					{
						SourceID:    "vulncheck-nist-nvd2",
						BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002"},
						Removed:     []string{"CVE-2026-0002"},
						Moved: []detection.Move{
							{
								ID: "CVE-2026-0001",
								To: []sourceTypes.SourceID{"nvd-feed-cve-v2"},
							},
						},
						Rates:      threshold.Rates{threshold.Added: 0, threshold.Removed: 50},
						Thresholds: threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
						Pass:       false,
					},
				},
				Pass: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detection.DiffDetection(tt.args.name, tt.args.ids, tt.args.th)
			// Sources carries no order guarantee (the report sorts for
			// presentation), so compare it order-insensitively.
			if diff := cmp.Diff(tt.want, got, cmpopts.SortSlices(func(a, b detection.SourceDiff) bool { return a.SourceID < b.SourceID })); diff != "" {
				t.Errorf("DiffDetection() mismatch (-want +got):\n%s", diff)
			}

			// Invariants of the lost-ID split, independent of the expected
			// values: per source, lost = Removed ⊎ Moved and every move
			// names at least one other source, sorted; over the file, the
			// union of every source's Removed is exactly what the file as a
			// whole lost.
			var targetUnion []string
			for _, list := range tt.args.ids.Target {
				targetUnion = append(targetUnion, list...)
			}
			var baselineUnion []string
			for _, list := range tt.args.ids.Baseline {
				baselineUnion = append(baselineUnion, list...)
			}
			fileLost := detection.Subtract(baselineUnion, targetUnion)
			slices.Sort(fileLost)
			fileLost = slices.Compact(fileLost)

			var removedUnion []string
			for _, sd := range got.Sources {
				lost := detection.Subtract(sd.BaselineIDs, sd.TargetIDs)
				if len(lost) != len(sd.Removed)+len(sd.Moved) {
					t.Errorf("%s: lost %d != removed %d + moved %d", sd.SourceID, len(lost), len(sd.Removed), len(sd.Moved))
				}
				for _, id := range sd.Removed {
					if slices.Contains(targetUnion, id) {
						t.Errorf("%s: removed %s is still reported by a source of the file", sd.SourceID, id)
					}
				}
				for _, m := range sd.Moved {
					if len(m.To) == 0 {
						t.Errorf("%s: move %s has no destination", sd.SourceID, m.ID)
					}
					if !slices.IsSorted(m.To) {
						t.Errorf("%s: move %s destinations not sorted: %v", sd.SourceID, m.ID, m.To)
					}
					if slices.Contains(m.To, sd.SourceID) {
						t.Errorf("%s: move %s lists the losing source as a destination", sd.SourceID, m.ID)
					}
					for _, to := range m.To {
						if !slices.Contains(tt.args.ids.Target[to], m.ID) {
							t.Errorf("%s: move %s names %s, which does not report it in the target", sd.SourceID, m.ID, to)
						}
					}
				}
				removedUnion = append(removedUnion, sd.Removed...)
			}
			slices.Sort(removedUnion)
			removedUnion = slices.Compact(removedUnion)
			if diff := cmp.Diff(fileLost, removedUnion, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("union of Removed != IDs lost by the file (-file +sources):\n%s", diff)
			}
		})
	}
}

func TestGenerateReport(t *testing.T) {
	type args struct {
		diffs map[string]detection.FileDiff
	}
	tests := []struct {
		name       string
		args       args
		wantPass   bool
		wantReport string
	}{
		{
			// A FAIL row marks the tripped axis in bold and its Details
			// headline names it with rate and threshold.
			name: "fail with details",
			args: args{
				diffs: map[string]detection.FileDiff{
					"redhat_9": {
						Name: "redhat_9",
						Sources: []detection.SourceDiff{
							{
								SourceID:    "redhat-csaf",
								BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002"},
								TargetIDs:   []string{"CVE-2026-0001", "CVE-2026-0002"},
								Rates:       threshold.Rates{threshold.Added: 0, threshold.Removed: 0},
								Thresholds:  threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
								Pass:        true,
							},
						},
						Pass: true,
					},
					"ubuntu_22.04": {
						Name: "ubuntu_22.04",
						Sources: []detection.SourceDiff{
							{
								SourceID:    "ubuntu-oval",
								BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"},
								TargetIDs:   []string{"CVE-2026-0001"},
								Removed:     []string{"CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"},
								Rates:       threshold.Rates{threshold.Added: 0, threshold.Removed: 75},
								Thresholds:  threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
								Pass:        false,
							},
						},
						Pass: false,
					},
				},
			},
			wantPass: false,
			wantReport: `# Diff Report: Detection

## Summary

**Result**: **FAIL**

| Name | Source | Baseline | Target | Added | Removed | Moved | Rate (added / removed) | Threshold (added / removed) | Result |
|------|--------|----------|--------|-------|---------|-------|------------------------|-----------------------------|--------|
| ubuntu_22.04 | ubuntu-oval | 4 | 1 | 0 | 3 | 0 | 0.0% / **75.0%** | 30.0% / 5.0% | **FAIL** |
| redhat_9 | redhat-csaf | 2 | 2 | 0 | 0 | 0 | 0.0% / 0.0% | 30.0% / 5.0% | PASS |

## Details (FAIL sources)

### ubuntu_22.04 / ubuntu-oval (removed 75.0% > 5.0%)

#### Removed IDs (3)

- CVE-2026-0002
- CVE-2026-0003
- CVE-2026-0004

`,
		},
		{
			// Within one cpe fixture, a failing small source sorts above the
			// passing large source and is reported as its own row.
			name: "small source failure not masked by large source",
			args: args{
				diffs: map[string]detection.FileDiff{
					"cpe_cisco": {
						Name: "cpe_cisco",
						Sources: []detection.SourceDiff{
							{
								SourceID:    "cisco-json",
								BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002"},
								Removed:     []string{"CVE-2026-0001", "CVE-2026-0002"},
								Rates:       threshold.Rates{threshold.Added: 0, threshold.Removed: 100},
								Thresholds:  threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
								Pass:        false,
							},
							{
								SourceID:    "nvd-feed-cve-v2",
								BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"},
								TargetIDs:   []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"},
								Rates:       threshold.Rates{threshold.Added: 0, threshold.Removed: 0},
								Thresholds:  threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
								Pass:        true,
							},
						},
						Pass: false,
					},
				},
			},
			wantPass: false,
			wantReport: `# Diff Report: Detection

## Summary

**Result**: **FAIL**

| Name | Source | Baseline | Target | Added | Removed | Moved | Rate (added / removed) | Threshold (added / removed) | Result |
|------|--------|----------|--------|-------|---------|-------|------------------------|-----------------------------|--------|
| cpe_cisco | cisco-json | 2 | 0 | 0 | 2 | 0 | 0.0% / **100.0%** | 30.0% / 5.0% | **FAIL** |
| cpe_cisco | nvd-feed-cve-v2 | 4 | 4 | 0 | 0 | 0 | 0.0% / 0.0% | 30.0% / 5.0% | PASS |

## Details (FAIL sources)

### cpe_cisco / cisco-json (removed 100.0% > 5.0%)

#### Removed IDs (2)

- CVE-2026-0001
- CVE-2026-0002

`,
		},
		{
			name: "all pass",
			args: args{
				diffs: map[string]detection.FileDiff{
					"redhat_9": {
						Name: "redhat_9",
						Sources: []detection.SourceDiff{
							{
								SourceID:    "redhat-csaf",
								BaselineIDs: []string{"CVE-2026-0001"},
								TargetIDs:   []string{"CVE-2026-0001"},
								Rates:       threshold.Rates{threshold.Added: 0, threshold.Removed: 0},
								Thresholds:  threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
								Pass:        true,
							},
						},
						Pass: true,
					},
				},
			},
			wantPass: true,
			wantReport: `# Diff Report: Detection

## Summary

**Result**: PASS

| Name | Source | Baseline | Target | Added | Removed | Moved | Rate (added / removed) | Threshold (added / removed) | Result |
|------|--------|----------|--------|-------|---------|-------|------------------------|-----------------------------|--------|
| redhat_9 | redhat-csaf | 1 | 1 | 0 | 0 | 0 | 0.0% / 0.0% | 30.0% / 5.0% | PASS |

`,
		},
		{
			// The Threshold column shows the resolved per-axis values, so
			// an override on one axis is visible on its row.
			name: "override applied",
			args: args{
				diffs: map[string]detection.FileDiff{
					"debian_13": {
						Name: "debian_13",
						Sources: []detection.SourceDiff{
							{
								SourceID:    "debian-security-tracker-api",
								BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002"},
								TargetIDs:   []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"},
								Added:       []string{"CVE-2026-0003"},
								Rates:       threshold.Rates{threshold.Added: 50, threshold.Removed: 0},
								Thresholds:  threshold.Rates{threshold.Added: 80, threshold.Removed: 5},
								Pass:        true,
							},
						},
						Pass: true,
					},
					"redhat_9": {
						Name: "redhat_9",
						Sources: []detection.SourceDiff{
							{
								SourceID:    "redhat-csaf",
								BaselineIDs: []string{"CVE-2026-0001"},
								TargetIDs:   []string{"CVE-2026-0001"},
								Rates:       threshold.Rates{threshold.Added: 0, threshold.Removed: 0},
								Thresholds:  threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
								Pass:        true,
							},
						},
						Pass: true,
					},
				},
			},
			wantPass: true,
			wantReport: `# Diff Report: Detection

## Summary

**Result**: PASS

| Name | Source | Baseline | Target | Added | Removed | Moved | Rate (added / removed) | Threshold (added / removed) | Result |
|------|--------|----------|--------|-------|---------|-------|------------------------|-----------------------------|--------|
| debian_13 | debian-security-tracker-api | 2 | 3 | 1 | 0 | 0 | 50.0% / 0.0% | 80.0% / 5.0% | PASS |
| redhat_9 | redhat-csaf | 1 | 1 | 0 | 0 | 0 | 0.0% / 0.0% | 30.0% / 5.0% | PASS |

`,
		},
		{
			// Locks the FAIL-first sort tier: a PASS row with a higher change
			// rate (held passing by an override) must sort below a FAIL row
			// whose rate is lower. Pure rate-desc sort would put alpha first.
			// Both axes of the FAIL row trip, so both are bold and both are
			// named in the headline.
			name: "FAIL row sorts above higher-rate PASS row",
			args: args{
				diffs: map[string]detection.FileDiff{
					"alpha": {
						Name: "alpha",
						Sources: []detection.SourceDiff{
							{
								SourceID:    "alma-errata",
								BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002"},
								TargetIDs:   []string{"CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005"},
								Added:       []string{"CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005"},
								Removed:     []string{"CVE-2026-0001", "CVE-2026-0002"},
								Rates:       threshold.Rates{threshold.Added: 150, threshold.Removed: 100},
								Thresholds:  threshold.Rates{threshold.Added: 300, threshold.Removed: 300},
								Pass:        true,
							},
						},
						Pass: true,
					},
					"beta": {
						Name: "beta",
						Sources: []detection.SourceDiff{
							{
								SourceID:    "alma-errata",
								BaselineIDs: []string{"CVE-2026-1001", "CVE-2026-1002"},
								TargetIDs:   []string{"CVE-2026-1001", "CVE-2026-1003"},
								Added:       []string{"CVE-2026-1003"},
								Removed:     []string{"CVE-2026-1002"},
								Rates:       threshold.Rates{threshold.Added: 50, threshold.Removed: 50},
								Thresholds:  threshold.Rates{threshold.Added: 0, threshold.Removed: 0},
								Pass:        false,
							},
						},
						Pass: false,
					},
				},
			},
			wantPass: false,
			wantReport: `# Diff Report: Detection

## Summary

**Result**: **FAIL**

| Name | Source | Baseline | Target | Added | Removed | Moved | Rate (added / removed) | Threshold (added / removed) | Result |
|------|--------|----------|--------|-------|---------|-------|------------------------|-----------------------------|--------|
| beta | alma-errata | 2 | 2 | 1 | 1 | 0 | **50.0%** / **50.0%** | 0.0% / 0.0% | **FAIL** |
| alpha | alma-errata | 2 | 3 | 3 | 2 | 0 | 150.0% / 100.0% | 300.0% / 300.0% | PASS |

## Details (FAIL sources)

### beta / alma-errata (added 50.0% > 0.0%, removed 50.0% > 0.0%)

#### Added IDs (1)

- CVE-2026-1003

#### Removed IDs (1)

- CVE-2026-1002

`,
		},
		{
			// Moved is counted on every row but listed only under a FAIL
			// row, where the IDs are sorted and each names its target
			// sources. Moved never enters the sort: cisco-json has the most
			// moves yet sorts last on its 0% rates.
			name: "moved counted on every row and listed only for FAIL rows",
			args: args{
				diffs: map[string]detection.FileDiff{
					"cpe_nvd": {
						Name: "cpe_nvd",
						Sources: []detection.SourceDiff{
							{
								SourceID:    "vulncheck-nist-nvd2",
								BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005"},
								TargetIDs:   []string{"CVE-2026-0004"},
								Removed:     []string{"CVE-2026-0003", "CVE-2026-0002"},
								Moved: []detection.Move{
									{
										ID: "CVE-2026-0005",
										To: []sourceTypes.SourceID{"jvn-feed-rss", "nvd-feed-cve-v2"},
									},
									{
										ID: "CVE-2026-0001",
										To: []sourceTypes.SourceID{"nvd-feed-cve-v2"},
									},
								},
								Rates:      threshold.Rates{threshold.Added: 0, threshold.Removed: 40},
								Thresholds: threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
								Pass:       false,
							},
							{
								SourceID:    "jvn-feed-rss",
								BaselineIDs: []string{"CVE-2026-0006", "CVE-2026-0007", "CVE-2026-0008", "CVE-2026-0009", "CVE-2026-0010"},
								TargetIDs:   []string{"CVE-2026-0006", "CVE-2026-0007", "CVE-2026-0008", "CVE-2026-0009", "CVE-2026-0005"},
								Added:       []string{"CVE-2026-0005"},
								Moved: []detection.Move{
									{
										ID: "CVE-2026-0010",
										To: []sourceTypes.SourceID{"nvd-feed-cve-v2"},
									},
								},
								Rates:      threshold.Rates{threshold.Added: 20, threshold.Removed: 0},
								Thresholds: threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
								Pass:       true,
							},
							{
								SourceID:    "cisco-json",
								BaselineIDs: []string{"CVE-2026-0021", "CVE-2026-0022", "CVE-2026-0023"},
								Moved: []detection.Move{
									{
										ID: "CVE-2026-0021",
										To: []sourceTypes.SourceID{"nvd-feed-cve-v2"},
									},
									{
										ID: "CVE-2026-0022",
										To: []sourceTypes.SourceID{"nvd-feed-cve-v2"},
									},
									{
										ID: "CVE-2026-0023",
										To: []sourceTypes.SourceID{"nvd-feed-cve-v2"},
									},
								},
								Rates:      threshold.Rates{threshold.Added: 0, threshold.Removed: 0},
								Thresholds: threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
								Pass:       true,
							},
							{
								SourceID: "nvd-feed-cve-v2",
								BaselineIDs: []string{"CVE-2026-0101", "CVE-2026-0102", "CVE-2026-0103", "CVE-2026-0104", "CVE-2026-0105",
									"CVE-2026-0106", "CVE-2026-0107", "CVE-2026-0108", "CVE-2026-0109", "CVE-2026-0110",
									"CVE-2026-0111", "CVE-2026-0112", "CVE-2026-0113", "CVE-2026-0114", "CVE-2026-0115",
									"CVE-2026-0116", "CVE-2026-0117", "CVE-2026-0118", "CVE-2026-0119", "CVE-2026-0120"},
								TargetIDs: []string{"CVE-2026-0101", "CVE-2026-0102", "CVE-2026-0103", "CVE-2026-0104", "CVE-2026-0105",
									"CVE-2026-0106", "CVE-2026-0107", "CVE-2026-0108", "CVE-2026-0109", "CVE-2026-0110",
									"CVE-2026-0111", "CVE-2026-0112", "CVE-2026-0113", "CVE-2026-0114", "CVE-2026-0115",
									"CVE-2026-0116", "CVE-2026-0117", "CVE-2026-0118", "CVE-2026-0119", "CVE-2026-0120",
									"CVE-2026-0001", "CVE-2026-0005", "CVE-2026-0010", "CVE-2026-0021", "CVE-2026-0022", "CVE-2026-0023"},
								Added:      []string{"CVE-2026-0001", "CVE-2026-0005", "CVE-2026-0010", "CVE-2026-0021", "CVE-2026-0022", "CVE-2026-0023"},
								Rates:      threshold.Rates{threshold.Added: 30, threshold.Removed: 0},
								Thresholds: threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
								Pass:       true,
							},
						},
						Pass: false,
					},
				},
			},
			wantPass: false,
			wantReport: `# Diff Report: Detection

## Summary

**Result**: **FAIL**

| Name | Source | Baseline | Target | Added | Removed | Moved | Rate (added / removed) | Threshold (added / removed) | Result |
|------|--------|----------|--------|-------|---------|-------|------------------------|-----------------------------|--------|
| cpe_nvd | vulncheck-nist-nvd2 | 5 | 1 | 0 | 2 | 2 | 0.0% / **40.0%** | 30.0% / 5.0% | **FAIL** |
| cpe_nvd | nvd-feed-cve-v2 | 20 | 26 | 6 | 0 | 0 | 30.0% / 0.0% | 30.0% / 5.0% | PASS |
| cpe_nvd | jvn-feed-rss | 5 | 5 | 1 | 0 | 1 | 20.0% / 0.0% | 30.0% / 5.0% | PASS |
| cpe_nvd | cisco-json | 3 | 0 | 0 | 0 | 3 | 0.0% / 0.0% | 30.0% / 5.0% | PASS |

## Details (FAIL sources)

### cpe_nvd / vulncheck-nist-nvd2 (removed 40.0% > 5.0%)

#### Removed IDs (2)

- CVE-2026-0002
- CVE-2026-0003

#### Moved IDs (2)

- CVE-2026-0001 → nvd-feed-cve-v2
- CVE-2026-0005 → jvn-feed-rss, nvd-feed-cve-v2

`,
		},
		{
			// A file compared with zero detections on both sides must still be
			// visible in the report instead of silently disappearing.
			name: "file without sources renders a placeholder row",
			args: args{
				diffs: map[string]detection.FileDiff{
					"empty_file": {
						Name: "empty_file",
						Pass: true,
					},
				},
			},
			wantPass: true,
			wantReport: `# Diff Report: Detection

## Summary

**Result**: PASS

| Name | Source | Baseline | Target | Added | Removed | Moved | Rate (added / removed) | Threshold (added / removed) | Result |
|------|--------|----------|--------|-------|---------|-------|------------------------|-----------------------------|--------|
| empty_file | (none) | 0 | 0 | 0 | 0 | 0 | 0.0% / 0.0% | - | PASS |

`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			gotPass, err := detection.GenerateReport(&buf, tt.args.diffs)
			if err != nil {
				t.Fatalf("GenerateReport() error = %v", err)
			}
			if gotPass != tt.wantPass {
				t.Errorf("GenerateReport() pass = %v, want %v", gotPass, tt.wantPass)
			}
			got := buf.String()
			if diff := cmp.Diff(tt.wantReport, got); diff != "" {
				t.Errorf("GenerateReport() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDiff(t *testing.T) {
	// Prepare a scan results directory with two dummy JSON files.
	scanDir := t.TempDir()
	for _, name := range []string{"redhat_9.json", "ubuntu_2204.json"} {
		if err := os.WriteFile(filepath.Join(scanDir, name), []byte(`{}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// ubuntu_2204 loses two of three IDs (66.7% removed, 0% added);
	// redhat_9 is unchanged.
	fakeDetect := func(_, _, _, _ string, files map[string]string) (map[string]detection.CVEIDs, error) {
		result := make(map[string]detection.CVEIDs, len(files))
		for name := range files {
			switch name {
			case "redhat_9":
				result[name] = detection.CVEIDs{
					Baseline: map[sourceTypes.SourceID][]string{"redhat-csaf": {"CVE-2026-0001", "CVE-2026-0002"}},
					Target:   map[sourceTypes.SourceID][]string{"redhat-csaf": {"CVE-2026-0001", "CVE-2026-0002"}},
				}
			case "ubuntu_2204":
				result[name] = detection.CVEIDs{
					Baseline: map[sourceTypes.SourceID][]string{"ubuntu-oval": {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"}},
					Target:   map[sourceTypes.SourceID][]string{"ubuntu-oval": {"CVE-2026-0001"}},
				}
			}
		}
		return result, nil
	}

	// Same shape as fakeDetect, but the two IDs ubuntu-oval loses are
	// reported by ubuntu-cve-tracker in the target (2/7 = 28.6% added,
	// under the 30% default): a move, not a loss, so nothing fails.
	fakeDetectMoved := func(_, _, _, _ string, files map[string]string) (map[string]detection.CVEIDs, error) {
		result := make(map[string]detection.CVEIDs, len(files))
		for name := range files {
			switch name {
			case "redhat_9":
				result[name] = detection.CVEIDs{
					Baseline: map[sourceTypes.SourceID][]string{"redhat-csaf": {"CVE-2026-0001", "CVE-2026-0002"}},
					Target:   map[sourceTypes.SourceID][]string{"redhat-csaf": {"CVE-2026-0001", "CVE-2026-0002"}},
				}
			case "ubuntu_2204":
				result[name] = detection.CVEIDs{
					Baseline: map[sourceTypes.SourceID][]string{
						"ubuntu-oval":        {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"},
						"ubuntu-cve-tracker": {"CVE-2026-0004", "CVE-2026-0005", "CVE-2026-0006", "CVE-2026-0007", "CVE-2026-0008", "CVE-2026-0009", "CVE-2026-0010"},
					},
					Target: map[sourceTypes.SourceID][]string{
						"ubuntu-oval": {"CVE-2026-0001"},
						"ubuntu-cve-tracker": {"CVE-2026-0004", "CVE-2026-0005", "CVE-2026-0006", "CVE-2026-0007", "CVE-2026-0008", "CVE-2026-0009", "CVE-2026-0010",
							"CVE-2026-0002", "CVE-2026-0003"},
					},
				}
			}
		}
		return result, nil
	}

	fakeDetectErr := func(_, _, _, _ string, _ map[string]string) (map[string]detection.CVEIDs, error) {
		return nil, errors.New("vuls0 crashed")
	}

	emptyDir := t.TempDir()

	// The 30 / 5 thresholds used below mirror the vuls-data-db defaults:
	// additions tolerated up to 30%, removals up to 5%.
	type args struct {
		dir        string
		detectFunc detection.DetectFunc
		opts       []detection.Option
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "fail on exceeded removed rate",
			args: args{
				dir:        scanDir,
				detectFunc: fakeDetect,
				opts: []detection.Option{detection.WithThreshold(threshold.Threshold{
					Default: threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
				})},
			},
			wantErr: true,
		},
		{
			name: "pass within threshold",
			args: args{
				dir:        scanDir,
				detectFunc: fakeDetect,
				opts: []detection.Option{detection.WithThreshold(threshold.Threshold{
					Default: threshold.Rates{threshold.Added: 100, threshold.Removed: 100},
				})},
			},
			wantErr: false,
		},
		{
			// No threshold option at all judges on Defaults (added 30 /
			// removed 5): ubuntu_2204's 66.7% removal fails.
			name: "no options use Defaults",
			args: args{
				dir:        scanDir,
				detectFunc: fakeDetect,
			},
			wantErr: true,
		},
		{
			// The 66.7% that fails above is judged on IDs the file lost;
			// when another source of the file still reports them they are
			// moves and the removed axis stays at 0 under Defaults.
			name: "lost IDs another source still reports do not trip the removed axis",
			args: args{
				dir:        scanDir,
				detectFunc: fakeDetectMoved,
			},
			wantErr: false,
		},
		{
			// A generous added threshold alone does not excuse removals.
			name: "added threshold does not cover removals",
			args: args{
				dir:        scanDir,
				detectFunc: fakeDetect,
				opts: []detection.Option{detection.WithThreshold(threshold.Threshold{
					Default: threshold.Rates{threshold.Added: 100, threshold.Removed: 5},
				})},
			},
			wantErr: true,
		},
		{
			name: "detect error propagated",
			args: args{
				dir:        scanDir,
				detectFunc: fakeDetectErr,
				opts: []detection.Option{detection.WithThreshold(threshold.Threshold{
					Default: threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
				})},
			},
			wantErr: true,
		},
		{
			name: "no scan results error",
			args: args{
				dir:        emptyDir,
				detectFunc: fakeDetect,
				opts: []detection.Option{detection.WithThreshold(threshold.Threshold{
					Default: threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
				})},
			},
			wantErr: true,
		},
		{
			// Locks override forwarding from Diff into diffDetection. The
			// "ubuntu_2204=removed:70" override lifts every source in that
			// file above its removed rate so the whole Diff returns nil. If
			// Diff stops forwarding the threshold, the override has no effect
			// and ubuntu_2204 fails again.
			name: "file override forwarded through to per-source resolution",
			args: args{
				dir:        scanDir,
				detectFunc: fakeDetect,
				opts: []detection.Option{detection.WithThreshold(threshold.Threshold{
					Default: threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
					Overrides: map[string]threshold.Rates{
						"ubuntu_2204": {threshold.Removed: 70},
					},
				})},
			},
			wantErr: false,
		},
		{
			// The "<file>/<source>" key form resolves for a specific source.
			name: "file/source override forwarded through",
			args: args{
				dir:        scanDir,
				detectFunc: fakeDetect,
				opts: []detection.Option{detection.WithThreshold(threshold.Threshold{
					Default: threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
					Overrides: map[string]threshold.Rates{
						"ubuntu_2204/ubuntu-oval": {threshold.Removed: 70},
					},
				})},
			},
			wantErr: false,
		},
		{
			// An override on the added axis does nothing for a removal.
			name: "override on the other axis does not lift",
			args: args{
				dir:        scanDir,
				detectFunc: fakeDetect,
				opts: []detection.Option{detection.WithThreshold(threshold.Threshold{
					Default: threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
					Overrides: map[string]threshold.Rates{
						"ubuntu_2204": {threshold.Added: 70},
					},
				})},
			},
			wantErr: true,
		},
		{
			// The lenient direction of the same precedence: the file-wide key
			// alone (10) would fail ubuntu_2204 (66.7%), but the file/source
			// key wins and lifts it above its rate.
			name: "file/source override rescues from strict file override",
			args: args{
				dir:        scanDir,
				detectFunc: fakeDetect,
				opts: []detection.Option{detection.WithThreshold(threshold.Threshold{
					Default: threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
					Overrides: map[string]threshold.Rates{
						"ubuntu_2204":             {threshold.Removed: 10},
						"ubuntu_2204/ubuntu-oval": {threshold.Removed: 70},
					},
				})},
			},
			wantErr: false,
		},
		{
			// "<file>/<source>" takes precedence over the file-wide key: the
			// generous file-wide 70 is overridden back down to 10 for the
			// only source present, so the file fails again.
			name: "file/source override beats file override",
			args: args{
				dir:        scanDir,
				detectFunc: fakeDetect,
				opts: []detection.Option{detection.WithThreshold(threshold.Threshold{
					Default: threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
					Overrides: map[string]threshold.Rates{
						"ubuntu_2204":             {threshold.Removed: 70},
						"ubuntu_2204/ubuntu-oval": {threshold.Removed: 10},
					},
				})},
			},
			wantErr: true,
		},
		{
			// An override entry that matches no file must fall through
			// cleanly: every file still resolves to the default threshold.
			name: "unmatched override key does not affect outcome",
			args: args{
				dir:        scanDir,
				detectFunc: fakeDetect,
				opts: []detection.Option{detection.WithThreshold(threshold.Threshold{
					Default:   threshold.Rates{threshold.Added: 100, threshold.Removed: 100}, // both files pass at default
					Overrides: map[string]threshold.Rates{"unknown_99": {threshold.Removed: 1}},
				})},
			},
			wantErr: false,
		},
		{
			// The judged axes are fixed by the command, not by the threshold:
			// a Default that omits the removed axis judges it at 0, so the
			// 66.7% removal still fails instead of going unchecked.
			name: "threshold without the removed axis judges it at 0",
			args: args{
				dir:        scanDir,
				detectFunc: fakeDetect, // 66.7% removed
				opts: []detection.Option{detection.WithThreshold(threshold.Threshold{
					Default: threshold.Rates{threshold.Added: 100},
				})},
			},
			wantErr: true,
		},
		{
			// detection has no changed axis; an override on it is a
			// configuration error, not silently ignored.
			name: "override on the changed axis is an error",
			args: args{
				dir:        scanDir,
				detectFunc: fakeDetect,
				opts: []detection.Option{detection.WithThreshold(threshold.Threshold{
					Default: threshold.Rates{threshold.Added: 30, threshold.Removed: 5},
					Overrides: map[string]threshold.Rates{
						"ubuntu_2204": {threshold.Changed: 70},
					},
				})},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := detection.Diff(
				tt.args.dir, "baseline.db", "vuls0", "target.db", "vuls0",
				append(tt.args.opts,
					detection.WithWriter(&bytes.Buffer{}),
					detection.WithDetectFunc(tt.args.detectFunc),
				)...,
			)

			if (err != nil) != tt.wantErr {
				t.Fatalf("Diff() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
