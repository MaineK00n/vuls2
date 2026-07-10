package detection_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/pkg/errors"

	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"

	"github.com/MaineK00n/vuls2/pkg/diff/detection"
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
			// A merged content carries a multi-element source list; every
			// element counts, deduped against other contents of the same CVE.
			name: "merged multi-source marker",
			args: args{
				scannedCves: map[string]detection.VulnInfo{
					"CVE-2026-0001": {CveContents: map[string][]detection.CveContent{
						"nvd": {
							{Optional: map[string]string{"vuls2-sources": `[{"source_id":"nvd-feed-cve-v2","root_id":"CVE-2026-0001"},{"source_id":"vulncheck-nist-nvd2"}]`}},
						},
						"cisco": {
							{Optional: map[string]string{"vuls2-sources": `[{"source_id":"cisco-json"}]`}},
						},
					}},
				},
			},
			want: map[sourceTypes.SourceID][]string{
				"nvd-feed-cve-v2":     {"CVE-2026-0001"},
				"vulncheck-nist-nvd2": {"CVE-2026-0001"},
				"cisco-json":          {"CVE-2026-0001"},
			},
		},
		{
			// Enrichment-added contents carry no vuls2-sources marker and must
			// not create a bucket — otherwise every CVE would also count under
			// the enrichment sources (NVD, MITRE, ...), recreating the masking
			// this diff exists to remove.
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
			name: "no marked content buckets under unknown",
			args: args{
				scannedCves: map[string]detection.VulnInfo{
					"CVE-2026-0001": {CveContents: map[string][]detection.CveContent{
						"nvd": {{}},
					}},
					"CVE-2026-0002": {},
				},
			},
			want: map[sourceTypes.SourceID][]string{
				"unknown": {"CVE-2026-0001", "CVE-2026-0002"},
			},
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
			// empty list signals a marker format change — fail loudly instead
			// of silently falling back to "unknown".
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
		d         detection.FileDiff
		threshold float64
		overrides map[string]float64
	}
	tests := []struct {
		name string
		args args
		want detection.FileDiff
	}{
		{
			name: "no change",
			args: args{
				d: detection.FileDiff{
					Name:        "redhat_9",
					BaselineIDs: map[sourceTypes.SourceID][]string{"redhat-csaf": {"CVE-2026-0001", "CVE-2026-0002"}},
					TargetIDs:   map[sourceTypes.SourceID][]string{"redhat-csaf": {"CVE-2026-0001", "CVE-2026-0002"}},
				},
				threshold: 10,
			},
			want: detection.FileDiff{
				Name:        "redhat_9",
				BaselineIDs: map[sourceTypes.SourceID][]string{"redhat-csaf": {"CVE-2026-0001", "CVE-2026-0002"}},
				TargetIDs:   map[sourceTypes.SourceID][]string{"redhat-csaf": {"CVE-2026-0001", "CVE-2026-0002"}},
				Sources: []detection.SourceDiff{
					{
						SourceID:    "redhat-csaf",
						BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002"},
						TargetIDs:   []string{"CVE-2026-0001", "CVE-2026-0002"},
						ChangeRate:  0,
						Threshold:   10,
						Pass:        true,
					},
				},
				Pass: true,
			},
		},
		{
			name: "small change within limit",
			args: args{
				d: detection.FileDiff{
					Name: "redhat_9",
					BaselineIDs: map[sourceTypes.SourceID][]string{"redhat-csaf": {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005",
						"CVE-2026-0006", "CVE-2026-0007", "CVE-2026-0008", "CVE-2026-0009", "CVE-2026-0010"}},
					TargetIDs: map[sourceTypes.SourceID][]string{"redhat-csaf": {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005",
						"CVE-2026-0006", "CVE-2026-0007", "CVE-2026-0008", "CVE-2026-0009", "CVE-2026-0011"}},
				},
				threshold: 25,
			},
			want: detection.FileDiff{
				Name: "redhat_9",
				BaselineIDs: map[sourceTypes.SourceID][]string{"redhat-csaf": {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005",
					"CVE-2026-0006", "CVE-2026-0007", "CVE-2026-0008", "CVE-2026-0009", "CVE-2026-0010"}},
				TargetIDs: map[sourceTypes.SourceID][]string{"redhat-csaf": {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005",
					"CVE-2026-0006", "CVE-2026-0007", "CVE-2026-0008", "CVE-2026-0009", "CVE-2026-0011"}},
				Sources: []detection.SourceDiff{
					{
						SourceID: "redhat-csaf",
						BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005",
							"CVE-2026-0006", "CVE-2026-0007", "CVE-2026-0008", "CVE-2026-0009", "CVE-2026-0010"},
						TargetIDs: []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004", "CVE-2026-0005",
							"CVE-2026-0006", "CVE-2026-0007", "CVE-2026-0008", "CVE-2026-0009", "CVE-2026-0011"},
						Added:      []string{"CVE-2026-0011"},
						Removed:    []string{"CVE-2026-0010"},
						ChangeRate: 20,
						Threshold:  25,
						Pass:       true,
					},
				},
				Pass: true,
			},
		},
		{
			name: "large removal exceeds limit",
			args: args{
				d: detection.FileDiff{
					Name:        "ubuntu_22.04",
					BaselineIDs: map[sourceTypes.SourceID][]string{"ubuntu-oval": {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"}},
					TargetIDs:   map[sourceTypes.SourceID][]string{"ubuntu-oval": {"CVE-2026-0001"}},
				},
				threshold: 10,
			},
			want: detection.FileDiff{
				Name:        "ubuntu_22.04",
				BaselineIDs: map[sourceTypes.SourceID][]string{"ubuntu-oval": {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"}},
				TargetIDs:   map[sourceTypes.SourceID][]string{"ubuntu-oval": {"CVE-2026-0001"}},
				Sources: []detection.SourceDiff{
					{
						SourceID:    "ubuntu-oval",
						BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"},
						TargetIDs:   []string{"CVE-2026-0001"},
						Removed:     []string{"CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"},
						ChangeRate:  75,
						Threshold:   10,
						Pass:        false,
					},
				},
				Pass: false,
			},
		},
		{
			// The motivating case for per-source granularity: the small
			// cisco-json source disappears while the big NVD source is
			// unchanged. The union of CVE IDs would barely move (cisco CVEs
			// are also detected by NVD), but the per-source diff fails loudly.
			name: "small source loss not masked by large source",
			args: args{
				d: detection.FileDiff{
					Name: "cpe_cisco",
					BaselineIDs: map[sourceTypes.SourceID][]string{
						"nvd-feed-cve-v2": {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"},
						"cisco-json":      {"CVE-2026-0001", "CVE-2026-0002"},
					},
					TargetIDs: map[sourceTypes.SourceID][]string{
						"nvd-feed-cve-v2": {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"},
					},
				},
				threshold: 10,
			},
			want: detection.FileDiff{
				Name: "cpe_cisco",
				BaselineIDs: map[sourceTypes.SourceID][]string{
					"nvd-feed-cve-v2": {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"},
					"cisco-json":      {"CVE-2026-0001", "CVE-2026-0002"},
				},
				TargetIDs: map[sourceTypes.SourceID][]string{
					"nvd-feed-cve-v2": {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"},
				},
				Sources: []detection.SourceDiff{
					{
						SourceID:    "cisco-json",
						BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002"},
						Removed:     []string{"CVE-2026-0001", "CVE-2026-0002"},
						ChangeRate:  100,
						Threshold:   10,
						Pass:        false,
					},
					{
						SourceID:    "nvd-feed-cve-v2",
						BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"},
						TargetIDs:   []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"},
						ChangeRate:  0,
						Threshold:   10,
						Pass:        true,
					},
				},
				Pass: false,
			},
		},
		{
			// A per-source threshold lifts exactly that source while the
			// other stays on the default.
			name: "per-source threshold lifts only its source",
			args: args{
				d: detection.FileDiff{
					Name: "cpe_jvn",
					BaselineIDs: map[sourceTypes.SourceID][]string{
						"jvn-feed-rss":    {"CVE-2026-0001", "CVE-2026-0002"},
						"nvd-feed-cve-v2": {"CVE-2026-0001", "CVE-2026-0002"},
					},
					TargetIDs: map[sourceTypes.SourceID][]string{
						"jvn-feed-rss":    {"CVE-2026-0001", "CVE-2026-0003"},
						"nvd-feed-cve-v2": {"CVE-2026-0001", "CVE-2026-0002"},
					},
				},
				threshold: 10,
				overrides: map[string]float64{"cpe_jvn/jvn-feed-rss": 150},
			},
			want: detection.FileDiff{
				Name: "cpe_jvn",
				BaselineIDs: map[sourceTypes.SourceID][]string{
					"jvn-feed-rss":    {"CVE-2026-0001", "CVE-2026-0002"},
					"nvd-feed-cve-v2": {"CVE-2026-0001", "CVE-2026-0002"},
				},
				TargetIDs: map[sourceTypes.SourceID][]string{
					"jvn-feed-rss":    {"CVE-2026-0001", "CVE-2026-0003"},
					"nvd-feed-cve-v2": {"CVE-2026-0001", "CVE-2026-0002"},
				},
				Sources: []detection.SourceDiff{
					{
						SourceID:    "jvn-feed-rss",
						BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002"},
						TargetIDs:   []string{"CVE-2026-0001", "CVE-2026-0003"},
						Added:       []string{"CVE-2026-0003"},
						Removed:     []string{"CVE-2026-0002"},
						ChangeRate:  100,
						Threshold:   150,
						Pass:        true,
					},
					{
						SourceID:    "nvd-feed-cve-v2",
						BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002"},
						TargetIDs:   []string{"CVE-2026-0001", "CVE-2026-0002"},
						ChangeRate:  0,
						Threshold:   10,
						Pass:        true,
					},
				},
				Pass: true,
			},
		},
		{
			name: "source only in target triggers 100% change",
			args: args{
				d: detection.FileDiff{
					Name:        "redhat_9",
					BaselineIDs: map[sourceTypes.SourceID][]string{},
					TargetIDs:   map[sourceTypes.SourceID][]string{"redhat-csaf": {"CVE-2026-0001", "CVE-2026-0002"}},
				},
				threshold: 10,
			},
			want: detection.FileDiff{
				Name:        "redhat_9",
				BaselineIDs: map[sourceTypes.SourceID][]string{},
				TargetIDs:   map[sourceTypes.SourceID][]string{"redhat-csaf": {"CVE-2026-0001", "CVE-2026-0002"}},
				Sources: []detection.SourceDiff{
					{
						SourceID:   "redhat-csaf",
						TargetIDs:  []string{"CVE-2026-0001", "CVE-2026-0002"},
						Added:      []string{"CVE-2026-0001", "CVE-2026-0002"},
						ChangeRate: 100,
						Threshold:  10,
						Pass:       false,
					},
				},
				Pass: false,
			},
		},
		{
			name: "both empty pass with no sources",
			args: args{
				d: detection.FileDiff{
					Name:        "redhat_9",
					BaselineIDs: map[sourceTypes.SourceID][]string{},
					TargetIDs:   map[sourceTypes.SourceID][]string{},
				},
				threshold: 10,
			},
			want: detection.FileDiff{
				Name:        "redhat_9",
				BaselineIDs: map[sourceTypes.SourceID][]string{},
				TargetIDs:   map[sourceTypes.SourceID][]string{},
				Sources:     []detection.SourceDiff{},
				Pass:        true,
			},
		},
		{
			// Caller-resolved override-style threshold (higher than default)
			// is applied verbatim and lifts the row above its rate.
			name: "high threshold lets a moderate rate pass",
			args: args{
				d: detection.FileDiff{
					Name:        "debian_13",
					BaselineIDs: map[sourceTypes.SourceID][]string{"debian-security-tracker-api": {"CVE-2026-0001", "CVE-2026-0002"}},
					TargetIDs:   map[sourceTypes.SourceID][]string{"debian-security-tracker-api": {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"}},
				},
				threshold: 80,
			},
			want: detection.FileDiff{
				Name:        "debian_13",
				BaselineIDs: map[sourceTypes.SourceID][]string{"debian-security-tracker-api": {"CVE-2026-0001", "CVE-2026-0002"}},
				TargetIDs:   map[sourceTypes.SourceID][]string{"debian-security-tracker-api": {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"}},
				Sources: []detection.SourceDiff{
					{
						SourceID:    "debian-security-tracker-api",
						BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002"},
						TargetIDs:   []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"},
						Added:       []string{"CVE-2026-0003"},
						ChangeRate:  50,
						Threshold:   80,
						Pass:        true,
					},
				},
				Pass: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detection.DiffDetection(tt.args.d, tt.args.overrides, tt.args.threshold)
			// Sources carries no order guarantee (the report sorts for
			// presentation), so compare it order-insensitively.
			if diff := cmp.Diff(tt.want, got, cmpopts.SortSlices(func(a, b detection.SourceDiff) bool { return a.SourceID < b.SourceID })); diff != "" {
				t.Errorf("DiffDetection() mismatch (-want +got):\n%s", diff)
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
								ChangeRate:  0,
								Threshold:   10,
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
								ChangeRate:  75.0,
								Threshold:   10,
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

| Name | Source | Baseline | Target | Added | Removed | Change Rate | Threshold | Result |
|------|--------|----------|--------|-------|---------|-------------|-----------|--------|
| ubuntu_22.04 | ubuntu-oval | 4 | 1 | 0 | 3 | 75.0% | 10.0% | **FAIL** |
| redhat_9 | redhat-csaf | 2 | 2 | 0 | 0 | 0.0% | 10.0% | PASS |

## Details (FAIL sources)

### ubuntu_22.04 / ubuntu-oval (75.0%)

#### Removed IDs (3)

- CVE-2026-0002
- CVE-2026-0003
- CVE-2026-0004

`,
		},
		{
			// The motivating scenario: within one cpe fixture, a failing small
			// source sorts above the passing large source and is reported as
			// its own row.
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
								ChangeRate:  100,
								Threshold:   10,
								Pass:        false,
							},
							{
								SourceID:    "nvd-feed-cve-v2",
								BaselineIDs: []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"},
								TargetIDs:   []string{"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003", "CVE-2026-0004"},
								ChangeRate:  0,
								Threshold:   10,
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

| Name | Source | Baseline | Target | Added | Removed | Change Rate | Threshold | Result |
|------|--------|----------|--------|-------|---------|-------------|-----------|--------|
| cpe_cisco | cisco-json | 2 | 0 | 0 | 2 | 100.0% | 10.0% | **FAIL** |
| cpe_cisco | nvd-feed-cve-v2 | 4 | 4 | 0 | 0 | 0.0% | 10.0% | PASS |

## Details (FAIL sources)

### cpe_cisco / cisco-json (100.0%)

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
								ChangeRate:  0,
								Threshold:   10,
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

| Name | Source | Baseline | Target | Added | Removed | Change Rate | Threshold | Result |
|------|--------|----------|--------|-------|---------|-------------|-----------|--------|
| redhat_9 | redhat-csaf | 1 | 1 | 0 | 0 | 0.0% | 10.0% | PASS |

`,
		},
		{
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
								ChangeRate:  50,
								Threshold:   80,
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
								ChangeRate:  0,
								Threshold:   10,
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

| Name | Source | Baseline | Target | Added | Removed | Change Rate | Threshold | Result |
|------|--------|----------|--------|-------|---------|-------------|-----------|--------|
| debian_13 | debian-security-tracker-api | 2 | 3 | 1 | 0 | 50.0% | 80.0% | PASS |
| redhat_9 | redhat-csaf | 1 | 1 | 0 | 0 | 0.0% | 10.0% | PASS |

`,
		},
		{
			// Locks the FAIL-first sort tier: a PASS row with a higher change
			// rate (held passing by an override) must sort below a FAIL row
			// whose rate is lower. Pure rate-desc sort would put alpha first.
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
								ChangeRate:  250,
								Threshold:   300,
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
								ChangeRate:  100,
								Threshold:   0,
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

| Name | Source | Baseline | Target | Added | Removed | Change Rate | Threshold | Result |
|------|--------|----------|--------|-------|---------|-------------|-----------|--------|
| beta | alma-errata | 2 | 2 | 1 | 1 | 100.0% | 0.0% | **FAIL** |
| alpha | alma-errata | 2 | 3 | 3 | 2 | 250.0% | 300.0% | PASS |

## Details (FAIL sources)

### beta / alma-errata (100.0%)

#### Added IDs (1)

- CVE-2026-1003

#### Removed IDs (1)

- CVE-2026-1002

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

func TestGenerateReportTruncatesLongIDLists(t *testing.T) {
	ids := make([]string, 502)
	for i := range ids {
		ids[i] = fmt.Sprintf("CVE-2026-%04d", i)
	}
	diffs := map[string]detection.FileDiff{
		"cpe_nvd": {
			Name: "cpe_nvd",
			Sources: []detection.SourceDiff{
				{
					SourceID:    "nvd-feed-cve-v2",
					BaselineIDs: ids,
					Removed:     ids,
					ChangeRate:  100,
					Threshold:   5,
					Pass:        false,
				},
			},
			Pass: false,
		},
	}

	var buf bytes.Buffer
	gotPass, err := detection.GenerateReport(&buf, diffs)
	if err != nil {
		t.Fatalf("GenerateReport() error = %v", err)
	}
	if gotPass {
		t.Error("GenerateReport() pass = true, want false")
	}
	got := buf.String()
	if !strings.Contains(got, "#### Removed IDs (502)") {
		t.Error("report should state the full list length")
	}
	if !strings.Contains(got, "- ... and 2 more\n") {
		t.Error("report should truncate the list with a trailer")
	}
	if strings.Contains(got, ids[501]) {
		t.Errorf("report should not contain the truncated ID %s", ids[501])
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

	fakeDetect := func(_, _, _, _ string, files map[string]string) (map[string]detection.FileDiff, error) {
		result := make(map[string]detection.FileDiff, len(files))
		for name := range files {
			switch name {
			case "redhat_9":
				result[name] = detection.FileDiff{
					Name:        name,
					BaselineIDs: map[sourceTypes.SourceID][]string{"redhat-csaf": {"CVE-2026-0001", "CVE-2026-0002"}},
					TargetIDs:   map[sourceTypes.SourceID][]string{"redhat-csaf": {"CVE-2026-0001", "CVE-2026-0002"}},
				}
			case "ubuntu_2204":
				result[name] = detection.FileDiff{
					Name:        name,
					BaselineIDs: map[sourceTypes.SourceID][]string{"ubuntu-oval": {"CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"}},
					TargetIDs:   map[sourceTypes.SourceID][]string{"ubuntu-oval": {"CVE-2026-0001"}},
				}
			}
		}
		return result, nil
	}

	fakeDetectErr := func(_, _, _, _ string, _ map[string]string) (map[string]detection.FileDiff, error) {
		return nil, errors.New("vuls0 crashed")
	}

	emptyDir := t.TempDir()

	type args struct {
		dir                          string
		detectFunc                   detection.DetectFunc
		changeRateThreshold          float64
		changeRateThresholdOverrides map[string]float64
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "fail on exceeded change rate",
			args: args{
				dir:                 scanDir,
				detectFunc:          fakeDetect,
				changeRateThreshold: 10,
			},
			wantErr: true,
		},
		{
			name: "pass within threshold",
			args: args{
				dir:                 scanDir,
				detectFunc:          fakeDetect,
				changeRateThreshold: 100,
			},
			wantErr: false,
		},
		{
			name: "detect error propagated",
			args: args{
				dir:                 scanDir,
				detectFunc:          fakeDetectErr,
				changeRateThreshold: 10,
			},
			wantErr: true,
		},
		{
			name: "no scan results error",
			args: args{
				dir:                 emptyDir,
				detectFunc:          fakeDetect,
				changeRateThreshold: 10,
			},
			wantErr: true,
		},
		{
			// Locks WithChangeRateThresholdOverrides forwarding through the
			// inline resolve+diffDetection loop in Diff. ubuntu_2204 in
			// fakeDetect produces a 66.7% change rate (baseline 3 IDs,
			// target 1, two removed) which would FAIL the 10% default. The
			// "ubuntu_2204=70" override lifts every source in that file above
			// its rate so the whole Diff returns nil. If Diff stops forwarding
			// the option, the override has no effect and ubuntu_2204 fails again.
			name: "file override forwarded through to per-source resolution",
			args: args{
				dir:                          scanDir,
				detectFunc:                   fakeDetect,
				changeRateThreshold:          10,
				changeRateThresholdOverrides: map[string]float64{"ubuntu_2204": 70},
			},
			wantErr: false,
		},
		{
			// The "<file>/<source>" key form resolves for a specific source.
			name: "file/source override forwarded through",
			args: args{
				dir:                          scanDir,
				detectFunc:                   fakeDetect,
				changeRateThreshold:          10,
				changeRateThresholdOverrides: map[string]float64{"ubuntu_2204/ubuntu-oval": 70},
			},
			wantErr: false,
		},
		{
			// "<file>/<source>" takes precedence over the file-wide key: the
			// generous file-wide 70 is overridden back down to 10 for the
			// only source present, so the file fails again.
			name: "file/source override beats file override",
			args: args{
				dir:                 scanDir,
				detectFunc:          fakeDetect,
				changeRateThreshold: 10,
				changeRateThresholdOverrides: map[string]float64{
					"ubuntu_2204":             70,
					"ubuntu_2204/ubuntu-oval": 10,
				},
			},
			wantErr: true,
		},
		{
			// An override entry that matches no file in the diffm must fall
			// through cleanly: every file still resolves to the default
			// threshold. Locks the `if v, ok := overrides[name]; ok` miss
			// branch in Diff's inline resolve loop.
			name: "unmatched override key does not affect outcome",
			args: args{
				dir:                          scanDir,
				detectFunc:                   fakeDetect,
				changeRateThreshold:          100, // both files pass at default
				changeRateThresholdOverrides: map[string]float64{"unknown_99": 1},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := detection.Diff(
				tt.args.dir, "baseline.db", "vuls0", "target.db", "vuls0",
				detection.WithChangeRateThreshold(tt.args.changeRateThreshold),
				detection.WithChangeRateThresholdOverrides(tt.args.changeRateThresholdOverrides),
				detection.WithWriter(&bytes.Buffer{}),
				detection.WithDetectFunc(tt.args.detectFunc),
			)

			if (err != nil) != tt.wantErr {
				t.Fatalf("Diff() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
