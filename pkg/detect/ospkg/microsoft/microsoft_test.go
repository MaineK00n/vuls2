package microsoft_test

import (
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"go.etcd.io/bbolt"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	kbcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/kbcriterion"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	vcAffectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	vcAffectedRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	vcFixStatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	vcPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	vcBinaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/db/session"
	"github.com/MaineK00n/vuls2/pkg/detect/internal/test"
	"github.com/MaineK00n/vuls2/pkg/detect/ospkg/microsoft"
	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"
	scanTypes "github.com/MaineK00n/vuls2/pkg/scan/types"
)

func TestDetect(t *testing.T) {
	type args struct {
		ecosystem   ecosystemTypes.Ecosystem
		sr          scanTypes.ScanResult
		concurrency int
	}
	tests := []struct {
		name    string
		fixture string
		config  session.Config
		args    args
		want    map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection
		wantErr error
	}{
		{
			name:    "no input returns nil",
			fixture: "testdata/fixtures/microsoft-supersession",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				ecosystem:   ecosystemTypes.EcosystemTypeMicrosoft,
				sr:          scanTypes.ScanResult{},
				concurrency: 1,
			},
			want: map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection{},
		},
		{
			name:    "detect CVE-2021-1640 by unapplied KB",
			fixture: "testdata/fixtures/microsoft-supersession",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				ecosystem: ecosystemTypes.EcosystemTypeMicrosoft,
				sr: scanTypes.ScanResult{
					Family:  ecosystemTypes.EcosystemTypeMicrosoft,
					Release: "Windows 10 Version 2004 for x64-based Systems",
					MicrosoftKB: scanTypes.MicrosoftKB{
						Applied:   []string{"5001330"},
						Unapplied: []string{"5000802"},
					},
				},
				concurrency: 1,
			},
			want: map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection{
				"CVE-2021-1640": {
					Ecosystem: ecosystemTypes.EcosystemTypeMicrosoft,
					Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
						"microsoft-cvrf": {
							{
								Criteria: criteriaTypes.FilteredCriteria{
									Operator: criteriaTypes.CriteriaOperatorTypeOR,
									Criterions: []criterionTypes.FilteredCriterion{
										{
											Criterion: criterionTypes.Criterion{
												Type: criterionTypes.CriterionTypeKB,
												KB: &kbcTypes.Criterion{
													Product: "Windows 10 Version 2004 for x64-based Systems",
													KBID:    "5000802",
												},
											},
											Accepts: criterionTypes.AcceptQueries{KB: true},
										},
									},
								},
								Tag: segmentTypes.DetectionTag("Windows 10 Version 2004 for x64-based Systems"),
							},
						},
					},
				},
			},
		},
		{
			name:    "all KBs applied, no detection",
			fixture: "testdata/fixtures/microsoft-supersession",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				ecosystem: ecosystemTypes.EcosystemTypeMicrosoft,
				sr: scanTypes.ScanResult{
					Family:  ecosystemTypes.EcosystemTypeMicrosoft,
					Release: "Windows 10 Version 2004 for x64-based Systems",
					MicrosoftKB: scanTypes.MicrosoftKB{
						Applied: []string{"5000802", "5001330"},
					},
				},
				concurrency: 1,
			},
			want: map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection{},
		},
		{
			name:    "supersession auto-discovery from applied KB",
			fixture: "testdata/fixtures/microsoft-supersession",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				ecosystem: ecosystemTypes.EcosystemTypeMicrosoft,
				sr: scanTypes.ScanResult{
					Family:  ecosystemTypes.EcosystemTypeMicrosoft,
					Release: "Windows 10 Version 2004 for x64-based Systems",
					MicrosoftKB: scanTypes.MicrosoftKB{
						Applied: []string{"5000802"},
					},
				},
				concurrency: 1,
			},
			want: map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection{
				"CVE-2021-26413": {
					Ecosystem: ecosystemTypes.EcosystemTypeMicrosoft,
					Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
						"microsoft-cvrf": {
							{
								Criteria: criteriaTypes.FilteredCriteria{
									Operator: criteriaTypes.CriteriaOperatorTypeOR,
									Criterions: []criterionTypes.FilteredCriterion{
										{
											Criterion: criterionTypes.Criterion{
												Type: criterionTypes.CriterionTypeKB,
												KB: &kbcTypes.Criterion{
													Product: "Windows 10 Version 2004 for x64-based Systems",
													KBID:    "5001330",
												},
											},
											Accepts: criterionTypes.AcceptQueries{KB: true},
										},
									},
								},
								Tag: segmentTypes.DetectionTag("Windows 10 Version 2004 for x64-based Systems"),
							},
						},
					},
				},
			},
		},
		{
			name:    "detect CVE-2022-0096 by Edge version with package normalization",
			fixture: "testdata/fixtures/microsoft-edge",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				ecosystem: ecosystemTypes.EcosystemTypeMicrosoft,
				sr: scanTypes.ScanResult{
					Family: ecosystemTypes.EcosystemTypeMicrosoft,
					OSPackages: []scanTypes.OSPackage{
						{Name: "Microsoft Edge", Version: "96.0.1054.62"},
					},
				},
				concurrency: 1,
			},
			want: map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection{
				"CVE-2022-0096": {
					Ecosystem: ecosystemTypes.EcosystemTypeMicrosoft,
					Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
						"microsoft-cvrf": {
							{
								Criteria: criteriaTypes.FilteredCriteria{
									Operator: criteriaTypes.CriteriaOperatorTypeOR,
									Criterions: []criterionTypes.FilteredCriterion{
										{
											Criterion: criterionTypes.Criterion{
												Type: criterionTypes.CriterionTypeVersion,
												Version: &vcTypes.Criterion{
													Vulnerable: true,
													FixStatus:  &vcFixStatusTypes.FixStatus{Class: vcFixStatusTypes.ClassFixed},
													Package: vcPackageTypes.Package{
														Type: vcPackageTypes.PackageTypeBinary,
														Binary: &vcBinaryPackageTypes.Package{
															Name: "Microsoft Edge (Chromium-based)",
														},
													},
													Affected: &vcAffectedTypes.Affected{
														Type:  vcAffectedRangeTypes.RangeTypeMicrosoftEdge,
														Range: []vcAffectedRangeTypes.Range{{LessThan: "97.0.1072.55"}},
														Fixed: []string{"97.0.1072.55"},
													},
												},
											},
											Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
										},
									},
								},
								Tag: segmentTypes.DetectionTag("Microsoft Edge (Chromium-based)"),
							},
						},
					},
				},
			},
		},
		{
			name:    "Edge version not affected, no detection",
			fixture: "testdata/fixtures/microsoft-edge",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				ecosystem: ecosystemTypes.EcosystemTypeMicrosoft,
				sr: scanTypes.ScanResult{
					Family: ecosystemTypes.EcosystemTypeMicrosoft,
					OSPackages: []scanTypes.OSPackage{
						{Name: "Microsoft Edge", Version: "98.0.1108.43"},
					},
				},
				concurrency: 1,
			},
			want: map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection{},
		},
		{
			name:    "detect CVE-2022-21907 by Release and Kernel.Version",
			fixture: "testdata/fixtures/microsoft-windows-version",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				ecosystem: ecosystemTypes.EcosystemTypeMicrosoft,
				sr: scanTypes.ScanResult{
					Family:  ecosystemTypes.EcosystemTypeMicrosoft,
					Release: "Windows 10 Version 21H2 for x64-based Systems",
					Kernel:  scanTypes.Kernel{Version: "10.0.19044.1000"},
					OSPackages: []scanTypes.OSPackage{
						{
							Name:    "Windows 10 Version 21H2 for x64-based Systems",
							Version: "10.0.19044.1000",
						},
					},
				},
				concurrency: 1,
			},
			want: map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection{
				"CVE-2022-21907": {
					Ecosystem: ecosystemTypes.EcosystemTypeMicrosoft,
					Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
						"microsoft-cvrf": {
							{
								Criteria: criteriaTypes.FilteredCriteria{
									Operator: criteriaTypes.CriteriaOperatorTypeOR,
									Criterions: []criterionTypes.FilteredCriterion{
										{
											Criterion: criterionTypes.Criterion{
												Type: criterionTypes.CriterionTypeVersion,
												Version: &vcTypes.Criterion{
													Vulnerable: true,
													FixStatus:  &vcFixStatusTypes.FixStatus{Class: vcFixStatusTypes.ClassFixed},
													Package: vcPackageTypes.Package{
														Type: vcPackageTypes.PackageTypeBinary,
														Binary: &vcBinaryPackageTypes.Package{
															Name: "Windows 10 Version 21H2 for x64-based Systems",
														},
													},
													Affected: &vcAffectedTypes.Affected{
														Type:  vcAffectedRangeTypes.RangeTypeMicrosoftWindows,
														Range: []vcAffectedRangeTypes.Range{{LessThan: "10.0.19044.1466"}},
														Fixed: []string{"10.0.19044.1466"},
													},
												},
											},
											Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
										},
										{
											Criterion: criterionTypes.Criterion{
												Type: criterionTypes.CriterionTypeKB,
												KB: &kbcTypes.Criterion{
													Product: "Windows 10 Version 21H2 for x64-based Systems",
													KBID:    "5009543",
												},
											},
										},
									},
								},
								Tag: segmentTypes.DetectionTag("Windows 10 Version 21H2 for x64-based Systems"),
							},
						},
					},
				},
			},
		},
		{
			name:    "Windows version patched, no detection",
			fixture: "testdata/fixtures/microsoft-windows-version",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				ecosystem: ecosystemTypes.EcosystemTypeMicrosoft,
				sr: scanTypes.ScanResult{
					Family:  ecosystemTypes.EcosystemTypeMicrosoft,
					Release: "Windows 10 Version 21H2 for x64-based Systems",
					Kernel:  scanTypes.Kernel{Version: "10.0.19044.1466"},
					OSPackages: []scanTypes.OSPackage{
						{
							Name:    "Windows 10 Version 21H2 for x64-based Systems",
							Version: "10.0.19044.1466",
						},
					},
				},
				concurrency: 1,
			},
			want: map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(tt.config, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			s, err := tt.config.New()
			if err != nil {
				t.Fatalf("new session. error = %v", err)
			}

			if err := s.Storage().Open(); err != nil {
				t.Fatalf("open db connection. error = %v", err)
			}
			defer s.Storage().Close()

			got, err := microsoft.Detect(s.Storage(), tt.args.ecosystem, tt.args.sr, tt.args.concurrency)
			switch {
			case tt.wantErr == nil && err != nil:
				t.Errorf("Detect() unexpected error: %v", err)
			case tt.wantErr != nil && err == nil:
				t.Errorf("Detect() expected error has not occurred")
			case tt.wantErr != nil && err != nil:
				if tt.wantErr.Error() != err.Error() {
					t.Errorf("Detect() error mismatch: want %v, got %v", tt.wantErr, err)
				}
			default:
				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Errorf("Detect() (-expected +got):\n%s", diff)
				}
			}
		})
	}
}

func Test_computeUnappliedKBs(t *testing.T) {
	type args struct {
		_         session.Storage
		applied   []string
		unapplied []string
	}
	tests := []struct {
		name    string
		fixture string
		config  session.Config
		args    args
		want    []string
		wantErr error
	}{
		{
			name:    "no input",
			fixture: "testdata/fixtures/microsoft-supersession",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				applied:   nil,
				unapplied: nil,
			},
			want: nil,
		},
		{
			name:    "applied only, discover unapplied via supersession",
			fixture: "testdata/fixtures/microsoft-supersession",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				applied: []string{"5000802"},
			},
			want: []string{"5001330", "5003173"},
		},
		{
			name:    "unapplied with chain",
			fixture: "testdata/fixtures/microsoft-supersession",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				applied:   []string{},
				unapplied: []string{"5000802"},
			},
			want: []string{"5000802", "5001330", "5003173"},
		},
		{
			name:    "all applied returns empty",
			fixture: "testdata/fixtures/microsoft-supersession",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				applied: []string{"5000802", "5001330", "5003173"},
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := test.PopulateDB(tt.config, tt.fixture); err != nil {
				t.Fatalf("populate db. error = %v", err)
			}

			s, err := tt.config.New()
			if err != nil {
				t.Fatalf("new session. error = %v", err)
			}

			if err := s.Storage().Open(); err != nil {
				t.Fatalf("open db connection. error = %v", err)
			}
			defer s.Storage().Close()

			got, err := microsoft.ComputeUnappliedKBs(s.Storage(), tt.args.applied, tt.args.unapplied)
			switch {
			case tt.wantErr == nil && err != nil:
				t.Errorf("computeUnappliedKBs() unexpected error: %v", err)
			case tt.wantErr != nil && err == nil:
				t.Errorf("computeUnappliedKBs() expected error has not occurred")
			case tt.wantErr != nil && err != nil:
				if tt.wantErr.Error() != err.Error() {
					t.Errorf("computeUnappliedKBs() error mismatch: want %v, got %v", tt.wantErr, err)
				}
			default:
				if diff := cmp.Diff(tt.want, got, cmpopts.SortSlices(func(a, b string) bool { return a < b })); diff != "" {
					t.Errorf("computeUnappliedKBs() (-expected +got):\n%s", diff)
				}
			}
		})
	}
}

func Test_normalizeMicrosoftPackageName(t *testing.T) {
	type args struct {
		name    string
		release string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "Microsoft Edge without release",
			args: args{
				name: "Microsoft Edge",
			},
			want: []string{
				"Microsoft Edge (Chromium-based)",
			},
		},
		{
			name: "Microsoft Edge with release",
			args: args{
				name:    "Microsoft Edge",
				release: "Windows 10 Version 1607 for x64-based Systems",
			},
			want: []string{
				"Microsoft Edge (Chromium-based)",
				"Microsoft Edge (Chromium-based) in IE Mode on Windows 10 Version 1607 for x64-based Systems",
				"Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1607 for x64-based Systems",
			},
		},
		{
			name: "Microsoft Visual Studio Code",
			args: args{
				name: "Microsoft Visual Studio Code",
			},
			want: []string{"Visual Studio Code"},
		},
		{
			name: "Microsoft Visual Studio Code Insiders",
			args: args{
				name: "Microsoft Visual Studio Code Insiders (User)",
			},
			want: []string{"Visual Studio Code"},
		},
		{
			name: "Microsoft Teams",
			args: args{
				name: "Microsoft Teams",
			},
			want: []string{"Microsoft Teams", "Microsoft Teams for Desktop"},
		},
		{
			name: "unknown package returns nil",
			args: args{
				name: "Google Chrome",
			},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := microsoft.NormalizeMicrosoftPackageName(tt.args.name, tt.args.release)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("normalizeMicrosoftPackageName() (-expected +got):\n%s", diff)
			}
		})
	}
}

func Test_filterMicrosoftKBProduct(t *testing.T) {
	type args struct {
		product string
		release string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "no suffix passes",
			args: args{
				product: "Microsoft Edge (Chromium-based)",
				release: "Windows 10 Version 1607 for x64-based Systems",
			},
			want: true,
		},
		{
			name: "matching release passes",
			args: args{
				product: "Microsoft Edge (Chromium-based) in IE Mode on Windows 10 Version 1607 for x64-based Systems",
				release: "Windows 10 Version 1607 for x64-based Systems",
			},
			want: true,
		},
		{
			name: "non-matching release blocked",
			args: args{
				product: "Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1511 for x64-based Systems",
				release: "Windows 10 Version 1607 for x64-based Systems",
			},
			want: false,
		},
		{
			name: "installed on matching release passes",
			args: args{
				product: ".NET 6.0 installed on Windows 10 Version 21H2 for x64-based Systems",
				release: "Windows 10 Version 21H2 for x64-based Systems",
			},
			want: true,
		},
		{
			name: "installed on non-matching release blocked",
			args: args{
				product: ".NET 6.0 installed on Windows 10 Version 21H2 for x64-based Systems",
				release: "Windows 11 Version 22H2 for x64-based Systems",
			},
			want: false,
		},
		{
			name: "empty release passes any suffix",
			args: args{
				product: "Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1511 for x64-based Systems",
				release: "",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := microsoft.FilterMicrosoftKBProduct(tt.args.product, tt.args.release); got != tt.want {
				t.Errorf("filterMicrosoftKBProduct() = %v, want %v", got, tt.want)
			}
		})
	}
}
