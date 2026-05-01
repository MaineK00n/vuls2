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
			name:    "detect CVE-2021-1640 and CVE-2021-26413 by unapplied KB with supersession",
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
									Criterias: []criteriaTypes.FilteredCriteria{
										{
											Operator: criteriaTypes.CriteriaOperatorTypeAND,
											Criterions: []criterionTypes.FilteredCriterion{
												{
													Criterion: criterionTypes.Criterion{
														Type: criterionTypes.CriterionTypeKB,
														KB: &kbcTypes.Criterion{
															Product: "Windows 10 Version 2004 for x64-based Systems",
															KBID:    "5000802",
														},
													},
													Accepts: criterionTypes.AcceptQueries{KB: criterionTypes.KB{Unapplied: true}},
												},
											},
										},
									},
								},
								Tag: segmentTypes.DetectionTag("Windows 10 Version 2004 for x64-based Systems"),
							},
						},
					},
				},
				"CVE-2021-26413": {
					Ecosystem: ecosystemTypes.EcosystemTypeMicrosoft,
					Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
						"microsoft-cvrf": {
							{
								Criteria: criteriaTypes.FilteredCriteria{
									Operator: criteriaTypes.CriteriaOperatorTypeOR,
									Criterias: []criteriaTypes.FilteredCriteria{
										{
											Operator: criteriaTypes.CriteriaOperatorTypeAND,
											Criterions: []criterionTypes.FilteredCriterion{
												{
													Criterion: criterionTypes.Criterion{
														Type: criterionTypes.CriterionTypeKB,
														KB: &kbcTypes.Criterion{
															Product: "Windows 10 Version 2004 for x64-based Systems",
															KBID:    "5001330",
														},
													},
													Accepts: criterionTypes.AcceptQueries{KB: criterionTypes.KB{Unapplied: true}},
												},
											},
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
			name:    "fix KB covered by applied superseding KB, no detection",
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
									Criterias: []criteriaTypes.FilteredCriteria{
										{
											Operator: criteriaTypes.CriteriaOperatorTypeAND,
											Criterions: []criterionTypes.FilteredCriterion{
												{
													Criterion: criterionTypes.Criterion{
														Type: criterionTypes.CriterionTypeKB,
														KB: &kbcTypes.Criterion{
															Product: "Windows 10 Version 2004 for x64-based Systems",
															KBID:    "5001330",
														},
													},
													Accepts: criterionTypes.AcceptQueries{KB: criterionTypes.KB{Covered: true}},
												},
											},
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
		{
			name:    "detect bare cross-platform app KB criterion on Windows host",
			fixture: "testdata/fixtures/microsoft-bare-app-kb",
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
					MicrosoftKB: scanTypes.MicrosoftKB{
						Unapplied: []string{"8800001"},
					},
				},
				concurrency: 1,
			},
			want: map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection{
				"CVE-2024-88001": {
					Ecosystem: ecosystemTypes.EcosystemTypeMicrosoft,
					Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
						"microsoft-cvrf": {
							{
								Criteria: criteriaTypes.FilteredCriteria{
									Operator: criteriaTypes.CriteriaOperatorTypeOR,
									Criterias: []criteriaTypes.FilteredCriteria{
										{
											Operator: criteriaTypes.CriteriaOperatorTypeAND,
											Criterions: []criterionTypes.FilteredCriterion{
												{
													Criterion: criterionTypes.Criterion{
														Type: criterionTypes.CriterionTypeKB,
														KB: &kbcTypes.Criterion{
															Product: "Microsoft Office 2016 (32-bit edition)",
															KBID:    "8800001",
														},
													},
													Accepts: criterionTypes.AcceptQueries{KB: criterionTypes.KB{Unapplied: true}},
												},
											},
										},
									},
								},
								Tag: segmentTypes.DetectionTag("Microsoft Office 2016 (32-bit edition)"),
							},
						},
					},
				},
			},
		},
		{
			name:    "cross-product KB filtered: Win10 host does not detect Server 2012 condition",
			fixture: "testdata/fixtures/microsoft-cross-product",
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
					MicrosoftKB: scanTypes.MicrosoftKB{
						Unapplied: []string{"9000001", "9000002"},
					},
				},
				concurrency: 1,
			},
			want: map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection{
				"CVE-2024-90001": {
					Ecosystem: ecosystemTypes.EcosystemTypeMicrosoft,
					Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
						"microsoft-cvrf": {
							{
								Criteria: criteriaTypes.FilteredCriteria{
									Operator: criteriaTypes.CriteriaOperatorTypeOR,
									Criterias: []criteriaTypes.FilteredCriteria{
										{
											Operator: criteriaTypes.CriteriaOperatorTypeAND,
											Criterions: []criterionTypes.FilteredCriterion{
												{
													Criterion: criterionTypes.Criterion{
														Type: criterionTypes.CriterionTypeKB,
														KB: &kbcTypes.Criterion{
															Product: "Windows 10 Version 21H2 for x64-based Systems",
															KBID:    "9000001",
														},
													},
													Accepts: criterionTypes.AcceptQueries{KB: criterionTypes.KB{Unapplied: true}},
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
				"CVE-2024-90002": {
					Ecosystem: ecosystemTypes.EcosystemTypeMicrosoft,
					Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
						"microsoft-cvrf": {
							{
								Criteria: criteriaTypes.FilteredCriteria{
									Operator: criteriaTypes.CriteriaOperatorTypeOR,
									Criterias: []criteriaTypes.FilteredCriteria{
										{
											Operator: criteriaTypes.CriteriaOperatorTypeAND,
											Criterions: []criterionTypes.FilteredCriterion{
												{
													Criterion: criterionTypes.Criterion{
														Type: criterionTypes.CriterionTypeKB,
														KB: &kbcTypes.Criterion{
															Product: "Windows 10 Version 21H2 for x64-based Systems",
															KBID:    "9000002",
														},
													},
													Accepts: criterionTypes.AcceptQueries{KB: criterionTypes.KB{Unapplied: true}},
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

func Test_classifyKBs(t *testing.T) {
	type args struct {
		_         session.Storage
		applied   []string
		unapplied []string
	}
	tests := []struct {
		name        string
		fixture     string
		config      session.Config
		args        args
		wantCovered   []string
		wantUnapplied []string
		wantErr       error
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
			wantCovered:   nil,
			wantUnapplied: nil,
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
			wantCovered:   []string{"5000802"},
			wantUnapplied: []string{"5001330", "5003173", "5003637"},
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
			wantCovered:   nil,
			wantUnapplied: []string{"5000802", "5001330", "5003173", "5003637"},
		},
		{
			name:    "latest superseding KB not applied remains unapplied",
			fixture: "testdata/fixtures/microsoft-supersession",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				applied: []string{"5000802", "5001330", "5003173"},
			},
			wantCovered:   []string{"5000802", "5001330", "5003173"},
			wantUnapplied: []string{"5003637"},
		},
		{
			name:    "intermediate KB covered by applied superseding KB",
			fixture: "testdata/fixtures/microsoft-supersession",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				applied: []string{"5000802", "5003173"},
			},
			wantCovered:   []string{"5000802", "5001330", "5003173"},
			wantUnapplied: []string{"5003637"},
		},
		{
			name:    "KB in both applied and unapplied prefers unapplied",
			fixture: "testdata/fixtures/microsoft-supersession",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				applied:   []string{"5000802", "5001330"},
				unapplied: []string{"5000802"},
			},
			wantCovered:   []string{"5000802", "5001330"},
			wantUnapplied: []string{"5000802", "5003173", "5003637"},
		},
		{
			name:    "supersedes bridges gap in superseded_by chain",
			fixture: "testdata/fixtures/microsoft-supersedes",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				applied:   []string{"7000004"},
				unapplied: []string{"7000001"},
			},
			wantCovered:   []string{"7000001", "7000002", "7000003", "7000004"},
			wantUnapplied: nil,
		},
		{
			name:    "superseded_by chain to applied KB covers all without supersedes field",
			fixture: "testdata/fixtures/microsoft-supersession",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				applied:   []string{"5003637"},
				unapplied: []string{"5000802"},
			},
			wantCovered:   []string{"5000802", "5001330", "5003173", "5003637"},
			wantUnapplied: nil,
		},
		{
			name:    "per-update supersedes (MSUC) covers chain",
			fixture: "testdata/fixtures/microsoft-update-supersedes",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				applied:   []string{"8000003"},
				unapplied: nil,
			},
			wantCovered:   []string{"8000001", "8000002", "8000003"},
			wantUnapplied: nil,
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

			gotCovered, gotUnapplied, err := microsoft.ClassifyKBs(s.Storage(), tt.args.applied, tt.args.unapplied)
			switch {
			case tt.wantErr == nil && err != nil:
				t.Errorf("classifyKBs() unexpected error: %v", err)
			case tt.wantErr != nil && err == nil:
				t.Errorf("classifyKBs() expected error has not occurred")
			case tt.wantErr != nil && err != nil:
				if tt.wantErr.Error() != err.Error() {
					t.Errorf("classifyKBs() error mismatch: want %v, got %v", tt.wantErr, err)
				}
			default:
				if diff := cmp.Diff(tt.wantCovered, gotCovered, cmpopts.SortSlices(func(a, b string) bool { return a < b })); diff != "" {
					t.Errorf("classifyKBs() covered (-expected +got):\n%s", diff)
				}
				if diff := cmp.Diff(tt.wantUnapplied, gotUnapplied, cmpopts.SortSlices(func(a, b string) bool { return a < b })); diff != "" {
					t.Errorf("classifyKBs() unapplied (-expected +got):\n%s", diff)
				}
			}
		})
	}
}

func Test_filterKBIDsByRelease(t *testing.T) {
	type args struct {
		kbs     []string
		release string
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
			fixture: "testdata/fixtures/microsoft-cross-product",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				kbs:     nil,
				release: "Windows 10 Version 21H2 for x64-based Systems",
			},
			want: []string{},
		},
		{
			name:    "filters out cross-product KB for different release",
			fixture: "testdata/fixtures/microsoft-cross-product",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				kbs:     []string{"9000001", "9000002"},
				release: "Windows Server 2012 R2",
			},
			want: []string{"9000001"},
		},
		{
			name:    "keeps KB matching host release",
			fixture: "testdata/fixtures/microsoft-cross-product",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				kbs:     []string{"9000001", "9000002"},
				release: "Windows 10 Version 21H2 for x64-based Systems",
			},
			want: []string{"9000001", "9000002"},
		},
		{
			name:    "KB not found in DB is kept",
			fixture: "testdata/fixtures/microsoft-cross-product",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				kbs:     []string{"9999999", "9000001"},
				release: "Windows 10 Version 21H2 for x64-based Systems",
			},
			want: []string{"9999999", "9000001"},
		},
		{
			name:    "empty release keeps all KBs",
			fixture: "testdata/fixtures/microsoft-cross-product",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				kbs:     []string{"9000001", "9000002"},
				release: "",
			},
			want: []string{"9000001", "9000002"},
		},
		{
			name:    "ARM64 release filters out x64-only KB",
			fixture: "testdata/fixtures/microsoft-cross-product",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				kbs:     []string{"9000001", "9000002"},
				release: "Windows 10 Version 21H2 for ARM64-based Systems",
			},
			want: []string{"9000002"},
		},
		{
			name:    "bare cross-platform app KB kept across releases",
			fixture: "testdata/fixtures/microsoft-cross-product",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				kbs:     []string{"9000003"},
				release: "Windows 10 Version 21H2 for x64-based Systems",
			},
			want: []string{"9000003"},
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

			got, err := microsoft.FilterKBIDsByRelease(s.Storage(), tt.args.kbs, tt.args.release)
			switch {
			case tt.wantErr == nil && err != nil:
				t.Errorf("filterKBIDsByRelease() unexpected error: %v", err)
			case tt.wantErr != nil && err == nil:
				t.Errorf("filterKBIDsByRelease() expected error has not occurred")
			case tt.wantErr != nil && err != nil:
				if tt.wantErr.Error() != err.Error() {
					t.Errorf("filterKBIDsByRelease() error mismatch: want %v, got %v", tt.wantErr, err)
				}
			default:
				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Errorf("filterKBIDsByRelease() (-expected +got):\n%s", diff)
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
			name: "bare OS name matching release passes",
			args: args{
				product: "Windows 10 Version 21H2 for x64-based Systems",
				release: "Windows 10 Version 21H2 for x64-based Systems",
			},
			want: true,
		},
		{
			name: "bare OS name cross-product filtered",
			args: args{
				product: "Windows Server 2012 R2",
				release: "Windows 10 Version 21H2 for x64-based Systems",
			},
			want: false,
		},
		{
			name: "bare Windows 8.1 SKU matching release passes",
			args: args{
				product: "Windows 8.1 for x64-based Systems",
				release: "Windows 8.1 for x64-based Systems",
			},
			want: true,
		},
		{
			name: "bare Windows Server comma-separated SKU matches family token",
			args: args{
				product: "Windows Server, Version 1903 (Server Core installation)",
				release: "Windows Server, Version 1903 (Server Core installation)",
			},
			want: true,
		},
		{
			name: "bare Windows Server comma-separated SKU cross-product filtered",
			args: args{
				product: "Windows Server, Version 1903 (Server Core installation)",
				release: "Windows 11 Version 23H2 for x64-based Systems",
			},
			want: false,
		},
		{
			name: "bare Azure Stack HCI OS matching release passes",
			args: args{
				product: "Azure Stack HCI OS 22H2",
				release: "Azure Stack HCI OS 22H2",
			},
			want: true,
		},
		{
			name: "bare Azure Stack HCI OS cross-product filtered",
			args: args{
				product: "Azure Stack HCI OS 22H2",
				release: "Windows 11 Version 23H2 for x64-based Systems",
			},
			want: false,
		},
		{
			name: "bare cross-platform Edge product passes",
			args: args{
				product: "Microsoft Edge (Chromium-based)",
				release: "Windows 10 Version 1607 for x64-based Systems",
			},
			want: true,
		},
		{
			name: "bare cross-platform Office product passes",
			args: args{
				product: "Microsoft Office 2016 (32-bit edition)",
				release: "Windows 10 Version 21H2 for x64-based Systems",
			},
			want: true,
		},
		{
			name: "bare cross-platform .NET product passes",
			args: args{
				product: ".NET 6.0",
				release: "Windows 11 Version 23H2 for x64-based Systems",
			},
			want: true,
		},
		{
			name: "bare cross-platform Azure File Sync product passes",
			args: args{
				product: "Azure File Sync v18.0",
				release: "Windows Server 2022",
			},
			want: true,
		},
		{
			name: "bare Windows Admin Center (cross-OS tool) passes",
			args: args{
				product: "Windows Admin Center",
				release: "Windows Server 2022",
			},
			want: true,
		},
		{
			name: "bare Windows Malicious Software Removal Tool passes",
			args: args{
				product: "Windows Malicious Software Removal Tool 64-bit",
				release: "Windows 11 Version 23H2 for x64-based Systems",
			},
			want: true,
		},
		{
			name: "bare Windows Update Assistant passes",
			args: args{
				product: "Windows Update Assistant",
				release: "Windows 10 Version 22H2 for x64-based Systems",
			},
			want: true,
		},
		{
			name: "bare Windows Azure Pack passes",
			args: args{
				product: "Windows Azure Pack Rollup 13.1",
				release: "Windows Server 2022",
			},
			want: true,
		},
		{
			name: "bare microsoft-bulletin Windows XP product cross-product filtered",
			args: args{
				product: "Microsoft Windows XP Professional x64 Edition Service Pack 2",
				release: "Windows 7 for x64-based Systems Service Pack 1",
			},
			want: false,
		},
		{
			name: "bare microsoft-bulletin Windows XP product matching release passes",
			args: args{
				product: "Microsoft Windows XP Professional x64 Edition Service Pack 2",
				release: "Microsoft Windows XP Professional x64 Edition Service Pack 2",
			},
			want: true,
		},
		{
			name: "bare microsoft-bulletin Server 2003 SP2 cross-product filtered",
			args: args{
				product: "Microsoft Windows Server 2003 Service Pack 2",
				release: "Windows Server 2012 R2",
			},
			want: false,
		},
		{
			name: "bare microsoft-bulletin Server 2003 Itanium cross-product filtered",
			args: args{
				product: "Microsoft Windows Server 2003 for Itanium-based Systems Service Pack 2",
				release: "Windows 8.1 for x64-based Systems",
			},
			want: false,
		},
		{
			name: "bare microsoft-bulletin Windows 2000 cross-product filtered",
			args: args{
				product: "Microsoft Windows 2000 Service Pack 4",
				release: "Windows Server 2008 for x64-based Systems Service Pack 2",
			},
			want: false,
		},
		{
			name: "bare microsoft-bulletin Windows XP SP3 cross-product filtered",
			args: args{
				product: "Microsoft Windows XP Service Pack 3",
				release: "Windows Server 2008 R2 for x64-based Systems Service Pack 1",
			},
			want: false,
		},
		{
			name: "bare versionless Windows RT cross-product filtered",
			args: args{
				product: "Windows RT",
				release: "Windows 8.1 for x64-based Systems",
			},
			want: false,
		},
		{
			name: "bare versionless Windows RT matching release passes",
			args: args{
				product: "Windows RT",
				release: "Windows RT",
			},
			want: true,
		},
		{
			name: "bare versionless Windows Vista cross-product filtered",
			args: args{
				product: "Windows Vista",
				release: "Windows Server 2008 for x64-based Systems Service Pack 2",
			},
			want: false,
		},
		{
			name: "bare versionless Windows Vista matching release passes",
			args: args{
				product: "Windows Vista",
				release: "Windows Vista",
			},
			want: true,
		},
		{
			name: "bare Microsoft Office (cross-platform with Microsoft prefix) passes",
			args: args{
				product: "Microsoft Office 2019 (64-bit edition)",
				release: "Windows Server 2019",
			},
			want: true,
		},
		{
			name: "bare Microsoft SharePoint Server (cross-platform) passes",
			args: args{
				product: "Microsoft SharePoint Server 2019",
				release: "Windows Server 2022",
			},
			want: true,
		},
		{
			name: "bare Microsoft SQL Server (cross-platform) passes",
			args: args{
				product: "Microsoft SQL Server 2022 for x64-based Systems (GDR)",
				release: "Windows Server 2022",
			},
			want: true,
		},
		{
			name: "bare Microsoft Exchange Server (cross-platform) passes",
			args: args{
				product: "Microsoft Exchange Server 2019 Cumulative Update 14",
				release: "Windows Server 2022",
			},
			want: true,
		},
		{
			name: "bare Microsoft Dynamics (cross-platform) passes",
			args: args{
				product: "Microsoft Dynamics 365 Business Central 2024 Release Wave 2",
				release: "Windows Server 2022",
			},
			want: true,
		},
		{
			name: "bare Skype for Business (cross-platform) passes",
			args: args{
				product: "Skype for Business 2016 (64-bit)",
				release: "Windows 10 Version 22H2 for x64-based Systems",
			},
			want: true,
		},
		{
			name: "bare Windows Small Business Server cross-product filtered",
			args: args{
				product: "Windows Small Business Server 2003 R2",
				release: "Windows Server 2008 R2 for x64-based Systems Service Pack 1",
			},
			want: false,
		},
		{
			name: "bare Windows Home Server cross-product filtered",
			args: args{
				product: "Windows Home Server",
				release: "Windows Server 2012",
			},
			want: false,
		},
		{
			name: "bare microsoft-bulletin Windows Me cross-product filtered",
			args: args{
				product: "Microsoft Windows Me",
				release: "Windows 7 for x64-based Systems Service Pack 1",
			},
			want: false,
		},
		{
			name: "bare microsoft-bulletin Windows NT4 cross-product filtered",
			args: args{
				product: "Microsoft Windows NT4",
				release: "Windows 7 for x64-based Systems Service Pack 1",
			},
			want: false,
		},
		{
			name: "bare microsoft-bulletin Windows NT Server 4.0 cross-product filtered",
			args: args{
				product: "Microsoft Windows NT Server 4.0 Service Pack 6a",
				release: "Windows Server 2008 R2 for x64-based Systems Service Pack 1",
			},
			want: false,
		},
		{
			name: "bare Windows Services for UNIX cross-product filtered",
			args: args{
				product: "Microsoft Windows Services for UNIX 3.5",
				release: "Windows 7 for x64-based Systems Service Pack 1",
			},
			want: false,
		},
		{
			name: "bare microsoft-bulletin Windows 98 cross-product filtered",
			args: args{
				product: "Microsoft Windows 98 Second Edition",
				release: "Windows 7 for x64-based Systems Service Pack 1",
			},
			want: false,
		},
		{
			name: "bare Windows Media Player (cross-platform app) passes",
			args: args{
				product: "Windows Media Player 11",
				release: "Windows 7 for x64-based Systems Service Pack 1",
			},
			want: true,
		},
		{
			name: "bare Windows Messenger (legacy EOL, NOT in allowlist) cross-product filtered",
			args: args{
				product: "Windows Messenger 4.7",
				release: "Windows XP Service Pack 3",
			},
			want: false,
		},
		{
			name: "bare Microsoft Windows SharePoint Services (cross-platform app) passes",
			args: args{
				product: "Microsoft Windows SharePoint Services 3.0 Service Pack 2 (32-bit version)",
				release: "Windows Server 2008 R2 for x64-based Systems Service Pack 1",
			},
			want: true,
		},
		{
			name: "bare versionless Microsoft Windows XP cross-product filtered",
			args: args{
				product: "Microsoft Windows XP",
				release: "Windows 7 for x64-based Systems Service Pack 1",
			},
			want: false,
		},
		{
			name: "bare versionless Microsoft Windows Millennium Edition cross-product filtered",
			args: args{
				product: "Microsoft Windows Millennium Edition",
				release: "Windows 7 for x64-based Systems Service Pack 1",
			},
			want: false,
		},
		{
			name: "bare Internet Information Services (allowlisted server) passes",
			args: args{
				product: "Internet Information Services 5.0",
				release: "Windows Server 2008 for x64-based Systems Service Pack 2",
			},
			want: true,
		},
		{
			name: "bare ISA Server (allowlisted server) passes",
			args: args{
				product: "Microsoft Internet Security and Acceleration Server 2000",
				release: "Windows Server 2008 for x64-based Systems Service Pack 2",
			},
			want: true,
		},
		{
			name: "bare Works Suite (allowlisted productivity legacy) passes",
			args: args{
				product: "Microsoft Works Suite 2004",
				release: "Windows 7 for x64-based Systems Service Pack 1",
			},
			want: true,
		},
		{
			name: "bare 2007 Microsoft Office System (legacy naming) passes",
			args: args{
				product: "2007 Microsoft Office System Service Pack 3",
				release: "Windows 10 Version 22H2 for x64-based Systems",
			},
			want: true,
		},
		{
			name: "bare Internet Explorer (no Microsoft prefix) passes",
			args: args{
				product: "Internet Explorer 11",
				release: "Windows 10 Version 22H2 for x64-based Systems",
			},
			want: true,
		},
		{
			name: "bare Media Center TV Pack (NOT in allowlist) cross-product filtered",
			args: args{
				product: "Media Center TV Pack",
				release: "Windows 7 for x64-based Systems Service Pack 1",
			},
			want: false,
		},
		{
			name: "bare Microsoft Surface (NOT in allowlist) cross-product filtered",
			args: args{
				product: "Microsoft Surface Pro 4",
				release: "Windows 10 Version 22H2 for x64-based Systems",
			},
			want: false,
		},
		{
			name: "bare Microsoft Virtual PC (NOT in allowlist) cross-product filtered",
			args: args{
				product: "Microsoft Virtual PC 2007",
				release: "Windows 7 for x64-based Systems Service Pack 1",
			},
			want: false,
		},
		{
			name: "bare Windows Live OneCare (legacy EOL, NOT in allowlist) cross-product filtered",
			args: args{
				product: "Windows Live OneCare",
				release: "Windows 7 for x64-based Systems Service Pack 1",
			},
			want: false,
		},
		{
			name: "bare Windows Essentials (legacy EOL, NOT in allowlist) cross-product filtered",
			args: args{
				product: "Windows Essentials 2012",
				release: "Windows 7 for x64-based Systems Service Pack 1",
			},
			want: false,
		},
		{
			name: "bare Windows Journal Viewer (legacy EOL, NOT in allowlist) cross-product filtered",
			args: args{
				product: "Windows Journal Viewer",
				release: "Windows 7 for x64-based Systems Service Pack 1",
			},
			want: false,
		},
		{
			name: "bare Microsoft Windows Script Host (legacy, NOT in allowlist) cross-product filtered",
			args: args{
				product: "Microsoft Windows Script Host 5.5",
				release: "Windows 10 Version 22H2 for x64-based Systems",
			},
			want: false,
		},
		{
			name: "bare Visual Studio (allowlisted dev) passes",
			args: args{
				product: "Microsoft Visual Studio 2015 Update 3",
				release: "Windows 10 Version 22H2 for x64-based Systems",
			},
			want: true,
		},
		{
			name: "bare Forefront (allowlisted) passes",
			args: args{
				product: "Microsoft Forefront UAG 2010",
				release: "Windows Server 2008 R2 for x64-based Systems Service Pack 1",
			},
			want: true,
		},
		{
			name: "bare BizTalk (allowlisted) passes",
			args: args{
				product: "Microsoft BizTalk Server 2020",
				release: "Windows Server 2019",
			},
			want: true,
		},
		{
			name: "bare Outlook Express (legacy variant via Outlook prefix) passes",
			args: args{
				product: "Outlook Express 5.5",
				release: "Windows XP Service Pack 3",
			},
			want: true,
		},
		{
			name: "bare MSXML Core Services (allowlisted runtime) passes",
			args: args{
				product: "MSXML 4.0 Service Pack 2",
				release: "Windows 7 for x64-based Systems Service Pack 1",
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
		{
			name: "empty release passes bare product",
			args: args{
				product: "Windows Server 2012 R2",
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
