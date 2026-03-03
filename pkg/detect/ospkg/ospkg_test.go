package ospkg_test

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.etcd.io/bbolt"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	necTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion"
	necBinaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion/binary"
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
	"github.com/MaineK00n/vuls2/pkg/detect/ospkg"
	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"
	scanTypes "github.com/MaineK00n/vuls2/pkg/scan/types"
)

func TestDetect(t *testing.T) {
	type args struct {
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
			name:    "happy",
			fixture: "testdata/fixtures/alma-small",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				sr: scanTypes.ScanResult{
					Family:  ecosystemTypes.EcosystemTypeAlma,
					Release: "8.9",

					Kernel: scanTypes.Kernel{Release: "4.18.0-513.9.1.el8_9.x86_64"},
					OSPackages: []scanTypes.OSPackage{
						{
							Name:       "dnf",
							Version:    "4.7.0",
							Release:    "19.el8.alma",
							Arch:       "noarch",
							SrcName:    "dnf",
							SrcVersion: "4.7.0",
							SrcRelease: "19.el8.alma",
						},
						{
							Name:       "kernel",
							Version:    "4.18.0",
							Release:    "513.9.1.el8_9",
							Arch:       "x86_64",
							SrcName:    "kernel",
							SrcVersion: "4.18.0",
							SrcRelease: "513.9.1.el8_9",
						},
						{
							Name:       "kernel",
							Version:    "4.18.0",
							Release:    "513.11.1.el8_9",
							Arch:       "x86_64",
							SrcName:    "kernel",
							SrcVersion: "4.18.0",
							SrcRelease: "513.11.1.el8_9",
						},
					},
				},
				concurrency: 1,
			},
			want: map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection{
				"ALSA-2024:0113": {
					Ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:8", ecosystemTypes.EcosystemTypeAlma)),
					Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
						sourceTypes.AlmaErrata: {
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
															Name: "kernel",
															Architectures: []string{
																"aarch64",
																"ppc64le",
																"s390x",
																"x86_64",
															},
														},
													},
													Affected: &vcAffectedTypes.Affected{
														Type: vcAffectedRangeTypes.RangeTypeRPM,
														Range: []vcAffectedRangeTypes.Range{
															{LessThan: "0:4.18.0-513.11.1.el8_9"},
														},
														Fixed: []string{"0:4.18.0-513.11.1.el8_9"},
													},
												},
											},
											Accepts: criterionTypes.AcceptQueries{Version: []int{1}},
										},
										{
											Criterion: criterionTypes.Criterion{
												Type: criterionTypes.CriterionTypeVersion,
												Version: &vcTypes.Criterion{
													Vulnerable: true,
													FixStatus:  &vcFixStatusTypes.FixStatus{Class: vcFixStatusTypes.ClassFixed},
													Package: vcPackageTypes.Package{
														Type: vcPackageTypes.PackageTypeBinary,
														Binary: &vcBinaryPackageTypes.Package{
															Name: "kernel-debug",
															Architectures: []string{
																"aarch64",
																"ppc64le",
																"s390x",
																"x86_64",
															},
														},
													},
													Affected: &vcAffectedTypes.Affected{
														Type: vcAffectedRangeTypes.RangeTypeRPM,
														Range: []vcAffectedRangeTypes.Range{
															{LessThan: "0:4.18.0-513.11.1.el8_9"},
														},
														Fixed: []string{"0:4.18.0-513.11.1.el8_9"},
													},
												},
											},
											Accepts: criterionTypes.AcceptQueries{Version: []int{}},
										},
										{
											Criterion: criterionTypes.Criterion{
												Type: criterionTypes.CriterionTypeVersion,
												Version: &vcTypes.Criterion{
													Vulnerable: true,
													FixStatus:  &vcFixStatusTypes.FixStatus{Class: vcFixStatusTypes.ClassFixed},
													Package: vcPackageTypes.Package{
														Type: vcPackageTypes.PackageTypeBinary,
														Binary: &vcBinaryPackageTypes.Package{
															Name: "kernel-devel",
															Architectures: []string{
																"aarch64",
																"ppc64le",
																"s390x",
																"x86_64",
															},
														},
													},
													Affected: &vcAffectedTypes.Affected{
														Type: vcAffectedRangeTypes.RangeTypeRPM,
														Range: []vcAffectedRangeTypes.Range{
															{LessThan: "0:4.18.0-513.11.1.el8_9"},
														},
														Fixed: []string{"0:4.18.0-513.11.1.el8_9"},
													},
												},
											},
											Accepts: criterionTypes.AcceptQueries{Version: []int{}},
										},
										{
											Criterion: criterionTypes.Criterion{
												Type: criterionTypes.CriterionTypeVersion,
												Version: &vcTypes.Criterion{
													Vulnerable: true,
													FixStatus:  &vcFixStatusTypes.FixStatus{Class: vcFixStatusTypes.ClassFixed},
													Package: vcPackageTypes.Package{
														Type: vcPackageTypes.PackageTypeBinary,
														Binary: &vcBinaryPackageTypes.Package{
															Name: "kernel-doc",
															Architectures: []string{
																"noarch",
															},
														},
													},
													Affected: &vcAffectedTypes.Affected{
														Type: vcAffectedRangeTypes.RangeTypeRPM,
														Range: []vcAffectedRangeTypes.Range{
															{LessThan: "0:4.18.0-513.11.1.el8_9"},
														},
														Fixed: []string{"0:4.18.0-513.11.1.el8_9"},
													},
												},
											},
											Accepts: criterionTypes.AcceptQueries{Version: []int{}},
										},
										{
											Criterion: criterionTypes.Criterion{
												Type: criterionTypes.CriterionTypeVersion,
												Version: &vcTypes.Criterion{
													Vulnerable: true,
													FixStatus:  &vcFixStatusTypes.FixStatus{Class: vcFixStatusTypes.ClassFixed},
													Package: vcPackageTypes.Package{
														Type: vcPackageTypes.PackageTypeBinary,
														Binary: &vcBinaryPackageTypes.Package{
															Name: "kernel-modules",
															Architectures: []string{
																"aarch64",
																"ppc64le",
																"s390x",
																"x86_64",
															},
														},
													},
													Affected: &vcAffectedTypes.Affected{
														Type: vcAffectedRangeTypes.RangeTypeRPM,
														Range: []vcAffectedRangeTypes.Range{
															{LessThan: "0:4.18.0-513.11.1.el8_9"},
														},
														Fixed: []string{"0:4.18.0-513.11.1.el8_9"},
													},
												},
											},
											Accepts: criterionTypes.AcceptQueries{Version: []int{}},
										},
										{
											Criterion: criterionTypes.Criterion{
												Type: criterionTypes.CriterionTypeVersion,
												Version: &vcTypes.Criterion{
													Vulnerable: true,
													FixStatus:  &vcFixStatusTypes.FixStatus{Class: vcFixStatusTypes.ClassFixed},
													Package: vcPackageTypes.Package{
														Type: vcPackageTypes.PackageTypeBinary,
														Binary: &vcBinaryPackageTypes.Package{
															Name: "perf",
															Architectures: []string{
																"aarch64",
																"ppc64le",
																"s390x",
																"x86_64",
															},
														},
													},
													Affected: &vcAffectedTypes.Affected{
														Type: vcAffectedRangeTypes.RangeTypeRPM,
														Range: []vcAffectedRangeTypes.Range{
															{LessThan: "0:4.18.0-513.11.1.el8_9"},
														},
														Fixed: []string{"0:4.18.0-513.11.1.el8_9"},
													},
												},
											},
											Accepts: criterionTypes.AcceptQueries{Version: []int{}},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:    "redhat kernel with matching repository",
			fixture: "testdata/fixtures/redhat-kpatch-small",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				sr: scanTypes.ScanResult{
					Family:  ecosystemTypes.EcosystemTypeRedHat,
					Release: "9",
					Kernel: scanTypes.Kernel{Release: "5.14.0-70.13.1.el9_0.x86_64"},
					OSPackages: []scanTypes.OSPackage{
						{
							Name:       "kernel",
							Epoch:      new(0),
							Version:    "5.14.0",
							Release:    "70.13.1.el9_0",
							Arch:       "x86_64",
							SrcName:    "kernel",
							SrcEpoch:   new(0),
							SrcVersion: "5.14.0",
							SrcRelease: "70.13.1.el9_0",
							Repository: "rhel-9-for-x86_64-baseos-rpms",
						},
					},
				},
				concurrency: 1,
			},
			want: map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection{
				"RHSA-2022:5214": {
					Ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:9", ecosystemTypes.EcosystemTypeRedHat)),
					Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
						sourceTypes.RedHatOVALv2: {
							{
								Criteria: criteriaTypes.FilteredCriteria{
									Operator:     criteriaTypes.CriteriaOperatorTypeAND,
									Repositories: []string{"rhel-9-for-ppc64le-baseos-rpms", "rhel-9-for-x86_64-baseos-rpms"},
									Criterias: []criteriaTypes.FilteredCriteria{
										{
											Operator: criteriaTypes.CriteriaOperatorTypeOR,
											Criterias: []criteriaTypes.FilteredCriteria{
												{
													Operator: criteriaTypes.CriteriaOperatorTypeAND,
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
																			Name:          "kpatch-patch-5_14_0-70_13_1",
																			Architectures: []string{"ppc64le", "x86_64"},
																		},
																	},
																	Affected: &vcAffectedTypes.Affected{
																		Type:  vcAffectedRangeTypes.RangeTypeRPM,
																		Range: []vcAffectedRangeTypes.Range{{LessThan: "0:1-1.el9_0"}},
																		Fixed: []string{"0:1-1.el9_0"},
																	},
																},
															},
															Accepts: criterionTypes.AcceptQueries{Version: []int{}},
														},
													},
												},
											},
											Criterions: []criterionTypes.FilteredCriterion{
												{
													Criterion: criterionTypes.Criterion{
														Type: criterionTypes.CriterionTypeNoneExist,
														NoneExist: &necTypes.Criterion{
															Type:   necTypes.PackageTypeBinary,
															Binary: &necBinaryPackageTypes.Package{Name: "kpatch-patch-5_14_0-70_13_1"},
														},
													},
													Accepts: criterionTypes.AcceptQueries{NoneExist: true},
												},
											},
										},
									},
									Criterions: []criterionTypes.FilteredCriterion{
										{
											Criterion: criterionTypes.Criterion{
												Type: criterionTypes.CriterionTypeVersion,
												Version: &vcTypes.Criterion{
													Package: vcPackageTypes.Package{
														Type: vcPackageTypes.PackageTypeBinary,
														Binary: &vcBinaryPackageTypes.Package{
															Name:          "kernel",
															Architectures: []string{"ppc64le", "x86_64"},
														},
													},
													Affected: &vcAffectedTypes.Affected{
														Type:  vcAffectedRangeTypes.RangeTypeRPM,
														Range: []vcAffectedRangeTypes.Range{{Equal: "0:5.14.0-70.13.1.el9_0"}},
													},
												},
											},
											Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
										},
									},
								},
								Tag: segmentTypes.DetectionTag("rhel-9-including-unpatched"),
							},
						},
					},
				},
			},
		},
		{
			name:    "redhat kernel with non-matching repository",
			fixture: "testdata/fixtures/redhat-kpatch-small",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				sr: scanTypes.ScanResult{
					Family:  ecosystemTypes.EcosystemTypeRedHat,
					Release: "9",
					Kernel: scanTypes.Kernel{Release: "5.14.0-70.13.1.el9_0.x86_64"},
					OSPackages: []scanTypes.OSPackage{
						{
							Name:       "kernel",
							Epoch:      new(0),
							Version:    "5.14.0",
							Release:    "70.13.1.el9_0",
							Arch:       "x86_64",
							SrcName:    "kernel",
							SrcEpoch:   new(0),
							SrcVersion: "5.14.0",
							SrcRelease: "70.13.1.el9_0",
							Repository: "some-non-matching-repo",
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

			got, err := ospkg.Detect(s.Storage(), tt.args.sr, tt.args.concurrency)
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

func Test_convertVCQueryPackage(t *testing.T) {
	type args struct {
		family ecosystemTypes.Ecosystem
		p      scanTypes.OSPackage
	}
	tests := []struct {
		name    string
		args    args
		want    vcTypes.Query
		wantErr bool
	}{
		{
			name: "redhat binary only",
			args: args{
				family: ecosystemTypes.EcosystemTypeRedHat,
				p: scanTypes.OSPackage{
					Name:    "kernel",
					Epoch:   nil,
					Version: "5.14.0",
					Release: "70.13.1.el9_0",
					Arch:    "x86_64",
				},
			},
			want: vcTypes.Query{
				Binary: &vcTypes.QueryBinary{
					Family:  ecosystemTypes.EcosystemTypeRedHat,
					Name:    "kernel",
					Version: "5.14.0-70.13.1.el9_0",
					Arch:    "x86_64",
				},
			},
		},
		{
			name: "redhat binary + source name only",
			args: args{
				family: ecosystemTypes.EcosystemTypeRedHat,
				p: scanTypes.OSPackage{
					Name:    "kernel",
					Epoch:   nil,
					Version: "5.14.0",
					Release: "70.13.1.el9_0",
					Arch:    "x86_64",
					SrcName: "kernel",
				},
			},
			want: vcTypes.Query{
				Binary: &vcTypes.QueryBinary{
					Family:  ecosystemTypes.EcosystemTypeRedHat,
					Name:    "kernel",
					Version: "5.14.0-70.13.1.el9_0",
					Arch:    "x86_64",
				},
				Source: &vcTypes.QuerySource{
					Family: ecosystemTypes.EcosystemTypeRedHat,
					Name:   "kernel",
				},
			},
		},
		{
			name: "redhat binary + source",
			args: args{
				family: ecosystemTypes.EcosystemTypeRedHat,
				p: scanTypes.OSPackage{
					Name:       "kernel",
					Epoch:      nil,
					Version:    "5.14.0",
					Release:    "70.13.1.el9_0",
					Arch:       "x86_64",
					SrcName:    "kernel",
					SrcVersion: "5.14.0",
					SrcRelease: "70.13.1.el9_0",
				},
			},
			want: vcTypes.Query{
				Binary: &vcTypes.QueryBinary{
					Family:  ecosystemTypes.EcosystemTypeRedHat,
					Name:    "kernel",
					Version: "5.14.0-70.13.1.el9_0",
					Arch:    "x86_64",
				},
				Source: &vcTypes.QuerySource{
					Family:  ecosystemTypes.EcosystemTypeRedHat,
					Name:    "kernel",
					Version: "5.14.0-70.13.1.el9_0",
				},
			},
		},
		{
			name: "fedora modular package",
			args: args{
				family: ecosystemTypes.EcosystemTypeFedora,
				p: scanTypes.OSPackage{
					Name:            "community-mysql",
					Epoch:           new(0),
					Version:         "8.0.31",
					Release:         "1.module_f35+15642+4eed9dbd",
					Arch:            "x86_64",
					ModularityLabel: "mysql:8.0:3520221024193033:f27b74a8",
					SrcName:         "community-mysql",
					SrcEpoch:        new(0),
					SrcVersion:      "8.0.31",
					SrcRelease:      "1.module_f35+15642+4eed9dbd",
				},
			},
			want: vcTypes.Query{
				Binary: &vcTypes.QueryBinary{
					Family:  ecosystemTypes.EcosystemTypeFedora,
					Name:    "mysql:8.0::community-mysql",
					Version: "0:8.0.31-1.module_f35+15642+4eed9dbd",
					Arch:    "x86_64",
				},
				Source: &vcTypes.QuerySource{
					Family:  ecosystemTypes.EcosystemTypeFedora,
					Name:    "mysql:8.0::community-mysql",
					Version: "0:8.0.31-1.module_f35+15642+4eed9dbd",
				},
			},
		},
		{
			name: "debian binary + source",
			args: args{
				family: ecosystemTypes.EcosystemTypeDebian,
				p: scanTypes.OSPackage{
					Name:       "linux-image-6.1.0-18-amd64",
					Version:    "6.1.76-1",
					SrcName:    "linux-signed-amd64",
					SrcVersion: "6.1.76+1",
				},
			},
			want: vcTypes.Query{
				Binary: &vcTypes.QueryBinary{
					Family:  ecosystemTypes.EcosystemTypeDebian,
					Name:    "linux-image-6.1.0-18-amd64",
					Version: "6.1.76-1",
				},
				Source: &vcTypes.QuerySource{
					Family:  ecosystemTypes.EcosystemTypeDebian,
					Name:    "linux",
					Version: "6.1.76+1",
				},
			},
		},
		{
			name: "ubuntu binary + source",
			args: args{
				family: ecosystemTypes.EcosystemTypeUbuntu,
				p: scanTypes.OSPackage{
					Name:       "linux-image-5.15.0-107-generic",
					Version:    "5.15.0-107.117",
					SrcName:    "linux-signed",
					SrcVersion: "5.15.0-107.117",
				},
			},
			want: vcTypes.Query{
				Binary: &vcTypes.QueryBinary{
					Family:  ecosystemTypes.EcosystemTypeUbuntu,
					Name:    "linux-image-5.15.0-107-generic",
					Version: "5.15.0-107.117",
				},
				Source: &vcTypes.QuerySource{
					Family:  ecosystemTypes.EcosystemTypeUbuntu,
					Name:    "linux",
					Version: "5.15.0-107.117",
				},
			},
		},
		{
			name: "alpine binary + source",
			args: args{
				family: ecosystemTypes.EcosystemTypeAlpine,
				p: scanTypes.OSPackage{
					Name:       "ca-certificates-bundle",
					Version:    "20240226",
					Release:    "r0",
					Arch:       "x86_64",
					SrcName:    "ca-certificates",
					SrcVersion: "20240226",
					SrcRelease: "r0",
				},
			},
			want: vcTypes.Query{
				Binary: &vcTypes.QueryBinary{
					Family:  ecosystemTypes.EcosystemTypeAlpine,
					Name:    "ca-certificates-bundle",
					Version: "20240226-r0",
					Arch:    "x86_64",
				},
				Source: &vcTypes.QuerySource{
					Family:  ecosystemTypes.EcosystemTypeAlpine,
					Name:    "ca-certificates",
					Version: "20240226-r0",
				},
			},
		},
		{
			name: "redhat with repository",
			args: args{
				family: ecosystemTypes.EcosystemTypeRedHat,
				p: scanTypes.OSPackage{
					Name:       "kernel",
					Version:    "5.14.0",
					Release:    "70.13.1.el9_0",
					Arch:       "x86_64",
					SrcName:    "kernel",
					SrcVersion: "5.14.0",
					SrcRelease: "70.13.1.el9_0",
					Repository: "rhel-9-for-x86_64-baseos-rpms",
				},
			},
			want: vcTypes.Query{
				Binary: &vcTypes.QueryBinary{
					Family:       ecosystemTypes.EcosystemTypeRedHat,
					Name:         "kernel",
					Version:      "5.14.0-70.13.1.el9_0",
					Arch:         "x86_64",
					Repositories: []string{"rhel-9-for-x86_64-baseos-rpms"},
				},
				Source: &vcTypes.QuerySource{
					Family:       ecosystemTypes.EcosystemTypeRedHat,
					Name:         "kernel",
					Version:      "5.14.0-70.13.1.el9_0",
					Repositories: []string{"rhel-9-for-x86_64-baseos-rpms"},
				},
			},
		},
		{
			name: "redhat without repository",
			args: args{
				family: ecosystemTypes.EcosystemTypeRedHat,
				p: scanTypes.OSPackage{
					Name:       "kernel",
					Version:    "5.14.0",
					Release:    "70.13.1.el9_0",
					Arch:       "x86_64",
					SrcName:    "kernel",
					SrcVersion: "5.14.0",
					SrcRelease: "70.13.1.el9_0",
				},
			},
			want: vcTypes.Query{
				Binary: &vcTypes.QueryBinary{
					Family:  ecosystemTypes.EcosystemTypeRedHat,
					Name:    "kernel",
					Version: "5.14.0-70.13.1.el9_0",
					Arch:    "x86_64",
				},
				Source: &vcTypes.QuerySource{
					Family:  ecosystemTypes.EcosystemTypeRedHat,
					Name:    "kernel",
					Version: "5.14.0-70.13.1.el9_0",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ospkg.ConvertVCQueryPackage(tt.args.family, tt.args.p)
			if (err != nil) != tt.wantErr {
				t.Errorf("convertVCQueryPackage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("convertVCQueryPackage() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func Test_rename(t *testing.T) {
	type args struct {
		family ecosystemTypes.Ecosystem
		name   string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "redhat kernel",
			args: args{
				family: ecosystemTypes.EcosystemTypeRedHat,
				name:   "kernel",
			},
			want: "kernel",
		},
		{
			name: "debian apt",
			args: args{
				family: ecosystemTypes.EcosystemTypeDebian,
				name:   "apt",
			},
			want: "apt",
		},
		{
			name: "debian linux-signed-amd64",
			args: args{
				family: ecosystemTypes.EcosystemTypeDebian,
				name:   "linux-signed-amd64",
			},
			want: "linux",
		},
		{
			name: "ubuntu apt",
			args: args{
				family: ecosystemTypes.EcosystemTypeUbuntu,
				name:   "apt",
			},
			want: "apt",
		},
		{
			name: "ubuntu linux-signed",
			args: args{
				family: ecosystemTypes.EcosystemTypeUbuntu,
				name:   "linux-signed",
			},
			want: "linux",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ospkg.Rename(tt.args.family, tt.args.name); got != tt.want {
				t.Errorf("rename() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_isKernelPackage(t *testing.T) {
	type args struct {
		family ecosystemTypes.Ecosystem
		name   string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "redhat kernel",
			args: args{
				family: ecosystemTypes.EcosystemTypeRedHat,
				name:   "kernel",
			},
			want: false,
		},
		{
			name: "debian apt",
			args: args{
				family: ecosystemTypes.EcosystemTypeDebian,
				name:   "apt",
			},
			want: false,
		},
		{
			name: "debian linux-signed-amd64",
			args: args{
				family: ecosystemTypes.EcosystemTypeDebian,
				name:   "linux-signed-amd64",
			},
			want: true,
		},
		{
			name: "ubuntu apt",
			args: args{
				family: ecosystemTypes.EcosystemTypeUbuntu,
				name:   "apt",
			},
			want: false,
		},
		{
			name: "ubuntu linux-signed",
			args: args{
				family: ecosystemTypes.EcosystemTypeUbuntu,
				name:   "linux-signed",
			},
			want: true,
		},
		{
			name: "ubuntu linux-aws-6.5",
			args: args{
				family: ecosystemTypes.EcosystemTypeUbuntu,
				name:   "linux-aws-6.5",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ospkg.IsKernelPackage(tt.args.family, tt.args.name); got != tt.want {
				t.Errorf("isKernelPackage() = %v, want %v", got, tt.want)
			}
		})
	}
}
