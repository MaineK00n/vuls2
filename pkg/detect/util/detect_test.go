package util_test

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/pkg/errors"
	"go.etcd.io/bbolt"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	necriterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion"
	necBinaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion/binary"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	vcAffectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	vcAffectedRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	vcFixStatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	vcPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	vcBinaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/db/session"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/session/types"
	"github.com/MaineK00n/vuls2/pkg/detect/internal/test"
	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"
	"github.com/MaineK00n/vuls2/pkg/detect/util"
)

func TestDetect(t *testing.T) {
	type args struct {
		ecosystem       ecosystemTypes.Ecosystem
		queries         []string
		createRequestFn func(rootID dataTypes.RootID, queries []string) util.Request
		concurrency     int
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
			name:    "ecosystem not found",
			fixture: "testdata/fixtures/alma-small",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				ecosystem: ecosystemTypes.Ecosystem("ECOSYSTEM-NOT-EXIST"),
				queries:   []string{"apt"},
				createRequestFn: func(rootID dataTypes.RootID, queries []string) util.Request {
					return util.Request{}
				},
				concurrency: 1,
			},
			wantErr: errors.Wrap(errors.Wrapf(dbTypes.ErrNotFoundEcosystem, "%q not found", ecosystemTypes.Ecosystem("ECOSYSTEM-NOT-EXIST")), "get index"),
		},
		{
			name:    "index not found",
			fixture: "testdata/fixtures/alma-small",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:8", ecosystemTypes.EcosystemTypeAlma)),
				queries:   []string{"PKG-NOT-EXIST"},
				createRequestFn: func(rootID dataTypes.RootID, queries []string) util.Request {
					return util.Request{}
				},
				concurrency: 1,
			},
			want: map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection{},
		},
		{
			name:    "detection not found (maybe DB broken or createRequestFn bug)",
			fixture: "testdata/fixtures/alma-small",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:8", ecosystemTypes.EcosystemTypeAlma)),
				queries:   []string{"mariadb-devel:10.3::Judy"},
				createRequestFn: func(rootID dataTypes.RootID, queries []string) util.Request {
					return util.Request{RootID: dataTypes.RootID("ROOTID-NOT-EXIST")}
				},
				concurrency: 1,
			},
			wantErr: errors.Wrap(errors.Wrap(errors.Wrapf(dbTypes.ErrNotFoundDetection, "%q not found", "alma:8 -> detection -> ROOTID-NOT-EXIST"), "get detection"), "err in goroutine"),
		},
		{
			name:    "happy",
			fixture: "testdata/fixtures/alma-small",
			config: session.Config{
				Type:    "boltdb",
				Path:    filepath.Join(t.TempDir(), "vuls.db"),
				Options: session.StorageOptions{BoltDB: bbolt.DefaultOptions},
			},
			args: args{
				ecosystem: ecosystemTypes.Ecosystem(fmt.Sprintf("%s:8", ecosystemTypes.EcosystemTypeAlma)),
				queries:   []string{"mariadb-devel:10.3::Judy"},
				createRequestFn: func(rootID dataTypes.RootID, queries []string) util.Request {
					switch rootID {
					case dataTypes.RootID("ALSA-2019:3708"):
						return util.Request{
							RootID: rootID,
							Query: criterionTypes.Query{
								Version: []vcTypes.Query{
									{
										Binary: &vcTypes.QueryBinary{
											Family:  ecosystemTypes.EcosystemTypeAlma,
											Name:    "mariadb-devel:10.3::Judy",
											Version: "1.0.5-18.module_el8.6.0+2867+72759d2f",
											Arch:    "i686",
										},
									},
								},
							},
							Indexes: []int{42},
						}
					default:
						return util.Request{}
					}
				},
				concurrency: 1,
			},
			want: map[dataTypes.RootID]detectTypes.VulnerabilityDataDetection{
				dataTypes.RootID("ALSA-2019:3708"): {
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
													Package: vcPackageTypes.Package{
														Type: vcPackageTypes.PackageTypeBinary,
														Binary: &vcBinaryPackageTypes.Package{
															Name:          "mariadb-devel:10.3::Judy",
															Architectures: []string{"i686"},
														},
													},
												},
											},
											Accepts: criterionTypes.AcceptQueries{Version: []int{42}},
										},
									},
								},
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

			got, err := util.Detect(s.Storage(), tt.args.ecosystem, tt.args.queries, tt.args.createRequestFn, tt.args.concurrency)
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

func Test_replaceIndexes(t *testing.T) {
	type args struct {
		fca     criteriaTypes.FilteredCriteria
		indexes []int
	}
	tests := []struct {
		name    string
		args    args
		want    criteriaTypes.FilteredCriteria
		wantErr bool
	}{
		{
			name: "version criterions",
			args: args{
				fca: criteriaTypes.FilteredCriteria{
					Operator: criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: []criterionTypes.FilteredCriterion{
						{
							Criterion: criterionTypes.Criterion{
								Type: criterionTypes.CriterionTypeVersion,
								Version: &vcTypes.Criterion{
									Package: vcPackageTypes.Package{
										Type:   vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{Name: "pkg0"},
									},
								},
							},
						},
						{
							Criterion: criterionTypes.Criterion{
								Type: criterionTypes.CriterionTypeVersion,
								Version: &vcTypes.Criterion{
									Package: vcPackageTypes.Package{
										Type:   vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{Name: "pkg1"},
									},
								},
							},
							Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
						},
					},
				},
				indexes: []int{1, 0},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterions: []criterionTypes.FilteredCriterion{
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &vcTypes.Criterion{
								Package: vcPackageTypes.Package{
									Type:   vcPackageTypes.PackageTypeBinary,
									Binary: &vcBinaryPackageTypes.Package{Name: "pkg0"},
								},
							},
						},
						Accepts: criterionTypes.AcceptQueries{Version: []int{}},
					},
					{
						Criterion: criterionTypes.Criterion{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &vcTypes.Criterion{
								Package: vcPackageTypes.Package{
									Type:   vcPackageTypes.PackageTypeBinary,
									Binary: &vcBinaryPackageTypes.Package{Name: "pkg1"},
								},
							},
						},
						Accepts: criterionTypes.AcceptQueries{Version: []int{1}},
					},
				},
			},
		},
		{
			name: "version criteria",
			args: args{
				fca: criteriaTypes.FilteredCriteria{
					Operator: criteriaTypes.CriteriaOperatorTypeOR,
					Criterias: []criteriaTypes.FilteredCriteria{
						{
							Operator: criteriaTypes.CriteriaOperatorTypeAND,
							Criterias: []criteriaTypes.FilteredCriteria{
								{
									Operator: criteriaTypes.CriteriaOperatorTypeOR,
									Criterions: []criterionTypes.FilteredCriterion{
										{
											Criterion: criterionTypes.Criterion{
												Type: criterionTypes.CriterionTypeVersion,
												Version: &vcTypes.Criterion{
													Package: vcPackageTypes.Package{
														Type:   vcPackageTypes.PackageTypeBinary,
														Binary: &vcBinaryPackageTypes.Package{Name: "pkg3"},
													},
												},
											},
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
												Type:   vcPackageTypes.PackageTypeBinary,
												Binary: &vcBinaryPackageTypes.Package{Name: "pkg2"},
											},
										},
									},
								},
							},
						},
						{
							Operator: criteriaTypes.CriteriaOperatorTypeAND,
							Criterias: []criteriaTypes.FilteredCriteria{
								{
									Operator: criteriaTypes.CriteriaOperatorTypeOR,
									Criterions: []criterionTypes.FilteredCriterion{
										{
											Criterion: criterionTypes.Criterion{
												Type: criterionTypes.CriterionTypeVersion,
												Version: &vcTypes.Criterion{
													Package: vcPackageTypes.Package{
														Type:   vcPackageTypes.PackageTypeBinary,
														Binary: &vcBinaryPackageTypes.Package{Name: "pkg1"},
													},
												},
											},
											Accepts: criterionTypes.AcceptQueries{Version: []int{1}},
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
												Type:   vcPackageTypes.PackageTypeBinary,
												Binary: &vcBinaryPackageTypes.Package{Name: "pkg2"},
											},
										},
									},
								},
							},
						},
						{
							Operator: criteriaTypes.CriteriaOperatorTypeAND,
							Criterias: []criteriaTypes.FilteredCriteria{
								{
									Operator: criteriaTypes.CriteriaOperatorTypeOR,
									Criterions: []criterionTypes.FilteredCriterion{
										{
											Criterion: criterionTypes.Criterion{
												Type: criterionTypes.CriterionTypeVersion,
												Version: &vcTypes.Criterion{
													Package: vcPackageTypes.Package{
														Type:   vcPackageTypes.PackageTypeBinary,
														Binary: &vcBinaryPackageTypes.Package{Name: "pkg0"},
													},
												},
											},
											Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
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
												Type:   vcPackageTypes.PackageTypeBinary,
												Binary: &vcBinaryPackageTypes.Package{Name: "pkg1"},
											},
										},
									},
									Accepts: criterionTypes.AcceptQueries{Version: []int{1}},
								},
							},
						},
					},
				},
				indexes: []int{3, 2, 1, 0},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeOR,
				Criterias: []criteriaTypes.FilteredCriteria{
					{
						Operator: criteriaTypes.CriteriaOperatorTypeAND,
						Criterias: []criteriaTypes.FilteredCriteria{
							{
								Operator: criteriaTypes.CriteriaOperatorTypeOR,
								Criterions: []criterionTypes.FilteredCriterion{
									{
										Criterion: criterionTypes.Criterion{
											Type: criterionTypes.CriterionTypeVersion,
											Version: &vcTypes.Criterion{
												Package: vcPackageTypes.Package{
													Type:   vcPackageTypes.PackageTypeBinary,
													Binary: &vcBinaryPackageTypes.Package{Name: "pkg3"},
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
									Type: criterionTypes.CriterionTypeVersion,
									Version: &vcTypes.Criterion{
										Package: vcPackageTypes.Package{
											Type:   vcPackageTypes.PackageTypeBinary,
											Binary: &vcBinaryPackageTypes.Package{Name: "pkg2"},
										},
									},
								},
								Accepts: criterionTypes.AcceptQueries{Version: []int{}},
							},
						},
					},
					{
						Operator: criteriaTypes.CriteriaOperatorTypeAND,
						Criterias: []criteriaTypes.FilteredCriteria{
							{
								Operator: criteriaTypes.CriteriaOperatorTypeOR,
								Criterions: []criterionTypes.FilteredCriterion{
									{
										Criterion: criterionTypes.Criterion{
											Type: criterionTypes.CriterionTypeVersion,
											Version: &vcTypes.Criterion{
												Package: vcPackageTypes.Package{
													Type:   vcPackageTypes.PackageTypeBinary,
													Binary: &vcBinaryPackageTypes.Package{Name: "pkg1"},
												},
											},
										},
										Accepts: criterionTypes.AcceptQueries{Version: []int{2}},
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
											Type:   vcPackageTypes.PackageTypeBinary,
											Binary: &vcBinaryPackageTypes.Package{Name: "pkg2"},
										},
									},
								},
								Accepts: criterionTypes.AcceptQueries{Version: []int{}},
							},
						},
					},
					{
						Operator: criteriaTypes.CriteriaOperatorTypeAND,
						Criterias: []criteriaTypes.FilteredCriteria{
							{
								Operator: criteriaTypes.CriteriaOperatorTypeOR,
								Criterions: []criterionTypes.FilteredCriterion{
									{
										Criterion: criterionTypes.Criterion{
											Type: criterionTypes.CriterionTypeVersion,
											Version: &vcTypes.Criterion{
												Package: vcPackageTypes.Package{
													Type:   vcPackageTypes.PackageTypeBinary,
													Binary: &vcBinaryPackageTypes.Package{Name: "pkg0"},
												},
											},
										},
										Accepts: criterionTypes.AcceptQueries{Version: []int{3}},
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
											Type:   vcPackageTypes.PackageTypeBinary,
											Binary: &vcBinaryPackageTypes.Package{Name: "pkg1"},
										},
									},
								},
								Accepts: criterionTypes.AcceptQueries{Version: []int{2}},
							},
						},
					},
				},
			},
		},
		{
			name: "repositories preserved",
			args: args{
				fca: criteriaTypes.FilteredCriteria{
					Operator:     criteriaTypes.CriteriaOperatorTypeOR,
					Repositories: []string{"rhel-9-for-x86_64-baseos-rpms", "rhel-9-for-x86_64-appstream-rpms"},
					Criterias: []criteriaTypes.FilteredCriteria{
						{
							Operator:     criteriaTypes.CriteriaOperatorTypeAND,
							Repositories: []string{"rhel-9-for-x86_64-baseos-rpms"},
							Criterions: []criterionTypes.FilteredCriterion{
								{
									Criterion: criterionTypes.Criterion{
										Type: criterionTypes.CriterionTypeVersion,
										Version: &vcTypes.Criterion{
											Package: vcPackageTypes.Package{
												Type:   vcPackageTypes.PackageTypeBinary,
												Binary: &vcBinaryPackageTypes.Package{Name: "pkg0"},
											},
										},
									},
									Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
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
										Type:   vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{Name: "pkg1"},
									},
								},
							},
							Accepts: criterionTypes.AcceptQueries{Version: []int{1}},
						},
					},
				},
				indexes: []int{10, 20},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator:     criteriaTypes.CriteriaOperatorTypeOR,
				Repositories: []string{"rhel-9-for-x86_64-baseos-rpms", "rhel-9-for-x86_64-appstream-rpms"},
				Criterias: []criteriaTypes.FilteredCriteria{
					{
						Operator:     criteriaTypes.CriteriaOperatorTypeAND,
						Repositories: []string{"rhel-9-for-x86_64-baseos-rpms"},
						Criterions: []criterionTypes.FilteredCriterion{
							{
								Criterion: criterionTypes.Criterion{
									Type: criterionTypes.CriterionTypeVersion,
									Version: &vcTypes.Criterion{
										Package: vcPackageTypes.Package{
											Type:   vcPackageTypes.PackageTypeBinary,
											Binary: &vcBinaryPackageTypes.Package{Name: "pkg0"},
										},
									},
								},
								Accepts: criterionTypes.AcceptQueries{Version: []int{10}},
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
									Type:   vcPackageTypes.PackageTypeBinary,
									Binary: &vcBinaryPackageTypes.Package{Name: "pkg1"},
								},
							},
						},
						Accepts: criterionTypes.AcceptQueries{Version: []int{20}},
					},
				},
			},
		},
		{
			name: "none-exist",
			args: args{
				fca: criteriaTypes.FilteredCriteria{
					Operator: criteriaTypes.CriteriaOperatorTypeAND,
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
													FixStatus: &vcFixStatusTypes.FixStatus{
														Class: vcFixStatusTypes.ClassFixed,
													},
													Package: vcPackageTypes.Package{
														Type: vcPackageTypes.PackageTypeBinary,
														Binary: &vcBinaryPackageTypes.Package{
															Name: "kpatch-patch-3_10_0-1062_1_1",
														},
													},
													Affected: &vcAffectedTypes.Affected{
														Type:  vcAffectedRangeTypes.RangeTypeRPM,
														Range: []vcAffectedRangeTypes.Range{{LessThan: "0:1-1.el7"}},
														Fixed: []string{"0:1-1.el7"},
													},
												},
											},
										},
									},
								},
							},
							Criterions: []criterionTypes.FilteredCriterion{
								{
									Criterion: criterionTypes.Criterion{
										Type: criterionTypes.CriterionTypeNoneExist,
										NoneExist: &necriterionTypes.Criterion{
											Type: necriterionTypes.PackageTypeBinary,
											Binary: &necBinaryPackageTypes.Package{
												Name: "kpatch-patch-3_10_0-1062_1_1",
											},
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
									Vulnerable: false,
									Package: vcPackageTypes.Package{
										Type: vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{
											Name: "kernel",
										},
									},
									Affected: &vcAffectedTypes.Affected{
										Type:  vcAffectedRangeTypes.RangeTypeRPM,
										Range: []vcAffectedRangeTypes.Range{{Equal: "0:3.10.0-1062.1.1.el7"}},
									},
								},
							},
							Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
						},
					},
				},
				indexes: []int{42},
			},
			want: criteriaTypes.FilteredCriteria{
				Operator: criteriaTypes.CriteriaOperatorTypeAND,
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
												FixStatus: &vcFixStatusTypes.FixStatus{
													Class: vcFixStatusTypes.ClassFixed,
												},
												Package: vcPackageTypes.Package{
													Type: vcPackageTypes.PackageTypeBinary,
													Binary: &vcBinaryPackageTypes.Package{
														Name: "kpatch-patch-3_10_0-1062_1_1",
													},
												},
												Affected: &vcAffectedTypes.Affected{
													Type:  vcAffectedRangeTypes.RangeTypeRPM,
													Range: []vcAffectedRangeTypes.Range{{LessThan: "0:1-1.el7"}},
													Fixed: []string{"0:1-1.el7"},
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
									NoneExist: &necriterionTypes.Criterion{
										Type: necriterionTypes.PackageTypeBinary,
										Binary: &necBinaryPackageTypes.Package{
											Name: "kpatch-patch-3_10_0-1062_1_1",
										},
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
								Vulnerable: false,
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeBinary,
									Binary: &vcBinaryPackageTypes.Package{
										Name: "kernel",
									},
								},
								Affected: &vcAffectedTypes.Affected{
									Type:  vcAffectedRangeTypes.RangeTypeRPM,
									Range: []vcAffectedRangeTypes.Range{{Equal: "0:3.10.0-1062.1.1.el7"}},
								},
							},
						},
						Accepts: criterionTypes.AcceptQueries{Version: []int{42}},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := util.ReplaceIndexes(tt.args.fca, tt.args.indexes)
			if (err != nil) != tt.wantErr {
				t.Errorf("replaceIndexes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("replaceIndexes() (-expected +got):\n%s", diff)
			}
		})
	}
}
