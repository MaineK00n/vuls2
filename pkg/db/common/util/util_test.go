package util_test

import (
	"reflect"
	"testing"

	"github.com/google/go-cmp/cmp"

	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	necTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion"
	necBinaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion/binary"
	necSourcePackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion/source"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	vcAffectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	vcAffectedRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	vcFixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	vcPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	vcBinaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	vcCPEPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/cpe"
	vcSourcePackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/source"
	"github.com/MaineK00n/vuls2/pkg/db/common/util"
)

func TestReplaceRepositories(t *testing.T) {
	type args struct {
		conds []conditionTypes.Condition
		repom map[string]string
	}
	tests := []struct {
		name      string
		args      args
		wantConds []conditionTypes.Condition
		wantRepom map[string]string
		wantErr   bool
	}{
		{
			name: "repom empty",
			args: args{
				conds: []conditionTypes.Condition{{
					Criteria: criteriaTypes.Criteria{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.Criterion{
							{
								Type: criterionTypes.CriterionTypeVersion,
								Version: &vcTypes.Criterion{
									Vulnerable: true,
									FixStatus:  &vcFixstatusTypes.FixStatus{Class: vcFixstatusTypes.ClassFixed},
									Package: vcPackageTypes.Package{
										Type: vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{
											Name:          "package",
											Architectures: []string{"x86_64", "aarch64"},
											Repositories:  []string{"repository1", "repository3"},
										},
									},
									Affected: &vcAffectedTypes.Affected{
										Type: vcAffectedRangeTypes.RangeTypeVersion,
										Range: []vcAffectedRangeTypes.Range{{
											LessThan: "0.0.1",
										}},
										Fixed: []string{"0.0.1"},
									},
								},
							},
							{
								Type: criterionTypes.CriterionTypeVersion,
								Version: &vcTypes.Criterion{
									Vulnerable: true,
									FixStatus:  &vcFixstatusTypes.FixStatus{Class: vcFixstatusTypes.ClassFixed},
									Package: vcPackageTypes.Package{
										Type: vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{
											Name:          "package",
											Architectures: []string{"x86_64", "aarch64"},
											Repositories:  []string{"repository2"},
										},
									},
									Affected: &vcAffectedTypes.Affected{
										Type: vcAffectedRangeTypes.RangeTypeVersion,
										Range: []vcAffectedRangeTypes.Range{{
											LessThan: "0.0.0-1",
										}},
										Fixed: []string{"0.0.0-1"},
									},
								},
							},
						},
					},
				}},
				repom: make(map[string]string),
			},
			wantConds: []conditionTypes.Condition{{
				Criteria: criteriaTypes.Criteria{
					Operator: criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: []criterionTypes.Criterion{
						{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &vcTypes.Criterion{
								Vulnerable: true,
								FixStatus:  &vcFixstatusTypes.FixStatus{Class: vcFixstatusTypes.ClassFixed},
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeBinary,
									Binary: &vcBinaryPackageTypes.Package{
										Name:          "package",
										Architectures: []string{"x86_64", "aarch64"},
										Repositories:  []string{"0", "1"},
									},
								},
								Affected: &vcAffectedTypes.Affected{
									Type: vcAffectedRangeTypes.RangeTypeVersion,
									Range: []vcAffectedRangeTypes.Range{{
										LessThan: "0.0.1",
									}},
									Fixed: []string{"0.0.1"},
								},
							},
						},
						{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &vcTypes.Criterion{
								Vulnerable: true,
								FixStatus:  &vcFixstatusTypes.FixStatus{Class: vcFixstatusTypes.ClassFixed},
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeBinary,
									Binary: &vcBinaryPackageTypes.Package{
										Name:          "package",
										Architectures: []string{"x86_64", "aarch64"},
										Repositories:  []string{"2"},
									},
								},
								Affected: &vcAffectedTypes.Affected{
									Type: vcAffectedRangeTypes.RangeTypeVersion,
									Range: []vcAffectedRangeTypes.Range{{
										LessThan: "0.0.0-1",
									}},
									Fixed: []string{"0.0.0-1"},
								},
							},
						},
					},
				},
			}},
			wantRepom: map[string]string{
				"repository1": "0",
				"repository2": "2",
				"repository3": "1",
			},
		},
		{
			name: "repom filled",
			args: args{
				conds: []conditionTypes.Condition{{
					Criteria: criteriaTypes.Criteria{
						Operator: criteriaTypes.CriteriaOperatorTypeOR,
						Criterions: []criterionTypes.Criterion{
							{
								Type: criterionTypes.CriterionTypeVersion,
								Version: &vcTypes.Criterion{
									Vulnerable: true,
									FixStatus:  &vcFixstatusTypes.FixStatus{Class: vcFixstatusTypes.ClassFixed},
									Package: vcPackageTypes.Package{
										Type: vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{
											Name:          "package",
											Architectures: []string{"x86_64", "aarch64"},
											Repositories:  []string{"repository1", "repository3"},
										},
									},
									Affected: &vcAffectedTypes.Affected{
										Type: vcAffectedRangeTypes.RangeTypeVersion,
										Range: []vcAffectedRangeTypes.Range{{
											LessThan: "0.0.1",
										}},
										Fixed: []string{"0.0.1"},
									},
								},
							},
							{
								Type: criterionTypes.CriterionTypeVersion,
								Version: &vcTypes.Criterion{
									Vulnerable: true,
									FixStatus:  &vcFixstatusTypes.FixStatus{Class: vcFixstatusTypes.ClassFixed},
									Package: vcPackageTypes.Package{
										Type: vcPackageTypes.PackageTypeBinary,
										Binary: &vcBinaryPackageTypes.Package{
											Name:          "package",
											Architectures: []string{"x86_64", "aarch64"},
											Repositories:  []string{"repository2"},
										},
									},
									Affected: &vcAffectedTypes.Affected{
										Type: vcAffectedRangeTypes.RangeTypeVersion,
										Range: []vcAffectedRangeTypes.Range{{
											LessThan: "0.0.0-1",
										}},
										Fixed: []string{"0.0.0-1"},
									},
								},
							},
						},
					},
				}},
				repom: map[string]string{
					"repository0": "0",
					"repository2": "1",
				},
			},
			wantConds: []conditionTypes.Condition{{
				Criteria: criteriaTypes.Criteria{
					Operator: criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: []criterionTypes.Criterion{
						{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &vcTypes.Criterion{
								Vulnerable: true,
								FixStatus:  &vcFixstatusTypes.FixStatus{Class: vcFixstatusTypes.ClassFixed},
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeBinary,
									Binary: &vcBinaryPackageTypes.Package{
										Name:          "package",
										Architectures: []string{"x86_64", "aarch64"},
										Repositories:  []string{"2", "3"},
									},
								},
								Affected: &vcAffectedTypes.Affected{
									Type: vcAffectedRangeTypes.RangeTypeVersion,
									Range: []vcAffectedRangeTypes.Range{{
										LessThan: "0.0.1",
									}},
									Fixed: []string{"0.0.1"},
								},
							},
						},
						{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &vcTypes.Criterion{
								Vulnerable: true,
								FixStatus:  &vcFixstatusTypes.FixStatus{Class: vcFixstatusTypes.ClassFixed},
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeBinary,
									Binary: &vcBinaryPackageTypes.Package{
										Name:          "package",
										Architectures: []string{"x86_64", "aarch64"},
										Repositories:  []string{"1"},
									},
								},
								Affected: &vcAffectedTypes.Affected{
									Type: vcAffectedRangeTypes.RangeTypeVersion,
									Range: []vcAffectedRangeTypes.Range{{
										LessThan: "0.0.0-1",
									}},
									Fixed: []string{"0.0.0-1"},
								},
							},
						},
					},
				},
			}},
			wantRepom: map[string]string{
				"repository0": "0",
				"repository1": "2",
				"repository2": "1",
				"repository3": "3",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := util.ReplaceRepositories(tt.args.conds, tt.args.repom); (err != nil) != tt.wantErr {
				t.Errorf("ReplaceRepositories() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if diff := cmp.Diff(tt.args.conds, tt.wantConds); diff != "" {
				t.Errorf("ReplaceRepositories() conditions (-expected +got):\n%s", diff)
			}

			if diff := cmp.Diff(tt.args.repom, tt.wantRepom); diff != "" {
				t.Errorf("ReplaceRepositories() repom (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestCollectPkgName(t *testing.T) {
	type args struct {
		conds []conditionTypes.Condition
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				conds: []conditionTypes.Condition{
					{
						Criteria: criteriaTypes.Criteria{
							Operator: criteriaTypes.CriteriaOperatorTypeOR,
							Criterias: []criteriaTypes.Criteria{
								{
									Operator: criteriaTypes.CriteriaOperatorTypeAND,
									Criterions: []criterionTypes.Criterion{
										{
											Type: criterionTypes.CriterionTypeVersion,
											Version: &vcTypes.Criterion{
												Vulnerable: true,
												Package: vcPackageTypes.Package{
													Type:   vcPackageTypes.PackageTypeBinary,
													Binary: &vcBinaryPackageTypes.Package{Name: "vcb"},
												},
											},
										},
										{
											Type: criterionTypes.CriterionTypeNoneExist,
											NoneExist: &necTypes.Criterion{
												Type:   necTypes.PackageTypeBinary,
												Binary: &necBinaryPackageTypes.Package{Name: "necb"},
											},
										},
									},
								},
								{
									Operator: criteriaTypes.CriteriaOperatorTypeAND,
									Criterions: []criterionTypes.Criterion{
										{
											Type: criterionTypes.CriterionTypeVersion,
											Version: &vcTypes.Criterion{
												Vulnerable: true,
												Package: vcPackageTypes.Package{
													Type:   vcPackageTypes.PackageTypeSource,
													Source: &vcSourcePackageTypes.Package{Name: "vcs"},
												},
											},
										},
										{
											Type: criterionTypes.CriterionTypeNoneExist,
											NoneExist: &necTypes.Criterion{
												Type:   necTypes.PackageTypeSource,
												Source: &necSourcePackageTypes.Package{Name: "necs"},
											},
										},
									},
								},
								{
									Operator: criteriaTypes.CriteriaOperatorTypeAND,
									Criterions: []criterionTypes.Criterion{
										{
											Type: criterionTypes.CriterionTypeVersion,
											Version: &vcTypes.Criterion{
												Vulnerable: true,
												Package: vcPackageTypes.Package{
													CPE: func() *vcCPEPackageTypes.CPE {
														fs := vcCPEPackageTypes.CPE("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*")
														return &fs
													}(),
												},
											},
										},
										{
											Type: criterionTypes.CriterionTypeVersion,
											Version: &vcTypes.Criterion{
												Vulnerable: false,
												Package: vcPackageTypes.Package{
													CPE: func() *vcCPEPackageTypes.CPE {
														fs := vcCPEPackageTypes.CPE("cpe:2.3:o:vendor:product:*:*:*:*:*:*:*:*")
														return &fs
													}(),
												},
											},
										},
									},
								},
							},
							Criterions: []criterionTypes.Criterion{
								{
									// Type: ,
								},
							},
						},
					},
				},
			},
			want: []string{"vcb", "vcs", "vendor:product", "vcl"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := util.CollectPkgName(tt.args.conds)
			if (err != nil) != tt.wantErr {
				t.Errorf("CollectPkgName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CollectPkgName() = %v, want %v", got, tt.want)
			}
		})
	}
}
