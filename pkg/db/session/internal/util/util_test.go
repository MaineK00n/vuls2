package util_test

import (
	"reflect"
	"testing"

	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	necriterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion"
	necBinaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion/binary"
	versoncriterion "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	vcAffectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	vcAffectedRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	vcFixStatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	vcPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	vcBinaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	vcSourcePackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/source"
	"github.com/MaineK00n/vuls2/pkg/db/session/internal/util"
)

func TestMarshal(t *testing.T) {
	type args struct {
		v any
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				v: map[string]string{
					"k2": "v2",
					"k1": "v1",
				},
			},
			want: []byte(`{"k1":"v1","k2":"v2"}`),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := util.Marshal(tt.args.v)
			if (err != nil) != tt.wantErr {
				t.Errorf("Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Marshal() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUnmarshal(t *testing.T) {
	type args struct {
		data []byte
		v    any
	}
	tests := []struct {
		name    string
		args    args
		want    any
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				data: []byte(`{"k1":"v1","k2":"v2"}`),
				v:    &map[string]string{},
			},
			want: &map[string]string{
				"k1": "v1",
				"k2": "v2",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := util.Unmarshal(tt.args.data, tt.args.v); (err != nil) != tt.wantErr {
				t.Errorf("Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(tt.args.v, tt.want) {
				t.Errorf("Unmarshal() = %v, want %v", tt.args.v, tt.want)
			}
		})
	}
}

func TestWalkCriteria(t *testing.T) {
	type args struct {
		ca criteriaTypes.Criteria
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
				ca: criteriaTypes.Criteria{
					Operator: criteriaTypes.CriteriaOperatorTypeOR,
					Criterions: []criterionTypes.Criterion{
						{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &versoncriterion.Criterion{
								Vulnerable: true,
								FixStatus: &vcFixStatusTypes.FixStatus{
									Class: vcFixStatusTypes.ClassUnfixed,
								},
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeBinary,
									Binary: &vcBinaryPackageTypes.Package{
										Name: "kernel",
									},
								},
							},
						},
						{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &versoncriterion.Criterion{
								Vulnerable: true,
								FixStatus: &vcFixStatusTypes.FixStatus{
									Class: vcFixStatusTypes.ClassUnfixed,
								},
								Package: vcPackageTypes.Package{
									Type: vcPackageTypes.PackageTypeSource,
									Source: &vcSourcePackageTypes.Package{
										Name: "kernel",
									},
								},
							},
						},
					},
				},
			},
			want: []string{"kernel", "kernel"},
		},
		{
			name: "none-exist",
			args: args{
				ca: criteriaTypes.Criteria{
					Operator: criteriaTypes.CriteriaOperatorTypeAND,
					Criterias: []criteriaTypes.Criteria{
						{
							Operator: criteriaTypes.CriteriaOperatorTypeOR,
							Criterias: []criteriaTypes.Criteria{
								{
									Operator: criteriaTypes.CriteriaOperatorTypeAND,
									Criterions: []criterionTypes.Criterion{
										{
											Type: criterionTypes.CriterionTypeVersion,
											Version: &versoncriterion.Criterion{
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
							Criterions: []criterionTypes.Criterion{
								{
									Type: criterionTypes.CriterionTypeNoneExist,
									NoneExist: &necriterionTypes.Criterion{
										Type: necriterionTypes.PackageTypeBinary,
										Binary: &necBinaryPackageTypes.Package{
											Name: "kpatch-patch-3_10_0-1062_1_1",
										},
									},
								},
							},
						},
					},
					Criterions: []criterionTypes.Criterion{
						{
							Type: criterionTypes.CriterionTypeVersion,
							Version: &versoncriterion.Criterion{
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
					},
				},
			},
			want: []string{"kpatch-patch-3_10_0-1062_1_1", "kernel"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := util.WalkCriteria(tt.args.ca)
			if (err != nil) != tt.wantErr {
				t.Errorf("WalkCriteria() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("WalkCriteria() = %v, want %v", got, tt.want)
			}
		})
	}
}
