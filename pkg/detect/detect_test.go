package detect

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	vcTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	vcAffectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	vcAffectedRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	vcFixStatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	vcPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	vcBinaryPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	warningTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/warning"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"
)

func TestCollectWarnings(t *testing.T) {
	tests := []struct {
		name     string
		detected map[dataTypes.RootID]detectTypes.VulnerabilityData
		want     map[sourceTypes.SourceID]map[warningTypes.Kind][]string
	}{
		{
			name:     "no warnings yields nil",
			detected: map[dataTypes.RootID]detectTypes.VulnerabilityData{},
			want:     nil,
		},
		{
			// Warnings group by (source, kind): the same warning recorded on
			// multiple criterions — including one nested a level down and one
			// in another source — is deduplicated per group, and the raw
			// empty-string cause is preserved verbatim (unset datum for
			// cause-carrying kinds; the constant [""] for cause-less kinds
			// like empty-range). Cause order carries no guarantee; this
			// single-root fixture makes the encounter order deterministic so
			// exact expectations stay valid.
			name: "groups by source and kind, dedups causes",
			detected: map[dataTypes.RootID]detectTypes.VulnerabilityData{
				"ROOT-ID": {
					ID: "ROOT-ID",
					Detections: []detectTypes.VulnerabilityDataDetection{{
						Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
						Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
							sourceTypes.RedHatOVALv2: {
								{
									Criteria: criteriaTypes.FilteredCriteria{
										Operator: criteriaTypes.CriteriaOperatorTypeOR,
										Criterions: []criterionTypes.FilteredCriterion{{
											Criterion: criterionTypes.Criterion{Type: criterionTypes.CriterionType("future-criterion")},
											Warnings: []warningTypes.Warning{
												{Kind: warningTypes.KindEmptyRange},
												{Kind: warningTypes.KindUnevaluablePackageType},
												{Kind: warningTypes.KindUnevaluablePackageType, Cause: "future-package"},
											},
										}},
									},
								},
								{
									Criteria: criteriaTypes.FilteredCriteria{
										Operator: criteriaTypes.CriteriaOperatorTypeOR,
										Criterias: []criteriaTypes.FilteredCriteria{{
											Operator: criteriaTypes.CriteriaOperatorTypeAND,
											Criterions: []criterionTypes.FilteredCriterion{{
												Criterion: criterionTypes.Criterion{Type: criterionTypes.CriterionType("future-criterion")},
												Warnings: []warningTypes.Warning{
													{Kind: warningTypes.KindUnevaluablePackageType, Cause: "future-package"},
													{Kind: warningTypes.KindUnevaluableRangeType, Cause: "future-range"},
												},
											}},
										}},
									},
								},
							},
							sourceTypes.RedHatCSAF: {
								{
									Criteria: criteriaTypes.FilteredCriteria{
										Operator: criteriaTypes.CriteriaOperatorTypeOR,
										Criterions: []criterionTypes.FilteredCriterion{{
											Criterion: criterionTypes.Criterion{Type: criterionTypes.CriterionType("future-criterion")},
											Warnings:  []warningTypes.Warning{{Kind: warningTypes.KindUnevaluableRangeType, Cause: "future-range"}},
										}},
									},
								},
							},
						},
					}},
				},
			},
			want: map[sourceTypes.SourceID]map[warningTypes.Kind][]string{
				sourceTypes.RedHatOVALv2: {
					warningTypes.KindEmptyRange:             {""},
					warningTypes.KindUnevaluablePackageType: {"", "future-package"},
					warningTypes.KindUnevaluableRangeType:   {"future-range"},
				},
				sourceTypes.RedHatCSAF: {
					warningTypes.KindUnevaluableRangeType: {"future-range"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, CollectWarnings(tt.detected)); diff != "" {
				t.Errorf("CollectWarnings() (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestFilterAffected(t *testing.T) {
	tests := []struct {
		name    string
		arg     map[dataTypes.RootID]detectTypes.VulnerabilityData
		want    map[dataTypes.RootID]detectTypes.VulnerabilityData
		wantErr bool
	}{
		{
			name: "empty input yields empty output",
			arg:  map[dataTypes.RootID]detectTypes.VulnerabilityData{},
			want: map[dataTypes.RootID]detectTypes.VulnerabilityData{},
		},
		{
			name: "affected condition is kept",
			arg: map[dataTypes.RootID]detectTypes.VulnerabilityData{
				"ROOT-ID": {
					ID: "ROOT-ID",
					Detections: []detectTypes.VulnerabilityDataDetection{{
						Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
						Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
							sourceTypes.RedHatOVALv2: {{
								Criteria: criteriaTypes.FilteredCriteria{
									Operator: criteriaTypes.CriteriaOperatorTypeOR,
									Criterias: []criteriaTypes.FilteredCriteria{{
										Operator: criteriaTypes.CriteriaOperatorTypeAND,
										Criterions: []criterionTypes.FilteredCriterion{{
											Criterion: criterionTypes.Criterion{
												Type: criterionTypes.CriterionTypeVersion,
												Version: &vcTypes.Criterion{
													Vulnerable: true,
													FixStatus:  &vcFixStatusTypes.FixStatus{Class: vcFixStatusTypes.ClassFixed},
													Package: vcPackageTypes.Package{
														Type:   vcPackageTypes.PackageTypeBinary,
														Binary: &vcBinaryPackageTypes.Package{Name: "kernel"},
													},
													Affected: &vcAffectedTypes.Affected{
														Type:  vcAffectedRangeTypes.RangeTypeRPM,
														Range: []vcAffectedRangeTypes.Range{{LessThan: "0:5.14.0-70.13.1.el9_0"}},
														Fixed: []string{"0:5.14.0-70.13.1.el9_0"},
													},
												},
											},
											Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
										}},
									}},
								},
							}},
						},
					}},
				},
			},
			want: map[dataTypes.RootID]detectTypes.VulnerabilityData{
				"ROOT-ID": {
					ID: "ROOT-ID",
					Detections: []detectTypes.VulnerabilityDataDetection{{
						Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
						Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
							sourceTypes.RedHatOVALv2: {{
								Criteria: criteriaTypes.FilteredCriteria{
									Operator: criteriaTypes.CriteriaOperatorTypeOR,
									Criterias: []criteriaTypes.FilteredCriteria{{
										Operator: criteriaTypes.CriteriaOperatorTypeAND,
										Criterions: []criterionTypes.FilteredCriterion{{
											Criterion: criterionTypes.Criterion{
												Type: criterionTypes.CriterionTypeVersion,
												Version: &vcTypes.Criterion{
													Vulnerable: true,
													FixStatus:  &vcFixStatusTypes.FixStatus{Class: vcFixStatusTypes.ClassFixed},
													Package: vcPackageTypes.Package{
														Type:   vcPackageTypes.PackageTypeBinary,
														Binary: &vcBinaryPackageTypes.Package{Name: "kernel"},
													},
													Affected: &vcAffectedTypes.Affected{
														Type:  vcAffectedRangeTypes.RangeTypeRPM,
														Range: []vcAffectedRangeTypes.Range{{LessThan: "0:5.14.0-70.13.1.el9_0"}},
														Fixed: []string{"0:5.14.0-70.13.1.el9_0"},
													},
												},
											},
											Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
										}},
									}},
								},
							}},
						},
					}},
				},
			},
		},
		{
			name: "unaffected-only VulnerabilityData is pruned entirely",
			arg: map[dataTypes.RootID]detectTypes.VulnerabilityData{
				"ROOT-ID": {
					ID: "ROOT-ID",
					Detections: []detectTypes.VulnerabilityDataDetection{{
						Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
						Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
							sourceTypes.RedHatOVALv2: {{
								Criteria: criteriaTypes.FilteredCriteria{
									Operator: criteriaTypes.CriteriaOperatorTypeOR,
									Criterias: []criteriaTypes.FilteredCriteria{{
										Operator: criteriaTypes.CriteriaOperatorTypeAND,
										Criterions: []criterionTypes.FilteredCriterion{{
											Criterion: criterionTypes.Criterion{
												Type: criterionTypes.CriterionTypeVersion,
												Version: &vcTypes.Criterion{
													Vulnerable: true,
													FixStatus:  &vcFixStatusTypes.FixStatus{Class: vcFixStatusTypes.ClassFixed},
													Package: vcPackageTypes.Package{
														Type:   vcPackageTypes.PackageTypeBinary,
														Binary: &vcBinaryPackageTypes.Package{Name: "openssl"},
													},
													Affected: &vcAffectedTypes.Affected{
														Type:  vcAffectedRangeTypes.RangeTypeRPM,
														Range: []vcAffectedRangeTypes.Range{{LessThan: "1:3.0.7-16.el9_2"}},
														Fixed: []string{"1:3.0.7-16.el9_2"},
													},
												},
											},
											Accepts: criterionTypes.AcceptQueries{Version: []int{}},
										}},
									}},
								},
							}},
						},
					}},
				},
			},
			want: map[dataTypes.RootID]detectTypes.VulnerabilityData{},
		},
		{
			name: "within a source slot, only affected conditions are kept",
			arg: map[dataTypes.RootID]detectTypes.VulnerabilityData{
				"ROOT-ID": {
					ID: "ROOT-ID",
					Detections: []detectTypes.VulnerabilityDataDetection{{
						Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
						Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
							sourceTypes.RedHatOVALv2: {
								{
									Criteria: criteriaTypes.FilteredCriteria{
										Operator: criteriaTypes.CriteriaOperatorTypeOR,
										Criterias: []criteriaTypes.FilteredCriteria{{
											Operator: criteriaTypes.CriteriaOperatorTypeAND,
											Criterions: []criterionTypes.FilteredCriterion{{
												Criterion: criterionTypes.Criterion{
													Type: criterionTypes.CriterionTypeVersion,
													Version: &vcTypes.Criterion{
														Vulnerable: true,
														FixStatus:  &vcFixStatusTypes.FixStatus{Class: vcFixStatusTypes.ClassFixed},
														Package: vcPackageTypes.Package{
															Type:   vcPackageTypes.PackageTypeBinary,
															Binary: &vcBinaryPackageTypes.Package{Name: "kernel"},
														},
														Affected: &vcAffectedTypes.Affected{
															Type:  vcAffectedRangeTypes.RangeTypeRPM,
															Range: []vcAffectedRangeTypes.Range{{LessThan: "0:5.14.0-70.13.1.el9_0"}},
															Fixed: []string{"0:5.14.0-70.13.1.el9_0"},
														},
													},
												},
												Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
											}},
										}},
									},
								},
								{
									Criteria: criteriaTypes.FilteredCriteria{
										Operator: criteriaTypes.CriteriaOperatorTypeOR,
										Criterias: []criteriaTypes.FilteredCriteria{{
											Operator: criteriaTypes.CriteriaOperatorTypeAND,
											Criterions: []criterionTypes.FilteredCriterion{{
												Criterion: criterionTypes.Criterion{
													Type: criterionTypes.CriterionTypeVersion,
													Version: &vcTypes.Criterion{
														Vulnerable: true,
														FixStatus:  &vcFixStatusTypes.FixStatus{Class: vcFixStatusTypes.ClassFixed},
														Package: vcPackageTypes.Package{
															Type:   vcPackageTypes.PackageTypeBinary,
															Binary: &vcBinaryPackageTypes.Package{Name: "openssl"},
														},
														Affected: &vcAffectedTypes.Affected{
															Type:  vcAffectedRangeTypes.RangeTypeRPM,
															Range: []vcAffectedRangeTypes.Range{{LessThan: "1:3.0.7-16.el9_2"}},
															Fixed: []string{"1:3.0.7-16.el9_2"},
														},
													},
												},
												Accepts: criterionTypes.AcceptQueries{Version: []int{}},
											}},
										}},
									},
								},
							},
						},
					}},
				},
			},
			want: map[dataTypes.RootID]detectTypes.VulnerabilityData{
				"ROOT-ID": {
					ID: "ROOT-ID",
					Detections: []detectTypes.VulnerabilityDataDetection{{
						Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
						Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
							sourceTypes.RedHatOVALv2: {{
								Criteria: criteriaTypes.FilteredCriteria{
									Operator: criteriaTypes.CriteriaOperatorTypeOR,
									Criterias: []criteriaTypes.FilteredCriteria{{
										Operator: criteriaTypes.CriteriaOperatorTypeAND,
										Criterions: []criterionTypes.FilteredCriterion{{
											Criterion: criterionTypes.Criterion{
												Type: criterionTypes.CriterionTypeVersion,
												Version: &vcTypes.Criterion{
													Vulnerable: true,
													FixStatus:  &vcFixStatusTypes.FixStatus{Class: vcFixStatusTypes.ClassFixed},
													Package: vcPackageTypes.Package{
														Type:   vcPackageTypes.PackageTypeBinary,
														Binary: &vcBinaryPackageTypes.Package{Name: "kernel"},
													},
													Affected: &vcAffectedTypes.Affected{
														Type:  vcAffectedRangeTypes.RangeTypeRPM,
														Range: []vcAffectedRangeTypes.Range{{LessThan: "0:5.14.0-70.13.1.el9_0"}},
														Fixed: []string{"0:5.14.0-70.13.1.el9_0"},
													},
												},
											},
											Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
										}},
									}},
								},
							}},
						},
					}},
				},
			},
		},
		{
			name: "source with no surviving conditions is dropped, sibling source is kept",
			arg: map[dataTypes.RootID]detectTypes.VulnerabilityData{
				"ROOT-ID": {
					ID: "ROOT-ID",
					Detections: []detectTypes.VulnerabilityDataDetection{{
						Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
						Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
							sourceTypes.RedHatOVALv2: {{
								Criteria: criteriaTypes.FilteredCriteria{
									Operator: criteriaTypes.CriteriaOperatorTypeOR,
									Criterias: []criteriaTypes.FilteredCriteria{{
										Operator: criteriaTypes.CriteriaOperatorTypeAND,
										Criterions: []criterionTypes.FilteredCriterion{{
											Criterion: criterionTypes.Criterion{
												Type: criterionTypes.CriterionTypeVersion,
												Version: &vcTypes.Criterion{
													Vulnerable: true,
													FixStatus:  &vcFixStatusTypes.FixStatus{Class: vcFixStatusTypes.ClassFixed},
													Package: vcPackageTypes.Package{
														Type:   vcPackageTypes.PackageTypeBinary,
														Binary: &vcBinaryPackageTypes.Package{Name: "kernel"},
													},
													Affected: &vcAffectedTypes.Affected{
														Type:  vcAffectedRangeTypes.RangeTypeRPM,
														Range: []vcAffectedRangeTypes.Range{{LessThan: "0:5.14.0-70.13.1.el9_0"}},
														Fixed: []string{"0:5.14.0-70.13.1.el9_0"},
													},
												},
											},
											Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
										}},
									}},
								},
							}},
							sourceTypes.SourceID("other-src"): {{
								Criteria: criteriaTypes.FilteredCriteria{
									Operator: criteriaTypes.CriteriaOperatorTypeOR,
									Criterias: []criteriaTypes.FilteredCriteria{{
										Operator: criteriaTypes.CriteriaOperatorTypeAND,
										Criterions: []criterionTypes.FilteredCriterion{{
											Criterion: criterionTypes.Criterion{
												Type: criterionTypes.CriterionTypeVersion,
												Version: &vcTypes.Criterion{
													Vulnerable: true,
													FixStatus:  &vcFixStatusTypes.FixStatus{Class: vcFixStatusTypes.ClassFixed},
													Package: vcPackageTypes.Package{
														Type:   vcPackageTypes.PackageTypeBinary,
														Binary: &vcBinaryPackageTypes.Package{Name: "openssl"},
													},
													Affected: &vcAffectedTypes.Affected{
														Type:  vcAffectedRangeTypes.RangeTypeRPM,
														Range: []vcAffectedRangeTypes.Range{{LessThan: "1:3.0.7-16.el9_2"}},
														Fixed: []string{"1:3.0.7-16.el9_2"},
													},
												},
											},
											Accepts: criterionTypes.AcceptQueries{Version: []int{}},
										}},
									}},
								},
							}},
						},
					}},
				},
			},
			want: map[dataTypes.RootID]detectTypes.VulnerabilityData{
				"ROOT-ID": {
					ID: "ROOT-ID",
					Detections: []detectTypes.VulnerabilityDataDetection{{
						Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
						Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
							sourceTypes.RedHatOVALv2: {{
								Criteria: criteriaTypes.FilteredCriteria{
									Operator: criteriaTypes.CriteriaOperatorTypeOR,
									Criterias: []criteriaTypes.FilteredCriteria{{
										Operator: criteriaTypes.CriteriaOperatorTypeAND,
										Criterions: []criterionTypes.FilteredCriterion{{
											Criterion: criterionTypes.Criterion{
												Type: criterionTypes.CriterionTypeVersion,
												Version: &vcTypes.Criterion{
													Vulnerable: true,
													FixStatus:  &vcFixStatusTypes.FixStatus{Class: vcFixStatusTypes.ClassFixed},
													Package: vcPackageTypes.Package{
														Type:   vcPackageTypes.PackageTypeBinary,
														Binary: &vcBinaryPackageTypes.Package{Name: "kernel"},
													},
													Affected: &vcAffectedTypes.Affected{
														Type:  vcAffectedRangeTypes.RangeTypeRPM,
														Range: []vcAffectedRangeTypes.Range{{LessThan: "0:5.14.0-70.13.1.el9_0"}},
														Fixed: []string{"0:5.14.0-70.13.1.el9_0"},
													},
												},
											},
											Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
										}},
									}},
								},
							}},
						},
					}},
				},
			},
		},
		{
			name: "detection with no surviving sources is dropped, sibling detection is kept",
			arg: map[dataTypes.RootID]detectTypes.VulnerabilityData{
				"ROOT-ID": {
					ID: "ROOT-ID",
					Detections: []detectTypes.VulnerabilityDataDetection{
						{
							Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
							Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
								sourceTypes.RedHatOVALv2: {{
									Criteria: criteriaTypes.FilteredCriteria{
										Operator: criteriaTypes.CriteriaOperatorTypeOR,
										Criterias: []criteriaTypes.FilteredCriteria{{
											Operator: criteriaTypes.CriteriaOperatorTypeAND,
											Criterions: []criterionTypes.FilteredCriterion{{
												Criterion: criterionTypes.Criterion{
													Type: criterionTypes.CriterionTypeVersion,
													Version: &vcTypes.Criterion{
														Vulnerable: true,
														FixStatus:  &vcFixStatusTypes.FixStatus{Class: vcFixStatusTypes.ClassFixed},
														Package: vcPackageTypes.Package{
															Type:   vcPackageTypes.PackageTypeBinary,
															Binary: &vcBinaryPackageTypes.Package{Name: "openssl"},
														},
														Affected: &vcAffectedTypes.Affected{
															Type:  vcAffectedRangeTypes.RangeTypeRPM,
															Range: []vcAffectedRangeTypes.Range{{LessThan: "1:3.0.7-16.el9_2"}},
															Fixed: []string{"1:3.0.7-16.el9_2"},
														},
													},
												},
												Accepts: criterionTypes.AcceptQueries{Version: []int{}},
											}},
										}},
									},
								}},
							},
						},
						{
							Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
							Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
								sourceTypes.RedHatOVALv2: {{
									Criteria: criteriaTypes.FilteredCriteria{
										Operator: criteriaTypes.CriteriaOperatorTypeOR,
										Criterias: []criteriaTypes.FilteredCriteria{{
											Operator: criteriaTypes.CriteriaOperatorTypeAND,
											Criterions: []criterionTypes.FilteredCriterion{{
												Criterion: criterionTypes.Criterion{
													Type: criterionTypes.CriterionTypeVersion,
													Version: &vcTypes.Criterion{
														Vulnerable: true,
														FixStatus:  &vcFixStatusTypes.FixStatus{Class: vcFixStatusTypes.ClassFixed},
														Package: vcPackageTypes.Package{
															Type:   vcPackageTypes.PackageTypeBinary,
															Binary: &vcBinaryPackageTypes.Package{Name: "kernel"},
														},
														Affected: &vcAffectedTypes.Affected{
															Type:  vcAffectedRangeTypes.RangeTypeRPM,
															Range: []vcAffectedRangeTypes.Range{{LessThan: "0:5.14.0-70.13.1.el9_0"}},
															Fixed: []string{"0:5.14.0-70.13.1.el9_0"},
														},
													},
												},
												Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
											}},
										}},
									},
								}},
							},
						},
					},
				},
			},
			want: map[dataTypes.RootID]detectTypes.VulnerabilityData{
				"ROOT-ID": {
					ID: "ROOT-ID",
					Detections: []detectTypes.VulnerabilityDataDetection{{
						Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
						Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
							sourceTypes.RedHatOVALv2: {{
								Criteria: criteriaTypes.FilteredCriteria{
									Operator: criteriaTypes.CriteriaOperatorTypeOR,
									Criterias: []criteriaTypes.FilteredCriteria{{
										Operator: criteriaTypes.CriteriaOperatorTypeAND,
										Criterions: []criterionTypes.FilteredCriterion{{
											Criterion: criterionTypes.Criterion{
												Type: criterionTypes.CriterionTypeVersion,
												Version: &vcTypes.Criterion{
													Vulnerable: true,
													FixStatus:  &vcFixStatusTypes.FixStatus{Class: vcFixStatusTypes.ClassFixed},
													Package: vcPackageTypes.Package{
														Type:   vcPackageTypes.PackageTypeBinary,
														Binary: &vcBinaryPackageTypes.Package{Name: "kernel"},
													},
													Affected: &vcAffectedTypes.Affected{
														Type:  vcAffectedRangeTypes.RangeTypeRPM,
														Range: []vcAffectedRangeTypes.Range{{LessThan: "0:5.14.0-70.13.1.el9_0"}},
														Fixed: []string{"0:5.14.0-70.13.1.el9_0"},
													},
												},
											},
											Accepts: criterionTypes.AcceptQueries{Version: []int{0}},
										}},
									}},
								},
							}},
						},
					}},
				},
			},
		},
		{
			name: "Criteria.Affected() error is surfaced",
			arg: map[dataTypes.RootID]detectTypes.VulnerabilityData{
				"ROOT-ID": {
					ID: "ROOT-ID",
					Detections: []detectTypes.VulnerabilityDataDetection{{
						Ecosystem: ecosystemTypes.Ecosystem("redhat:9"),
						Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
							sourceTypes.RedHatOVALv2: {{
								// An out-of-vocabulary operator triggers the default
								// branch of FilteredCriteria.Affected() and returns
								// an error: operator evaluation is deliberately
								// strict, unlike the other (lenient) enums.
								Criteria: criteriaTypes.FilteredCriteria{Operator: criteriaTypes.CriteriaOperatorType("future-operator")},
							}},
						},
					}},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := filterAffected(tt.arg)
			if (err != nil) != tt.wantErr {
				t.Fatalf("filterAffected() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("filterAffected() (-want +got):\n%s", diff)
			}
		})
	}
}
