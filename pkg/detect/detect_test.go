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
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"
)

// versionCondition returns a single-package FilteredCondition for a binary
// rpm with a fixed-version range. When matched is true the inner criterion's
// Accepts.Version is populated with a query index so Criteria.Affected()
// returns true; otherwise Accepts.Version is empty and Affected() returns
// false.
func versionCondition(pkgName, fixed string, isAffected bool) conditionTypes.FilteredCondition {
	c := criterionTypes.FilteredCriterion{
		Criterion: criterionTypes.Criterion{
			Type: criterionTypes.CriterionTypeVersion,
			Version: &vcTypes.Criterion{
				Vulnerable: true,
				FixStatus:  &vcFixStatusTypes.FixStatus{Class: vcFixStatusTypes.ClassFixed},
				Package: vcPackageTypes.Package{
					Type:   vcPackageTypes.PackageTypeBinary,
					Binary: &vcBinaryPackageTypes.Package{Name: pkgName},
				},
				Affected: &vcAffectedTypes.Affected{
					Type:  vcAffectedRangeTypes.RangeTypeRPM,
					Range: []vcAffectedRangeTypes.Range{{LessThan: fixed}},
					Fixed: []string{fixed},
				},
			},
		},
		Accepts: criterionTypes.AcceptQueries{Version: []int{}},
	}
	if isAffected {
		c.Accepts.Version = []int{0}
	}
	return conditionTypes.FilteredCondition{
		Criteria: criteriaTypes.FilteredCriteria{
			Operator: criteriaTypes.CriteriaOperatorTypeOR,
			Criterias: []criteriaTypes.FilteredCriteria{
				{
					Operator:   criteriaTypes.CriteriaOperatorTypeAND,
					Criterions: []criterionTypes.FilteredCriterion{c},
				},
			},
		},
	}
}

func TestFilterAffected(t *testing.T) {
	const eco = ecosystemTypes.Ecosystem("redhat:9")
	const src = sourceTypes.SourceID("redhat-ovalv2")

	affectedCond := versionCondition("kernel", "0:5.14.0-70.13.1.el9_0", true)
	unaffectedCond := versionCondition("openssl", "1:3.0.7-16.el9_2", false)

	tests := []struct {
		name    string
		in      map[dataTypes.RootID]detectTypes.VulnerabilityData
		want    map[dataTypes.RootID]detectTypes.VulnerabilityData
		wantErr bool
	}{
		{
			name: "empty input yields empty output",
			in:   map[dataTypes.RootID]detectTypes.VulnerabilityData{},
			want: map[dataTypes.RootID]detectTypes.VulnerabilityData{},
		},
		{
			name: "affected condition is kept",
			in: map[dataTypes.RootID]detectTypes.VulnerabilityData{
				"CVE-A": {
					ID: "CVE-A",
					Detections: []detectTypes.VulnerabilityDataDetection{{
						Ecosystem: eco,
						Contents:  map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{src: {affectedCond}},
					}},
				},
			},
			want: map[dataTypes.RootID]detectTypes.VulnerabilityData{
				"CVE-A": {
					ID: "CVE-A",
					Detections: []detectTypes.VulnerabilityDataDetection{{
						Ecosystem: eco,
						Contents:  map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{src: {affectedCond}},
					}},
				},
			},
		},
		{
			name: "unaffected-only VulnerabilityData is pruned entirely",
			in: map[dataTypes.RootID]detectTypes.VulnerabilityData{
				"CVE-B": {
					ID: "CVE-B",
					Detections: []detectTypes.VulnerabilityDataDetection{{
						Ecosystem: eco,
						Contents:  map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{src: {unaffectedCond}},
					}},
				},
			},
			want: map[dataTypes.RootID]detectTypes.VulnerabilityData{},
		},
		{
			name: "within a source slot, only affected conditions are kept",
			in: map[dataTypes.RootID]detectTypes.VulnerabilityData{
				"CVE-C": {
					ID: "CVE-C",
					Detections: []detectTypes.VulnerabilityDataDetection{{
						Ecosystem: eco,
						Contents:  map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{src: {affectedCond, unaffectedCond}},
					}},
				},
			},
			want: map[dataTypes.RootID]detectTypes.VulnerabilityData{
				"CVE-C": {
					ID: "CVE-C",
					Detections: []detectTypes.VulnerabilityDataDetection{{
						Ecosystem: eco,
						Contents:  map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{src: {affectedCond}},
					}},
				},
			},
		},
		{
			name: "source with no surviving conditions is dropped, sibling source is kept",
			in: map[dataTypes.RootID]detectTypes.VulnerabilityData{
				"CVE-D": {
					ID: "CVE-D",
					Detections: []detectTypes.VulnerabilityDataDetection{{
						Ecosystem: eco,
						Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{
							src:                               {affectedCond},
							sourceTypes.SourceID("other-src"): {unaffectedCond},
						},
					}},
				},
			},
			want: map[dataTypes.RootID]detectTypes.VulnerabilityData{
				"CVE-D": {
					ID: "CVE-D",
					Detections: []detectTypes.VulnerabilityDataDetection{{
						Ecosystem: eco,
						Contents:  map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{src: {affectedCond}},
					}},
				},
			},
		},
		{
			name: "detection with no surviving sources is dropped, sibling detection is kept",
			in: map[dataTypes.RootID]detectTypes.VulnerabilityData{
				"CVE-E": {
					ID: "CVE-E",
					Detections: []detectTypes.VulnerabilityDataDetection{
						{
							Ecosystem: eco,
							Contents:  map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{src: {unaffectedCond}},
						},
						{
							Ecosystem: eco,
							Contents:  map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{src: {affectedCond}},
						},
					},
				},
			},
			want: map[dataTypes.RootID]detectTypes.VulnerabilityData{
				"CVE-E": {
					ID: "CVE-E",
					Detections: []detectTypes.VulnerabilityDataDetection{{
						Ecosystem: eco,
						Contents:  map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{src: {affectedCond}},
					}},
				},
			},
		},
		{
			name: "Criteria.Affected() error is surfaced",
			in: map[dataTypes.RootID]detectTypes.VulnerabilityData{
				"CVE-F": {
					ID: "CVE-F",
					Detections: []detectTypes.VulnerabilityDataDetection{{
						Ecosystem: eco,
						Contents: map[sourceTypes.SourceID][]conditionTypes.FilteredCondition{src: {{
							// Out-of-range operator triggers the default branch
							// of FilteredCriteria.Affected() and returns an
							// error. The valid values are the AND/OR iota
							// constants, so any other int falls through.
							Criteria: criteriaTypes.FilteredCriteria{Operator: criteriaTypes.CriteriaOperatorType(-1)},
						}}},
					}},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := filterAffected(tt.in)
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
