package validate

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
)

func TestInspectOrphanSegment(t *testing.T) {
	tests := []struct {
		name string
		data dataTypes.Data
		want []Violation
	}{
		{
			name: "ok",
			data: dataTypes.Data{
				ID: "CVE-2024-0001",
				Advisories: []advisoryTypes.Advisory{
					{
						Content:  advisoryContentTypes.Content{ID: "ADV-2024-0001"},
						Segments: []segmentTypes.Segment{{Ecosystem: ecosystemTypes.EcosystemTypeCPE, Tag: "vulnerable"}},
					},
				},
				Vulnerabilities: []vulnerabilityTypes.Vulnerability{
					{
						Content:  vulnerabilityContentTypes.Content{ID: "CVE-2024-0001"},
						Segments: []segmentTypes.Segment{{Ecosystem: ecosystemTypes.EcosystemTypeCPE, Tag: "vulnerable"}},
					},
				},
				Detections: []detectionTypes.Detection{
					{
						Ecosystem: ecosystemTypes.EcosystemTypeCPE,
						Conditions: []conditionTypes.Condition{
							{Tag: "vulnerable"},
						},
					},
				},
			},
		},
		{
			name: "advisory segment with unknown tag",
			data: dataTypes.Data{
				ID: "CVE-2024-0001",
				Advisories: []advisoryTypes.Advisory{
					{
						Content:  advisoryContentTypes.Content{ID: "ADV-2024-0001"},
						Segments: []segmentTypes.Segment{{Ecosystem: ecosystemTypes.EcosystemTypeCPE, Tag: "other"}},
					},
				},
				Detections: []detectionTypes.Detection{
					{
						Ecosystem: ecosystemTypes.EcosystemTypeCPE,
						Conditions: []conditionTypes.Condition{
							{Tag: "vulnerable"},
						},
					},
				},
			},
			want: []Violation{
				{
					Pointer: "/advisories/0/segments/0",
					Message: "advisory ADV-2024-0001: segment (ecosystem: cpe, tag: other) has no corresponding detection condition",
				},
			},
		},
		{
			name: "vulnerability segment with unknown ecosystem",
			data: dataTypes.Data{
				ID: "CVE-2024-0001",
				Vulnerabilities: []vulnerabilityTypes.Vulnerability{
					{
						Content:  vulnerabilityContentTypes.Content{ID: "CVE-2024-0001"},
						Segments: []segmentTypes.Segment{{Ecosystem: ecosystemTypes.EcosystemTypeFedora, Tag: "vulnerable"}},
					},
				},
				Detections: []detectionTypes.Detection{
					{
						Ecosystem: ecosystemTypes.EcosystemTypeCPE,
						Conditions: []conditionTypes.Condition{
							{Tag: "vulnerable"},
						},
					},
				},
			},
			want: []Violation{
				{
					Pointer: "/vulnerabilities/0/segments/0",
					Message: "vulnerability CVE-2024-0001: segment (ecosystem: fedora, tag: vulnerable) has no corresponding detection condition",
				},
			},
		},
		{
			name: "segments without any detections",
			data: dataTypes.Data{
				ID: "CVE-2024-0001",
				Vulnerabilities: []vulnerabilityTypes.Vulnerability{
					{
						Content:  vulnerabilityContentTypes.Content{ID: "CVE-2024-0001"},
						Segments: []segmentTypes.Segment{{Ecosystem: ecosystemTypes.EcosystemTypeCPE, Tag: "vulnerable"}},
					},
				},
			},
			want: []Violation{
				{
					Pointer: "/vulnerabilities/0/segments/0",
					Message: "vulnerability CVE-2024-0001: segment (ecosystem: cpe, tag: vulnerable) has no corresponding detection condition",
				},
			},
		},
		{
			name: "content without segments",
			data: dataTypes.Data{
				ID: "CVE-2024-0001",
				Vulnerabilities: []vulnerabilityTypes.Vulnerability{
					{Content: vulnerabilityContentTypes.Content{ID: "CVE-2024-0001"}},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, inspectOrphanSegment(tt.data)); diff != "" {
				t.Errorf("inspectOrphanSegment() (-expected +got):\n%s", diff)
			}
		})
	}
}
