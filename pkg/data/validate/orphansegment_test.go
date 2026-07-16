package validate

import (
	"testing"

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

func TestDetectOrphanSegment(t *testing.T) {
	detection := detectionTypes.Detection{
		Ecosystem: ecosystemTypes.EcosystemTypeCPE,
		Conditions: []conditionTypes.Condition{
			{Tag: "vulnerable"},
		},
	}

	tests := []struct {
		name string
		data dataTypes.Data
		want int
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
				Detections: []detectionTypes.Detection{detection},
			},
			want: 0,
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
				Detections: []detectionTypes.Detection{detection},
			},
			want: 1,
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
				Detections: []detectionTypes.Detection{detection},
			},
			want: 1,
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
			want: 1,
		},
		{
			name: "content without segments",
			data: dataTypes.Data{
				ID: "CVE-2024-0001",
				Vulnerabilities: []vulnerabilityTypes.Vulnerability{
					{Content: vulnerabilityContentTypes.Content{ID: "CVE-2024-0001"}},
				},
			},
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := detectOrphanSegment(tt.data); len(got) != tt.want {
				t.Errorf("detectOrphanSegment() = %q, want %d finding(s)", got, tt.want)
			}
		})
	}
}
