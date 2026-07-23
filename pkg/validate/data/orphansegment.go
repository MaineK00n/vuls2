package data

import (
	"fmt"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
)

var orphanSegmentCheck = Check{
	Name:        "orphan-segment",
	Description: "advisory/vulnerability: every segment has a corresponding detection condition",
	Detect:      detectOrphanSegment,
}

// detectOrphanSegment reports advisory and vulnerability segments whose
// (ecosystem, tag) pair matches no detection condition in the same file.
func detectOrphanSegment(data dataTypes.Data) []Detected {
	type key struct {
		ecosystem ecosystemTypes.Ecosystem
		tag       segmentTypes.DetectionTag
	}

	known := make(map[key]struct{})
	for _, d := range data.Detections {
		for _, cond := range d.Conditions {
			known[key{ecosystem: d.Ecosystem, tag: cond.Tag}] = struct{}{}
		}
	}

	var ds []Detected
	for ai, a := range data.Advisories {
		for si, s := range a.Segments {
			if _, ok := known[key{ecosystem: s.Ecosystem, tag: s.Tag}]; !ok {
				ds = append(ds, Detected{
					Pointer: fmt.Sprintf("/advisories/%d/segments/%d", ai, si),
					Message: fmt.Sprintf("advisory %s: segment (ecosystem: %s, tag: %s) has no corresponding detection condition", a.Content.ID, s.Ecosystem, s.Tag),
				})
			}
		}
	}
	for vi, v := range data.Vulnerabilities {
		for si, s := range v.Segments {
			if _, ok := known[key{ecosystem: s.Ecosystem, tag: s.Tag}]; !ok {
				ds = append(ds, Detected{
					Pointer: fmt.Sprintf("/vulnerabilities/%d/segments/%d", vi, si),
					Message: fmt.Sprintf("vulnerability %s: segment (ecosystem: %s, tag: %s) has no corresponding detection condition", v.Content.ID, s.Ecosystem, s.Tag),
				})
			}
		}
	}
	return ds
}
