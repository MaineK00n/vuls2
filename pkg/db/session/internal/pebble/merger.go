package pebble

import (
	"io"
	"slices"
	"strings"

	"github.com/cockroachdb/pebble"
	"github.com/pkg/errors"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
	"github.com/MaineK00n/vuls2/pkg/db/session/internal/util"
)

// MergerName is the name stored in pebble SST files.
// Changing this name will make existing databases unopenable.
const MergerName = "vuls.merge.v1"

// VulsMerger is the custom pebble Merger used for merge-on-write operations.
// It dispatches to the appropriate ValueMerger based on key prefix.
var VulsMerger = &pebble.Merger{
	Name: MergerName,
	Merge: func(key, value []byte) (pebble.ValueMerger, error) {
		k := string(key)
		parts := strings.SplitN(k, sep, 3)
		if len(parts) < 2 {
			return nil, errors.Errorf("unexpected key format: %q", k)
		}

		switch {
		// vulnerability\x00root\x00<Root ID>
		case parts[0] == "vulnerability" && parts[1] == "root":
			m := &rootMerger{}
			return m, m.add(value)

		// vulnerability\x00advisory\x00<Advisory ID>
		case parts[0] == "vulnerability" && parts[1] == "advisory":
			m := &advisoryMerger{}
			return m, m.add(value)

		// vulnerability\x00vulnerability\x00<CVE ID>
		case parts[0] == "vulnerability" && parts[1] == "vulnerability":
			m := &vulnerabilityMerger{}
			return m, m.add(value)

		// <ecosystem>\x00index\x00<package>
		case parts[1] == "index":
			m := &indexMerger{}
			return m, m.add(value)

		// <ecosystem>\x00detection\x00<Root ID>
		case parts[1] == "detection":
			m := &detectionMerger{}
			return m, m.add(value)

		default:
			return nil, errors.Errorf("no merger for key: %q", k)
		}
	},
}

// detectionMerger merges map[SourceID][]Condition values.
// Each operand is a full map; merge unions the keys (later values for the same SourceID overwrite).
type detectionMerger struct {
	operands [][]byte
}

func (m *detectionMerger) add(value []byte) error {
	buf := make([]byte, len(value))
	copy(buf, value)
	m.operands = append(m.operands, buf)
	return nil
}

func (m *detectionMerger) MergeNewer(value []byte) error { return m.add(value) }
func (m *detectionMerger) MergeOlder(value []byte) error { return m.add(value) }

func (m *detectionMerger) Finish(_ bool) ([]byte, io.Closer, error) {
	result := make(map[sourceTypes.SourceID][]conditionTypes.Condition)
	// Apply from oldest to newest. MergeOlder adds at the end, MergeNewer adds at the end.
	// Since operands are accumulated in call order (first = initial, then newer or older),
	// we just merge all; for detection the semantic is "set sourceID key", so last wins per sourceID.
	// Actually, the order we apply doesn't matter because each operand sets distinct sourceIDs
	// (each comes from a single data file with one DataSource.ID), and if the same sourceID appears
	// in multiple operands the later one should win. We iterate in order so later operands win.
	for _, op := range m.operands {
		var partial map[sourceTypes.SourceID][]conditionTypes.Condition
		if err := util.Unmarshal(op, &partial); err != nil {
			return nil, nil, errors.Wrap(err, "unmarshal detection operand")
		}
		for k, v := range partial {
			result[k] = v
		}
	}
	bs, err := util.Marshal(result)
	if err != nil {
		return nil, nil, errors.Wrap(err, "marshal merged detection")
	}
	return bs, nil, nil
}

// indexMerger merges []RootID values with deduplication.
type indexMerger struct {
	operands [][]byte
}

func (m *indexMerger) add(value []byte) error {
	buf := make([]byte, len(value))
	copy(buf, value)
	m.operands = append(m.operands, buf)
	return nil
}

func (m *indexMerger) MergeNewer(value []byte) error { return m.add(value) }
func (m *indexMerger) MergeOlder(value []byte) error { return m.add(value) }

func (m *indexMerger) Finish(_ bool) ([]byte, io.Closer, error) {
	var result []dataTypes.RootID
	seen := make(map[dataTypes.RootID]struct{})
	for _, op := range m.operands {
		var partial []dataTypes.RootID
		if err := util.Unmarshal(op, &partial); err != nil {
			return nil, nil, errors.Wrap(err, "unmarshal index operand")
		}
		for _, id := range partial {
			if _, ok := seen[id]; !ok {
				seen[id] = struct{}{}
				result = append(result, id)
			}
		}
	}
	bs, err := util.Marshal(result)
	if err != nil {
		return nil, nil, errors.Wrap(err, "marshal merged index")
	}
	return bs, nil, nil
}

// advisoryMerger merges map[SourceID]map[RootID][]Advisory values.
type advisoryMerger struct {
	operands [][]byte
}

func (m *advisoryMerger) add(value []byte) error {
	buf := make([]byte, len(value))
	copy(buf, value)
	m.operands = append(m.operands, buf)
	return nil
}

func (m *advisoryMerger) MergeNewer(value []byte) error { return m.add(value) }
func (m *advisoryMerger) MergeOlder(value []byte) error { return m.add(value) }

func (m *advisoryMerger) Finish(_ bool) ([]byte, io.Closer, error) {
	result := make(map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory)
	for _, op := range m.operands {
		var partial map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory
		if err := util.Unmarshal(op, &partial); err != nil {
			return nil, nil, errors.Wrap(err, "unmarshal advisory operand")
		}
		for sid, roots := range partial {
			if result[sid] == nil {
				result[sid] = make(map[dataTypes.RootID][]advisoryTypes.Advisory)
			}
			for rid, advisories := range roots {
				result[sid][rid] = append(result[sid][rid], advisories...)
			}
		}
	}
	bs, err := util.Marshal(result)
	if err != nil {
		return nil, nil, errors.Wrap(err, "marshal merged advisory")
	}
	return bs, nil, nil
}

// vulnerabilityMerger merges map[SourceID]map[RootID][]Vulnerability values.
type vulnerabilityMerger struct {
	operands [][]byte
}

func (m *vulnerabilityMerger) add(value []byte) error {
	buf := make([]byte, len(value))
	copy(buf, value)
	m.operands = append(m.operands, buf)
	return nil
}

func (m *vulnerabilityMerger) MergeNewer(value []byte) error { return m.add(value) }
func (m *vulnerabilityMerger) MergeOlder(value []byte) error { return m.add(value) }

func (m *vulnerabilityMerger) Finish(_ bool) ([]byte, io.Closer, error) {
	result := make(map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability)
	for _, op := range m.operands {
		var partial map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability
		if err := util.Unmarshal(op, &partial); err != nil {
			return nil, nil, errors.Wrap(err, "unmarshal vulnerability operand")
		}
		for sid, roots := range partial {
			if result[sid] == nil {
				result[sid] = make(map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability)
			}
			for rid, vulns := range roots {
				result[sid][rid] = append(result[sid][rid], vulns...)
			}
		}
	}
	bs, err := util.Marshal(result)
	if err != nil {
		return nil, nil, errors.Wrap(err, "marshal merged vulnerability")
	}
	return bs, nil, nil
}

// rootMerger merges vulnerabilityRoot values, deduplicating each slice field.
type rootMerger struct {
	operands [][]byte
}

func (m *rootMerger) add(value []byte) error {
	buf := make([]byte, len(value))
	copy(buf, value)
	m.operands = append(m.operands, buf)
	return nil
}

func (m *rootMerger) MergeNewer(value []byte) error { return m.add(value) }
func (m *rootMerger) MergeOlder(value []byte) error { return m.add(value) }

func (m *rootMerger) Finish(_ bool) ([]byte, io.Closer, error) {
	var result vulnerabilityRoot
	for _, op := range m.operands {
		var r vulnerabilityRoot
		if err := util.Unmarshal(op, &r); err != nil {
			return nil, nil, errors.Wrap(err, "unmarshal root operand")
		}
		if result.ID == "" {
			result.ID = r.ID
		}
		for _, a := range r.Advisories {
			if !slices.Contains(result.Advisories, a) {
				result.Advisories = append(result.Advisories, a)
			}
		}
		for _, v := range r.Vulnerabilities {
			if !slices.Contains(result.Vulnerabilities, v) {
				result.Vulnerabilities = append(result.Vulnerabilities, v)
			}
		}
		for _, e := range r.Ecosystems {
			if !slices.Contains(result.Ecosystems, e) {
				result.Ecosystems = append(result.Ecosystems, e)
			}
		}
		for _, d := range r.DataSources {
			if !slices.Contains(result.DataSources, d) {
				result.DataSources = append(result.DataSources, d)
			}
		}
	}
	bs, err := util.Marshal(result)
	if err != nil {
		return nil, nil, errors.Wrap(err, "marshal merged root")
	}
	return bs, nil, nil
}
