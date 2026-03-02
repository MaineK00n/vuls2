package util

import (
	"encoding/json"
	"time"

	"github.com/pkg/errors"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	advisoryContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	cweTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/cwe"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	noneexistcriterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion"
	necBinaryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion/binary"
	necSourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion/source"
	versioncriterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion"
	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	rangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
	packageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	vcBinaryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	cpeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/cpe"
	languageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/language"
	vcSourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/source"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	epssTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/epss"
	exploitTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/exploit"
	kevTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/kev"
	metasploitTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/metasploit"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
	cvssV2Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v2"
	cvssV30Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v30"
	cvssV31Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v31"
	cvssV40Types "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity/cvss/v40"
	snortTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/snort"
	vulnerabilityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability"
	vulnerabilityContentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/vulnerability/content"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"

	pb "github.com/MaineK00n/vuls2/pkg/db/session/internal/boltdb/pb"
	dbTypes "github.com/MaineK00n/vuls2/pkg/db/session/types"
)

// ============================================================
// MarshalPB / UnmarshalPB  — type-switched entry points
// ============================================================

// MarshalPB serializes a known Go value to protobuf wire format.
// Supported types are the same ones stored in boltdb buckets.
func MarshalPB(v any) ([]byte, error) {
	msg, err := toProto(v)
	if err != nil {
		return nil, err
	}
	bs, err := proto.Marshal(msg)
	if err != nil {
		return nil, errors.Wrap(err, "protobuf marshal")
	}
	return bs, nil
}

func toProto(v any) (proto.Message, error) {
	switch val := v.(type) {
	case dbTypes.Metadata:
		return metadataToProto(val), nil
	case *dbTypes.Metadata:
		return metadataToProto(*val), nil

	// vulnerabilityRoot is package-private, so we accept it via the exported wrapper
	// Actually, we need a different approach. We'll define a VulnerabilityRootData struct.
	case VulnerabilityRootData:
		return vulnRootToProto(val), nil

	case map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory:
		return advisoryMapToProto(val), nil

	case map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability:
		return vulnMapToProto(val), nil

	case map[sourceTypes.SourceID][]conditionTypes.Condition:
		return detectionMapToProto(val), nil

	case []dataTypes.RootID:
		return rootIDListToProto(val), nil

	case datasourceTypes.DataSource:
		return datasourceToProto(val), nil

	default:
		return nil, errors.Errorf("MarshalPB: unsupported type %T", v)
	}
}

// UnmarshalPB deserializes protobuf wire format into target.
// target must be a pointer to a supported type.
func UnmarshalPB(data []byte, target any) error {
	switch t := target.(type) {
	case *dbTypes.Metadata:
		var msg pb.Metadata
		if err := proto.Unmarshal(data, &msg); err != nil {
			return errors.Wrap(err, "protobuf unmarshal Metadata")
		}
		*t = metadataFromProto(&msg)
		return nil

	case *VulnerabilityRootData:
		var msg pb.VulnerabilityRoot
		if err := proto.Unmarshal(data, &msg); err != nil {
			return errors.Wrap(err, "protobuf unmarshal VulnerabilityRoot")
		}
		*t = vulnRootFromProto(&msg)
		return nil

	case *map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory:
		var msg pb.AdvisoryMap
		if err := proto.Unmarshal(data, &msg); err != nil {
			return errors.Wrap(err, "protobuf unmarshal AdvisoryMap")
		}
		*t = advisoryMapFromProto(&msg)
		return nil

	case *map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability:
		var msg pb.VulnerabilityMap
		if err := proto.Unmarshal(data, &msg); err != nil {
			return errors.Wrap(err, "protobuf unmarshal VulnerabilityMap")
		}
		*t = vulnMapFromProto(&msg)
		return nil

	case *map[sourceTypes.SourceID][]conditionTypes.Condition:
		var msg pb.DetectionConditionMap
		if err := proto.Unmarshal(data, &msg); err != nil {
			return errors.Wrap(err, "protobuf unmarshal DetectionConditionMap")
		}
		*t = detectionMapFromProto(&msg)
		return nil

	case *[]dataTypes.RootID:
		var msg pb.RootIDList
		if err := proto.Unmarshal(data, &msg); err != nil {
			return errors.Wrap(err, "protobuf unmarshal RootIDList")
		}
		*t = rootIDListFromProto(&msg)
		return nil

	case *datasourceTypes.DataSource:
		var msg pb.DataSource
		if err := proto.Unmarshal(data, &msg); err != nil {
			return errors.Wrap(err, "protobuf unmarshal DataSource")
		}
		*t = datasourceFromProto(&msg)
		return nil

	default:
		return errors.Errorf("UnmarshalPB: unsupported type %T", target)
	}
}

// VulnerabilityRootData mirrors the package-private vulnerabilityRoot in boltdb.
type VulnerabilityRootData struct {
	ID              dataTypes.RootID
	Advisories      []advisoryContentTypes.AdvisoryID
	Vulnerabilities []vulnerabilityContentTypes.VulnerabilityID
	Ecosystems      []ecosystemTypes.Ecosystem
	DataSources     []sourceTypes.SourceID
}

// ============================================================
// Timestamp helpers
// ============================================================

func tsToProto(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func tsFromProto(t *timestamppb.Timestamp) *time.Time {
	if t == nil {
		return nil
	}
	v := t.AsTime()
	return &v
}

func tsValToProto(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

func tsValFromProto(t *timestamppb.Timestamp) time.Time {
	if t == nil {
		return time.Time{}
	}
	return t.AsTime()
}

// ============================================================
// Metadata
// ============================================================

func metadataToProto(m dbTypes.Metadata) *pb.Metadata {
	msg := &pb.Metadata{
		SchemaVersion: uint32(m.SchemaVersion),
		CreatedBy:     m.CreatedBy,
		LastModified:  tsValToProto(m.LastModified),
		Digest:        m.Digest,
	}
	if m.Downloaded != nil {
		msg.Downloaded = tsToProto(m.Downloaded)
	}
	return msg
}

func metadataFromProto(msg *pb.Metadata) dbTypes.Metadata {
	m := dbTypes.Metadata{
		SchemaVersion: uint(msg.SchemaVersion),
		CreatedBy:     msg.CreatedBy,
		LastModified:  tsValFromProto(msg.LastModified),
		Digest:        msg.Digest,
		Downloaded:    tsFromProto(msg.Downloaded),
	}
	return m
}

// ============================================================
// VulnerabilityRoot
// ============================================================

func vulnRootToProto(r VulnerabilityRootData) *pb.VulnerabilityRoot {
	msg := &pb.VulnerabilityRoot{
		Id: string(r.ID),
	}
	for _, a := range r.Advisories {
		msg.Advisories = append(msg.Advisories, string(a))
	}
	for _, v := range r.Vulnerabilities {
		msg.Vulnerabilities = append(msg.Vulnerabilities, string(v))
	}
	for _, e := range r.Ecosystems {
		msg.Ecosystems = append(msg.Ecosystems, string(e))
	}
	for _, d := range r.DataSources {
		msg.DataSources = append(msg.DataSources, string(d))
	}
	return msg
}

func vulnRootFromProto(msg *pb.VulnerabilityRoot) VulnerabilityRootData {
	r := VulnerabilityRootData{
		ID: dataTypes.RootID(msg.Id),
	}
	for _, a := range msg.Advisories {
		r.Advisories = append(r.Advisories, advisoryContentTypes.AdvisoryID(a))
	}
	for _, v := range msg.Vulnerabilities {
		r.Vulnerabilities = append(r.Vulnerabilities, vulnerabilityContentTypes.VulnerabilityID(v))
	}
	for _, e := range msg.Ecosystems {
		r.Ecosystems = append(r.Ecosystems, ecosystemTypes.Ecosystem(e))
	}
	for _, d := range msg.DataSources {
		r.DataSources = append(r.DataSources, sourceTypes.SourceID(d))
	}
	return r
}

// ============================================================
// Advisory map
// ============================================================

func advisoryMapToProto(m map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory) *pb.AdvisoryMap {
	msg := &pb.AdvisoryMap{
		Entries: make(map[string]*pb.RootAdvisoryMap, len(m)),
	}
	for sid, rootMap := range m {
		ram := &pb.RootAdvisoryMap{
			Entries: make(map[string]*pb.AdvisoryList, len(rootMap)),
		}
		for rid, advisories := range rootMap {
			al := &pb.AdvisoryList{}
			for _, a := range advisories {
				al.Items = append(al.Items, advisoryToProto(a))
			}
			ram.Entries[string(rid)] = al
		}
		msg.Entries[string(sid)] = ram
	}
	return msg
}

func advisoryMapFromProto(msg *pb.AdvisoryMap) map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory {
	m := make(map[sourceTypes.SourceID]map[dataTypes.RootID][]advisoryTypes.Advisory, len(msg.Entries))
	for sid, ram := range msg.Entries {
		rootMap := make(map[dataTypes.RootID][]advisoryTypes.Advisory, len(ram.Entries))
		for rid, al := range ram.Entries {
			var advisories []advisoryTypes.Advisory
			for _, a := range al.Items {
				advisories = append(advisories, advisoryFromProto(a))
			}
			rootMap[dataTypes.RootID(rid)] = advisories
		}
		m[sourceTypes.SourceID(sid)] = rootMap
	}
	return m
}

func advisoryToProto(a advisoryTypes.Advisory) *pb.Advisory {
	msg := &pb.Advisory{
		Content: advisoryContentToProto(a.Content),
	}
	for _, s := range a.Segments {
		msg.Segments = append(msg.Segments, segmentToProto(s))
	}
	return msg
}

func advisoryFromProto(msg *pb.Advisory) advisoryTypes.Advisory {
	a := advisoryTypes.Advisory{
		Content: advisoryContentFromProto(msg.Content),
	}
	for _, s := range msg.Segments {
		a.Segments = append(a.Segments, segmentFromProto(s))
	}
	return a
}

func advisoryContentToProto(c advisoryContentTypes.Content) *pb.AdvisoryContent {
	msg := &pb.AdvisoryContent{
		Id:          string(c.ID),
		Title:       c.Title,
		Description: c.Description,
		Published:   tsToProto(c.Published),
		Modified:    tsToProto(c.Modified),
	}
	for _, s := range c.Severity {
		msg.Severity = append(msg.Severity, severityToProto(s))
	}
	for _, cw := range c.CWE {
		msg.Cwe = append(msg.Cwe, cweToProto(cw))
	}
	for _, r := range c.References {
		msg.References = append(msg.References, referenceToProto(r))
	}
	if c.Optional != nil {
		if bs, err := json.Marshal(c.Optional); err == nil {
			msg.OptionalJson = bs
		}
	}
	return msg
}

func advisoryContentFromProto(msg *pb.AdvisoryContent) advisoryContentTypes.Content {
	if msg == nil {
		return advisoryContentTypes.Content{}
	}
	c := advisoryContentTypes.Content{
		ID:          advisoryContentTypes.AdvisoryID(msg.Id),
		Title:       msg.Title,
		Description: msg.Description,
		Published:   tsFromProto(msg.Published),
		Modified:    tsFromProto(msg.Modified),
	}
	for _, s := range msg.Severity {
		c.Severity = append(c.Severity, severityFromProto(s))
	}
	for _, cw := range msg.Cwe {
		c.CWE = append(c.CWE, cweFromProto(cw))
	}
	for _, r := range msg.References {
		c.References = append(c.References, referenceFromProto(r))
	}
	if len(msg.OptionalJson) > 0 {
		_ = json.Unmarshal(msg.OptionalJson, &c.Optional)
	}
	return c
}

// ============================================================
// Vulnerability map
// ============================================================

func vulnMapToProto(m map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability) *pb.VulnerabilityMap {
	msg := &pb.VulnerabilityMap{
		Entries: make(map[string]*pb.RootVulnerabilityMap, len(m)),
	}
	for sid, rootMap := range m {
		rvm := &pb.RootVulnerabilityMap{
			Entries: make(map[string]*pb.VulnerabilityList, len(rootMap)),
		}
		for rid, vulns := range rootMap {
			vl := &pb.VulnerabilityList{}
			for _, v := range vulns {
				vl.Items = append(vl.Items, vulnerabilityToProto(v))
			}
			rvm.Entries[string(rid)] = vl
		}
		msg.Entries[string(sid)] = rvm
	}
	return msg
}

func vulnMapFromProto(msg *pb.VulnerabilityMap) map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability {
	m := make(map[sourceTypes.SourceID]map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability, len(msg.Entries))
	for sid, rvm := range msg.Entries {
		rootMap := make(map[dataTypes.RootID][]vulnerabilityTypes.Vulnerability, len(rvm.Entries))
		for rid, vl := range rvm.Entries {
			var vulns []vulnerabilityTypes.Vulnerability
			for _, v := range vl.Items {
				vulns = append(vulns, vulnerabilityFromProto(v))
			}
			rootMap[dataTypes.RootID(rid)] = vulns
		}
		m[sourceTypes.SourceID(sid)] = rootMap
	}
	return m
}

func vulnerabilityToProto(v vulnerabilityTypes.Vulnerability) *pb.Vulnerability {
	msg := &pb.Vulnerability{
		Content: vulnerabilityContentToProto(v.Content),
	}
	for _, s := range v.Segments {
		msg.Segments = append(msg.Segments, segmentToProto(s))
	}
	return msg
}

func vulnerabilityFromProto(msg *pb.Vulnerability) vulnerabilityTypes.Vulnerability {
	v := vulnerabilityTypes.Vulnerability{
		Content: vulnerabilityContentFromProto(msg.Content),
	}
	for _, s := range msg.Segments {
		v.Segments = append(v.Segments, segmentFromProto(s))
	}
	return v
}

func vulnerabilityContentToProto(c vulnerabilityContentTypes.Content) *pb.VulnerabilityContent {
	msg := &pb.VulnerabilityContent{
		Id:          string(c.ID),
		Title:       c.Title,
		Description: c.Description,
		Published:   tsToProto(c.Published),
		Modified:    tsToProto(c.Modified),
	}
	for _, s := range c.Severity {
		msg.Severity = append(msg.Severity, severityToProto(s))
	}
	for _, cw := range c.CWE {
		msg.Cwe = append(msg.Cwe, cweToProto(cw))
	}
	for _, e := range c.Exploit {
		msg.Exploit = append(msg.Exploit, exploitToProto(e))
	}
	for _, m := range c.Metasploit {
		msg.Metasploit = append(msg.Metasploit, metasploitToProto(m))
	}
	if c.EPSS != nil {
		msg.Epss = epssToProto(c.EPSS)
	}
	for _, s := range c.Snort {
		_ = s // Snort is an empty struct
		msg.Snort = append(msg.Snort, &pb.Snort{})
	}
	if c.KEV != nil {
		msg.Kev = kevToProto(c.KEV)
	}
	for _, r := range c.References {
		msg.References = append(msg.References, referenceToProto(r))
	}
	if c.Optional != nil {
		if bs, err := json.Marshal(c.Optional); err == nil {
			msg.OptionalJson = bs
		}
	}
	return msg
}

func vulnerabilityContentFromProto(msg *pb.VulnerabilityContent) vulnerabilityContentTypes.Content {
	if msg == nil {
		return vulnerabilityContentTypes.Content{}
	}
	c := vulnerabilityContentTypes.Content{
		ID:          vulnerabilityContentTypes.VulnerabilityID(msg.Id),
		Title:       msg.Title,
		Description: msg.Description,
		Published:   tsFromProto(msg.Published),
		Modified:    tsFromProto(msg.Modified),
	}
	for _, s := range msg.Severity {
		c.Severity = append(c.Severity, severityFromProto(s))
	}
	for _, cw := range msg.Cwe {
		c.CWE = append(c.CWE, cweFromProto(cw))
	}
	for _, e := range msg.Exploit {
		c.Exploit = append(c.Exploit, exploitFromProto(e))
	}
	for _, m := range msg.Metasploit {
		c.Metasploit = append(c.Metasploit, metasploitFromProto(m))
	}
	if msg.Epss != nil {
		c.EPSS = epssFromProto(msg.Epss)
	}
	for range msg.Snort {
		c.Snort = append(c.Snort, snortTypes.Snort{})
	}
	if msg.Kev != nil {
		c.KEV = kevFromProto(msg.Kev)
	}
	for _, r := range msg.References {
		c.References = append(c.References, referenceFromProto(r))
	}
	if len(msg.OptionalJson) > 0 {
		_ = json.Unmarshal(msg.OptionalJson, &c.Optional)
	}
	return c
}

// ============================================================
// Detection condition map
// ============================================================

func detectionMapToProto(m map[sourceTypes.SourceID][]conditionTypes.Condition) *pb.DetectionConditionMap {
	msg := &pb.DetectionConditionMap{
		Entries: make(map[string]*pb.ConditionList, len(m)),
	}
	for sid, conds := range m {
		cl := &pb.ConditionList{}
		for _, c := range conds {
			cl.Items = append(cl.Items, conditionToProto(c))
		}
		msg.Entries[string(sid)] = cl
	}
	return msg
}

func detectionMapFromProto(msg *pb.DetectionConditionMap) map[sourceTypes.SourceID][]conditionTypes.Condition {
	m := make(map[sourceTypes.SourceID][]conditionTypes.Condition, len(msg.Entries))
	for sid, cl := range msg.Entries {
		var conds []conditionTypes.Condition
		for _, c := range cl.Items {
			conds = append(conds, conditionFromProto(c))
		}
		m[sourceTypes.SourceID(sid)] = conds
	}
	return m
}

func conditionToProto(c conditionTypes.Condition) *pb.Condition {
	return &pb.Condition{
		Criteria: criteriaToProto(c.Criteria),
		Tag:      string(c.Tag),
	}
}

func conditionFromProto(msg *pb.Condition) conditionTypes.Condition {
	return conditionTypes.Condition{
		Criteria: criteriaFromProto(msg.Criteria),
		Tag:      segmentTypes.DetectionTag(msg.Tag),
	}
}

// ============================================================
// Criteria (recursive)
// ============================================================

func criteriaToProto(c criteriaTypes.Criteria) *pb.Criteria {
	msg := &pb.Criteria{
		Operator: pb.CriteriaOperator(c.Operator),
	}
	for _, sub := range c.Criterias {
		msg.Criterias = append(msg.Criterias, criteriaToProto(sub))
	}
	for _, cn := range c.Criterions {
		msg.Criterions = append(msg.Criterions, criterionToProto(cn))
	}
	return msg
}

func criteriaFromProto(msg *pb.Criteria) criteriaTypes.Criteria {
	if msg == nil {
		return criteriaTypes.Criteria{}
	}
	c := criteriaTypes.Criteria{
		Operator: criteriaTypes.CriteriaOperatorType(msg.Operator),
	}
	for _, sub := range msg.Criterias {
		c.Criterias = append(c.Criterias, criteriaFromProto(sub))
	}
	for _, cn := range msg.Criterions {
		c.Criterions = append(c.Criterions, criterionFromProto(cn))
	}
	return c
}

// ============================================================
// Criterion
// ============================================================

func criterionToProto(cn criterionTypes.Criterion) *pb.Criterion {
	msg := &pb.Criterion{
		Type: pb.CriterionType(cn.Type),
	}
	if cn.Version != nil {
		msg.Version = versionCriterionToProto(cn.Version)
	}
	if cn.NoneExist != nil {
		msg.NoneExist = noneExistCriterionToProto(cn.NoneExist)
	}
	return msg
}

func criterionFromProto(msg *pb.Criterion) criterionTypes.Criterion {
	cn := criterionTypes.Criterion{
		Type: criterionTypes.CriterionType(msg.Type),
	}
	if msg.Version != nil {
		vc := versionCriterionFromProto(msg.Version)
		cn.Version = &vc
	}
	if msg.NoneExist != nil {
		nec := noneExistCriterionFromProto(msg.NoneExist)
		cn.NoneExist = &nec
	}
	return cn
}

// ============================================================
// Version Criterion
// ============================================================

func versionCriterionToProto(vc *versioncriterionTypes.Criterion) *pb.VersionCriterion {
	msg := &pb.VersionCriterion{
		Vulnerable: vc.Vulnerable,
		Package:    packageToProto(vc.Package),
	}
	if vc.FixStatus != nil {
		msg.FixStatus = &pb.FixStatus{
			Class:  string(vc.FixStatus.Class),
			Vendor: vc.FixStatus.Vendor,
		}
	}
	if vc.Affected != nil {
		msg.Affected = affectedToProto(vc.Affected)
	}
	return msg
}

func versionCriterionFromProto(msg *pb.VersionCriterion) versioncriterionTypes.Criterion {
	vc := versioncriterionTypes.Criterion{
		Vulnerable: msg.Vulnerable,
		Package:    packageFromProto(msg.Package),
	}
	if msg.FixStatus != nil {
		vc.FixStatus = &fixstatusTypes.FixStatus{
			Class:  fixstatusTypes.Class(msg.FixStatus.Class),
			Vendor: msg.FixStatus.Vendor,
		}
	}
	if msg.Affected != nil {
		a := affectedFromProto(msg.Affected)
		vc.Affected = &a
	}
	return vc
}

// ============================================================
// Package
// ============================================================

func packageToProto(p packageTypes.Package) *pb.Package {
	msg := &pb.Package{
		Type: pb.PackageType(p.Type),
	}
	if p.Binary != nil {
		msg.Binary = &pb.BinaryPackage{
			Name:          p.Binary.Name,
			Architectures: p.Binary.Architectures,
			Repositories:  p.Binary.Repositories,
		}
	}
	if p.Source != nil {
		msg.Source = &pb.SourcePackage{
			Name:         p.Source.Name,
			Repositories: p.Source.Repositories,
		}
	}
	if p.CPE != nil {
		msg.Cpe = string(*p.CPE)
	}
	if p.Language != nil {
		msg.Language = &pb.LanguagePackage{
			Name:          p.Language.Name,
			Architectures: p.Language.Architectures,
			Functions:     p.Language.Functions,
		}
	}
	return msg
}

func packageFromProto(msg *pb.Package) packageTypes.Package {
	if msg == nil {
		return packageTypes.Package{}
	}
	p := packageTypes.Package{
		Type: packageTypes.PackageType(msg.Type),
	}
	if msg.Binary != nil {
		p.Binary = &vcBinaryTypes.Package{
			Name:          msg.Binary.Name,
			Architectures: msg.Binary.Architectures,
			Repositories:  msg.Binary.Repositories,
		}
	}
	if msg.Source != nil {
		p.Source = &vcSourceTypes.Package{
			Name:         msg.Source.Name,
			Repositories: msg.Source.Repositories,
		}
	}
	if msg.Cpe != "" {
		cpe := cpeTypes.CPE(msg.Cpe)
		p.CPE = &cpe
	}
	if msg.Language != nil {
		p.Language = &languageTypes.Package{
			Name:          msg.Language.Name,
			Architectures: msg.Language.Architectures,
			Functions:     msg.Language.Functions,
		}
	}
	return p
}

// ============================================================
// Affected & Range
// ============================================================

func affectedToProto(a *affectedTypes.Affected) *pb.Affected {
	msg := &pb.Affected{
		Type:  pb.RangeType(a.Type),
		Fixed: a.Fixed,
	}
	for _, r := range a.Range {
		msg.Range = append(msg.Range, &pb.Range{
			Eq: r.Equal,
			Lt: r.LessThan,
			Le: r.LessEqual,
			Gt: r.GreaterThan,
			Ge: r.GreaterEqual,
		})
	}
	return msg
}

func affectedFromProto(msg *pb.Affected) affectedTypes.Affected {
	a := affectedTypes.Affected{
		Type:  rangeTypes.RangeType(msg.Type),
		Fixed: msg.Fixed,
	}
	for _, r := range msg.Range {
		a.Range = append(a.Range, rangeTypes.Range{
			Equal:        r.Eq,
			LessThan:     r.Lt,
			LessEqual:    r.Le,
			GreaterThan:  r.Gt,
			GreaterEqual: r.Ge,
		})
	}
	return a
}

// ============================================================
// None-Exist Criterion
// ============================================================

func noneExistCriterionToProto(nec *noneexistcriterionTypes.Criterion) *pb.NoneExistCriterion {
	msg := &pb.NoneExistCriterion{
		Type: pb.NoneExistPackageType(nec.Type),
	}
	if nec.Binary != nil {
		msg.Binary = &pb.BinaryPackage{
			Name:          nec.Binary.Name,
			Architectures: nec.Binary.Architectures,
			Repositories:  nec.Binary.Repositories,
		}
	}
	if nec.Source != nil {
		msg.Source = &pb.SourcePackage{
			Name:         nec.Source.Name,
			Repositories: nec.Source.Repositories,
		}
	}
	return msg
}

func noneExistCriterionFromProto(msg *pb.NoneExistCriterion) noneexistcriterionTypes.Criterion {
	nec := noneexistcriterionTypes.Criterion{
		Type: noneexistcriterionTypes.PackageType(msg.Type),
	}
	if msg.Binary != nil {
		nec.Binary = &necBinaryTypes.Package{
			Name:          msg.Binary.Name,
			Architectures: msg.Binary.Architectures,
			Repositories:  msg.Binary.Repositories,
		}
	}
	if msg.Source != nil {
		nec.Source = &necSourceTypes.Package{
			Name:         msg.Source.Name,
			Repositories: msg.Source.Repositories,
		}
	}
	return nec
}

// ============================================================
// Segment
// ============================================================

func segmentToProto(s segmentTypes.Segment) *pb.Segment {
	return &pb.Segment{
		Ecosystem: string(s.Ecosystem),
		Tag:       string(s.Tag),
	}
}

func segmentFromProto(msg *pb.Segment) segmentTypes.Segment {
	return segmentTypes.Segment{
		Ecosystem: ecosystemTypes.Ecosystem(msg.Ecosystem),
		Tag:       segmentTypes.DetectionTag(msg.Tag),
	}
}

// ============================================================
// RootID list
// ============================================================

func rootIDListToProto(ids []dataTypes.RootID) *pb.RootIDList {
	msg := &pb.RootIDList{}
	for _, id := range ids {
		msg.Ids = append(msg.Ids, string(id))
	}
	return msg
}

func rootIDListFromProto(msg *pb.RootIDList) []dataTypes.RootID {
	ids := make([]dataTypes.RootID, 0, len(msg.Ids))
	for _, id := range msg.Ids {
		ids = append(ids, dataTypes.RootID(id))
	}
	return ids
}

// ============================================================
// DataSource
// ============================================================

func datasourceToProto(ds datasourceTypes.DataSource) *pb.DataSource {
	msg := &pb.DataSource{
		Id: string(ds.ID),
	}
	if ds.Name != nil {
		msg.Name = ds.Name
	}
	for _, r := range ds.Raw {
		msg.Raw = append(msg.Raw, repositoryToProto(r))
	}
	if ds.Extracted != nil {
		msg.Extracted = repositoryToProto(*ds.Extracted)
	}
	return msg
}

func datasourceFromProto(msg *pb.DataSource) datasourceTypes.DataSource {
	ds := datasourceTypes.DataSource{
		ID: sourceTypes.SourceID(msg.Id),
	}
	if msg.Name != nil {
		ds.Name = msg.Name
	}
	for _, r := range msg.Raw {
		ds.Raw = append(ds.Raw, repositoryFromProto(r))
	}
	if msg.Extracted != nil {
		e := repositoryFromProto(msg.Extracted)
		ds.Extracted = &e
	}
	return ds
}

func repositoryToProto(r repositoryTypes.Repository) *pb.Repository {
	return &pb.Repository{
		Url:    r.URL,
		Commit: r.Commit,
		Date:   tsToProto(r.Date),
	}
}

func repositoryFromProto(msg *pb.Repository) repositoryTypes.Repository {
	return repositoryTypes.Repository{
		URL:    msg.Url,
		Commit: msg.Commit,
		Date:   tsFromProto(msg.Date),
	}
}

// ============================================================
// Severity
// ============================================================

func severityToProto(s severityTypes.Severity) *pb.Severity {
	msg := &pb.Severity{
		Type:   pb.SeverityType(s.Type),
		Source: s.Source,
		Vendor: s.Vendor,
	}
	if s.CVSSv2 != nil {
		msg.CvssV2 = &pb.CVSSv2{
			Vector:                   s.CVSSv2.Vector,
			BaseScore:                s.CVSSv2.BaseScore,
			NvdBaseSeverity:          s.CVSSv2.NVDBaseSeverity,
			TemporalScore:            s.CVSSv2.TemporalScore,
			NvdTemporalSeverity:      s.CVSSv2.NVDTemporalSeverity,
			EnvironmentalScore:       s.CVSSv2.EnvironmentalScore,
			NvdEnvironmentalSeverity: s.CVSSv2.NVDEnvironmentalSeverity,
		}
	}
	if s.CVSSv30 != nil {
		msg.CvssV30 = &pb.CVSSv30{
			Vector:                s.CVSSv30.Vector,
			BaseScore:             s.CVSSv30.BaseScore,
			BaseSeverity:          s.CVSSv30.BaseSeverity,
			TemporalScore:         s.CVSSv30.TemporalScore,
			TemporalSeverity:      s.CVSSv30.TemporalSeverity,
			EnvironmentalScore:    s.CVSSv30.EnvironmentalScore,
			EnvironmentalSeverity: s.CVSSv30.EnvironmentalSeverity,
		}
	}
	if s.CVSSv31 != nil {
		msg.CvssV31 = &pb.CVSSv31{
			Vector:                s.CVSSv31.Vector,
			BaseScore:             s.CVSSv31.BaseScore,
			BaseSeverity:          s.CVSSv31.BaseSeverity,
			TemporalScore:         s.CVSSv31.TemporalScore,
			TemporalSeverity:      s.CVSSv31.TemporalSeverity,
			EnvironmentalScore:    s.CVSSv31.EnvironmentalScore,
			EnvironmentalSeverity: s.CVSSv31.EnvironmentalSeverity,
		}
	}
	if s.CVSSv40 != nil {
		msg.CvssV40 = &pb.CVSSv40{
			Vector:   s.CVSSv40.Vector,
			Score:    s.CVSSv40.Score,
			Severity: s.CVSSv40.Severity,
		}
	}
	return msg
}

func severityFromProto(msg *pb.Severity) severityTypes.Severity {
	s := severityTypes.Severity{
		Type:   severityTypes.SeverityType(msg.Type),
		Source: msg.Source,
		Vendor: msg.Vendor,
	}
	if msg.CvssV2 != nil {
		s.CVSSv2 = &cvssV2Types.CVSSv2{
			Vector:                   msg.CvssV2.Vector,
			BaseScore:                msg.CvssV2.BaseScore,
			NVDBaseSeverity:          msg.CvssV2.NvdBaseSeverity,
			TemporalScore:            msg.CvssV2.TemporalScore,
			NVDTemporalSeverity:      msg.CvssV2.NvdTemporalSeverity,
			EnvironmentalScore:       msg.CvssV2.EnvironmentalScore,
			NVDEnvironmentalSeverity: msg.CvssV2.NvdEnvironmentalSeverity,
		}
	}
	if msg.CvssV30 != nil {
		s.CVSSv30 = &cvssV30Types.CVSSv30{
			Vector:                msg.CvssV30.Vector,
			BaseScore:             msg.CvssV30.BaseScore,
			BaseSeverity:          msg.CvssV30.BaseSeverity,
			TemporalScore:         msg.CvssV30.TemporalScore,
			TemporalSeverity:      msg.CvssV30.TemporalSeverity,
			EnvironmentalScore:    msg.CvssV30.EnvironmentalScore,
			EnvironmentalSeverity: msg.CvssV30.EnvironmentalSeverity,
		}
	}
	if msg.CvssV31 != nil {
		s.CVSSv31 = &cvssV31Types.CVSSv31{
			Vector:                msg.CvssV31.Vector,
			BaseScore:             msg.CvssV31.BaseScore,
			BaseSeverity:          msg.CvssV31.BaseSeverity,
			TemporalScore:         msg.CvssV31.TemporalScore,
			TemporalSeverity:      msg.CvssV31.TemporalSeverity,
			EnvironmentalScore:    msg.CvssV31.EnvironmentalScore,
			EnvironmentalSeverity: msg.CvssV31.EnvironmentalSeverity,
		}
	}
	if msg.CvssV40 != nil {
		s.CVSSv40 = &cvssV40Types.CVSSv40{
			Vector:   msg.CvssV40.Vector,
			Score:    msg.CvssV40.Score,
			Severity: msg.CvssV40.Severity,
		}
	}
	return s
}

// ============================================================
// CWE, Reference
// ============================================================

func cweToProto(c cweTypes.CWE) *pb.CWE {
	return &pb.CWE{
		Source: c.Source,
		Cwe:    c.CWE,
	}
}

func cweFromProto(msg *pb.CWE) cweTypes.CWE {
	return cweTypes.CWE{
		Source: msg.Source,
		CWE:    msg.Cwe,
	}
}

func referenceToProto(r referenceTypes.Reference) *pb.Reference {
	return &pb.Reference{
		Source: r.Source,
		Url:    r.URL,
	}
}

func referenceFromProto(msg *pb.Reference) referenceTypes.Reference {
	return referenceTypes.Reference{
		Source: msg.Source,
		URL:    msg.Url,
	}
}

// ============================================================
// Exploit, Metasploit, EPSS, KEV
// ============================================================

func exploitToProto(e exploitTypes.Exploit) *pb.Exploit {
	return &pb.Exploit{
		Source:      e.Source,
		Id:          e.ID,
		Description: e.Description,
		Published:   tsToProto(e.Published),
		Modified:    tsToProto(e.Modified),
		Link:        e.Link,
	}
}

func exploitFromProto(msg *pb.Exploit) exploitTypes.Exploit {
	return exploitTypes.Exploit{
		Source:      msg.Source,
		ID:          msg.Id,
		Description: msg.Description,
		Published:   tsFromProto(msg.Published),
		Modified:    tsFromProto(msg.Modified),
		Link:        msg.Link,
	}
}

func metasploitToProto(m metasploitTypes.Metasploit) *pb.Metasploit {
	msg := &pb.Metasploit{
		Type:        m.Type,
		Name:        m.Name,
		FullName:    m.FullName,
		Description: m.Description,
		Rank:        int32(m.Rank),
		Published:   tsToProto(m.Published),
		Modified:    tsToProto(m.Modified),
	}
	for _, r := range m.References {
		msg.References = append(msg.References, referenceToProto(r))
	}
	return msg
}

func metasploitFromProto(msg *pb.Metasploit) metasploitTypes.Metasploit {
	m := metasploitTypes.Metasploit{
		Type:        msg.Type,
		Name:        msg.Name,
		FullName:    msg.FullName,
		Description: msg.Description,
		Rank:        int(msg.Rank),
		Published:   tsFromProto(msg.Published),
		Modified:    tsFromProto(msg.Modified),
	}
	for _, r := range msg.References {
		m.References = append(m.References, referenceFromProto(r))
	}
	return m
}

func epssToProto(e *epssTypes.EPSS) *pb.EPSS {
	msg := &pb.EPSS{
		Model:     e.Model,
		ScoreDate: tsValToProto(e.ScoreDate),
		Epss:      e.EPSS,
	}
	if e.Percentile != nil {
		msg.Percentile = e.Percentile
	}
	return msg
}

func epssFromProto(msg *pb.EPSS) *epssTypes.EPSS {
	e := &epssTypes.EPSS{
		Model:     msg.Model,
		ScoreDate: tsValFromProto(msg.ScoreDate),
		EPSS:      msg.Epss,
	}
	if msg.Percentile != nil {
		e.Percentile = msg.Percentile
	}
	return e
}

func kevToProto(k *kevTypes.KEV) *pb.KEV {
	return &pb.KEV{
		VendorProject:              k.VendorProject,
		Product:                    k.Product,
		RequiredAction:             k.RequiredAction,
		KnownRansomwareCampaignUse: k.KnownRansomwareCampaignUse,
		Notes:                      k.Notes,
		DateAdded:                  tsValToProto(k.DateAdded),
		DueDate:                    tsValToProto(k.DueDate),
	}
}

func kevFromProto(msg *pb.KEV) *kevTypes.KEV {
	return &kevTypes.KEV{
		VendorProject:              msg.VendorProject,
		Product:                    msg.Product,
		RequiredAction:             msg.RequiredAction,
		KnownRansomwareCampaignUse: msg.KnownRansomwareCampaignUse,
		Notes:                      msg.Notes,
		DateAdded:                  tsValFromProto(msg.DateAdded),
		DueDate:                    tsValFromProto(msg.DueDate),
	}
}
