package types

import (
	"time"

	capecTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/capec"
	mitigationTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/capec/mitigation"
	skillsrequiredTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/capec/skillsrequired"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
)

// CAPECData is the session-layer view of a CAPEC record returned by
// Session.GetCAPECData. Carries per-source contents under Contents and
// the union of contributing data-source provenance under DataSources.
type CAPECData struct {
	ID          string                                `json:"id"`
	Contents    map[sourceTypes.SourceID]CAPECContent `json:"contents,omitempty"`
	DataSources []datasourceTypes.DataSource          `json:"datasources,omitempty"`
}

// CAPECContent is the per-source body of a CAPEC record. Mirrors
// capecTypes.CAPEC with within-catalog ID references (ChildOf /
// ParentOf / CanFollow / CanPrecede / PeerOf) replaced by CAPECRef.
type CAPECContent struct {
	Name                string                             `json:"name,omitempty"`
	Description         string                             `json:"description,omitempty"`
	ExtendedDescription string                             `json:"extended_description,omitempty"`
	Abstraction         string                             `json:"abstraction,omitempty"`
	Status              string                             `json:"status,omitempty"`
	LikelihoodOfAttack  string                             `json:"likelihood_of_attack,omitempty"`
	TypicalSeverity     string                             `json:"typical_severity,omitempty"`
	Domains             []string                           `json:"domains,omitempty"`
	Prerequisites       []string                           `json:"prerequisites,omitempty"`
	SkillsRequired      skillsrequiredTypes.SkillsRequired `json:"skills_required,omitzero"`
	ResourcesRequired   []string                           `json:"resources_required,omitempty"`
	Consequences        map[string][]string                `json:"consequences,omitempty"`
	ExampleInstances    []string                           `json:"example_instances,omitempty"`
	Mitigations         []mitigationTypes.Mitigation       `json:"mitigations,omitempty"`
	ExecutionFlow       string                             `json:"execution_flow,omitempty"`
	RelatedCWEs         []string                           `json:"related_cwes,omitempty"`
	RelatedAttacks      []string                           `json:"related_attacks,omitempty"`
	ChildOf             []CAPECRef                         `json:"child_of,omitempty"`
	ParentOf            []CAPECRef                         `json:"parent_of,omitempty"`
	CanFollow           []CAPECRef                         `json:"can_follow,omitempty"`
	CanPrecede          []CAPECRef                         `json:"can_precede,omitempty"`
	PeerOf              []CAPECRef                         `json:"peer_of,omitempty"`
	AlternateTerms      []string                           `json:"alternate_terms,omitempty"`
	Version             string                             `json:"version,omitempty"`
	Modified            time.Time                          `json:"modified,omitzero"`
	References          []referenceTypes.Reference         `json:"references,omitempty"`
	DataSource          sourceTypes.Source                 `json:"data_source,omitzero"`
}

// CAPECRef is the minimal CAPEC reference embedded inside a CAPECContent
// whenever the source record carries another CAPEC's external ID.
type CAPECRef struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// ToCAPECRef converts a CAPEC external ID to a CAPECRef by looking up
// the cache. When the ID isn't cached, only the ID is set.
func ToCAPECRef(id string, cache map[string]capecTypes.CAPEC) CAPECRef {
	if c, ok := cache[id]; ok {
		return CAPECRef{ID: c.ID, Name: c.Name, Description: c.Description}
	}
	return CAPECRef{ID: id}
}

// ToCAPECRefs is the slice form of ToCAPECRef.
func ToCAPECRefs(ids []string, cache map[string]capecTypes.CAPEC) []CAPECRef {
	if len(ids) == 0 {
		return nil
	}
	out := make([]CAPECRef, 0, len(ids))
	for _, id := range ids {
		out = append(out, ToCAPECRef(id, cache))
	}
	return out
}

// ToCAPECContent converts a per-source capecTypes.CAPEC into the
// embedded-refs CAPECContent view.
func ToCAPECContent(c capecTypes.CAPEC, cache map[string]capecTypes.CAPEC) CAPECContent {
	return CAPECContent{
		Name:                c.Name,
		Description:         c.Description,
		ExtendedDescription: c.ExtendedDescription,
		Abstraction:         c.Abstraction,
		Status:              c.Status,
		LikelihoodOfAttack:  c.LikelihoodOfAttack,
		TypicalSeverity:     c.TypicalSeverity,
		Domains:             c.Domains,
		Prerequisites:       c.Prerequisites,
		SkillsRequired:      c.SkillsRequired,
		ResourcesRequired:   c.ResourcesRequired,
		Consequences:        c.Consequences,
		ExampleInstances:    c.ExampleInstances,
		Mitigations:         c.Mitigations,
		ExecutionFlow:       c.ExecutionFlow,
		RelatedCWEs:         c.RelatedCWEs,
		RelatedAttacks:      c.RelatedAttacks,
		ChildOf:             ToCAPECRefs(c.ChildOf, cache),
		ParentOf:            ToCAPECRefs(c.ParentOf, cache),
		CanFollow:           ToCAPECRefs(c.CanFollow, cache),
		CanPrecede:          ToCAPECRefs(c.CanPrecede, cache),
		PeerOf:              ToCAPECRefs(c.PeerOf, cache),
		AlternateTerms:      c.AlternateTerms,
		Version:             c.Version,
		Modified:            c.Modified,
		References:          c.References,
		DataSource:          c.DataSource,
	}
}
