package search

import (
	"time"

	capecTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/capec"
	mitigationTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/capec/mitigation"
	skillsrequiredTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/capec/skillsrequired"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
)

// CAPECRef is the minimal reference embedded in a CAPECResult whenever
// the underlying CAPEC record holds another CAPEC's ID. Carries {ID,
// Name, Description} so a single response renders the bidirectional
// relationship view from one query.
type CAPECRef struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// CAPECResult mirrors capecTypes.CAPEC but replaces the within-catalog
// reference IDs (ChildOf / ParentOf / CanFollow / CanPrecede / PeerOf)
// with embedded CAPECRef values. Cross-catalog references (RelatedCWEs,
// RelatedAttacks) stay as raw ID lists since the search command targets
// one catalog at a time.
type CAPECResult struct {
	ID                  string                             `json:"id"`
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

func toCAPECRef(id string, cache map[string]*capecTypes.CAPEC) CAPECRef {
	if id == "" {
		return CAPECRef{}
	}
	if c, ok := cache[id]; ok && c != nil {
		return CAPECRef{ID: c.ID, Name: c.Name, Description: c.Description}
	}
	return CAPECRef{ID: id}
}

func toCAPECRefs(ids []string, cache map[string]*capecTypes.CAPEC) []CAPECRef {
	if len(ids) == 0 {
		return nil
	}
	out := make([]CAPECRef, 0, len(ids))
	for _, id := range ids {
		out = append(out, toCAPECRef(id, cache))
	}
	return out
}

func toCAPECResult(c *capecTypes.CAPEC, cache map[string]*capecTypes.CAPEC) CAPECResult {
	if c == nil {
		return CAPECResult{}
	}
	return CAPECResult{
		ID:                  c.ID,
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
		ChildOf:             toCAPECRefs(c.ChildOf, cache),
		ParentOf:            toCAPECRefs(c.ParentOf, cache),
		CanFollow:           toCAPECRefs(c.CanFollow, cache),
		CanPrecede:          toCAPECRefs(c.CanPrecede, cache),
		PeerOf:              toCAPECRefs(c.PeerOf, cache),
		AlternateTerms:      c.AlternateTerms,
		Version:             c.Version,
		Modified:            c.Modified,
		References:          c.References,
		DataSource:          c.DataSource,
	}
}
