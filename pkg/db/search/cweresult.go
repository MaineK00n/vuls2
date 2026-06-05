package search

import (
	cweTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe"
	mappingnotesTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/mappingnotes"
	memberTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/member"
	noteTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/note"
	taxonomymappingTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/taxonomymapping"
	audienceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/view/audience"
	alternatetermTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/alternateterm"
	applicableplatformTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/applicableplatform"
	commonconsequenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/commonconsequence"
	demonstrativeexampleTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/demonstrativeexample"
	detectionmethodTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/detectionmethod"
	modeofintroductionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/modeofintroduction"
	potentialmitigationTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/potentialmitigation"
	relatedweaknessTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/relatedweakness"
	weaknessordinalityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/weaknessordinality"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
)

// CWERef is the minimal reference embedded in a CWEResult whenever the
// underlying CWE record holds another CWE's ID. Carries {ID, Name,
// Description} for embedded display.
type CWERef struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// CWEResult mirrors cweTypes.CWE but replaces within-catalog CWE
// references (Weakness.RelatedWeaknesses / Category.Members /
// View.Members) with embedded CWERef values. RelatedAttackPatterns
// (CAPEC IDs) stays as raw IDs since it crosses catalogs.
type CWEResult struct {
	ID          string `json:"id"`
	Kind        string `json:"kind,omitempty"`
	Name        string `json:"name,omitempty"`
	Status      string `json:"status,omitempty"`
	Description string `json:"description,omitempty"`

	Weakness CWEResultWeakness `json:"weakness,omitzero"`
	Category CWEResultCategory `json:"category,omitzero"`
	View     CWEResultView     `json:"view,omitzero"`

	References []referenceTypes.Reference `json:"references,omitempty"`
	DataSource sourceTypes.Source         `json:"data_source,omitzero"`
}

// CWEResultRelatedWeakness mirrors relatedweaknessTypes.RelatedWeakness
// but embeds CWERef for the referenced weakness.
type CWEResultRelatedWeakness struct {
	Nature  string `json:"nature,omitempty"`
	CWE     CWERef `json:"cwe,omitzero"`
	ViewID  string `json:"view_id,omitempty"`
	Ordinal string `json:"ordinal,omitempty"`
	ChainID string `json:"chain_id,omitempty"`
}

// CWEResultMember mirrors a Category/View member with the referenced
// CWE expanded.
type CWEResultMember struct {
	CWE    CWERef `json:"cwe"`
	ViewID string `json:"view_id,omitempty"`
}

type CWEResultWeakness struct {
	Abstraction           string                                           `json:"abstraction,omitempty"`
	Structure             string                                           `json:"structure,omitempty"`
	Diagram               string                                           `json:"diagram,omitempty"`
	ExtendedDescription   string                                           `json:"extended_description,omitempty"`
	LikelihoodOfExploit   string                                           `json:"likelihood_of_exploit,omitempty"`
	BackgroundDetails     []string                                         `json:"background_details,omitempty"`
	ModesOfIntroduction   []modeofintroductionTypes.ModeOfIntroduction     `json:"modes_of_introduction,omitempty"`
	RelatedWeaknesses     []CWEResultRelatedWeakness                       `json:"related_weaknesses,omitempty"`
	RelatedAttackPatterns []string                                         `json:"related_attack_patterns,omitempty"`
	WeaknessOrdinalities  []weaknessordinalityTypes.WeaknessOrdinality     `json:"weakness_ordinalities,omitempty"`
	ApplicablePlatforms   []applicableplatformTypes.ApplicablePlatform     `json:"applicable_platforms,omitempty"`
	AffectedResources     []string                                         `json:"affected_resources,omitempty"`
	FunctionalAreas       []string                                         `json:"functional_areas,omitempty"`
	AlternateTerms        []alternatetermTypes.AlternateTerm               `json:"alternate_terms,omitempty"`
	CommonConsequences    []commonconsequenceTypes.CommonConsequence       `json:"common_consequences,omitempty"`
	PotentialMitigations  []potentialmitigationTypes.PotentialMitigation   `json:"potential_mitigations,omitempty"`
	DemonstrativeExamples []demonstrativeexampleTypes.DemonstrativeExample `json:"demonstrative_examples,omitempty"`
	DetectionMethods      []detectionmethodTypes.DetectionMethod           `json:"detection_methods,omitempty"`
	TaxonomyMappings      []taxonomymappingTypes.TaxonomyMapping           `json:"taxonomy_mappings,omitempty"`
	Notes                 []noteTypes.Note                                 `json:"notes,omitempty"`
	MappingNotes          mappingnotesTypes.MappingNotes                   `json:"mapping_notes,omitzero"`
}

type CWEResultCategory struct {
	Members          []CWEResultMember                      `json:"members,omitempty"`
	TaxonomyMappings []taxonomymappingTypes.TaxonomyMapping `json:"taxonomy_mappings,omitempty"`
	Notes            []noteTypes.Note                       `json:"notes,omitempty"`
	MappingNotes     mappingnotesTypes.MappingNotes         `json:"mapping_notes,omitzero"`
}

type CWEResultView struct {
	Type         string                         `json:"type,omitempty"`
	Audience     []audienceTypes.Audience       `json:"audience,omitempty"`
	Members      []CWEResultMember              `json:"members,omitempty"`
	Notes        []noteTypes.Note               `json:"notes,omitempty"`
	MappingNotes mappingnotesTypes.MappingNotes `json:"mapping_notes,omitzero"`
}

func toCWERef(id string, cache map[string]*cweTypes.CWE) CWERef {
	if id == "" {
		return CWERef{}
	}
	if c, ok := cache[id]; ok && c != nil {
		return CWERef{ID: c.ID, Name: c.Name, Description: c.Description}
	}
	return CWERef{ID: id}
}

func toCWEResultRelatedWeaknesses(items []relatedweaknessTypes.RelatedWeakness, cache map[string]*cweTypes.CWE) []CWEResultRelatedWeakness {
	if len(items) == 0 {
		return nil
	}
	out := make([]CWEResultRelatedWeakness, 0, len(items))
	for _, rw := range items {
		out = append(out, CWEResultRelatedWeakness{
			Nature:  rw.Nature,
			CWE:     toCWERef(rw.CWEID, cache),
			ViewID:  rw.ViewID,
			Ordinal: rw.Ordinal,
			ChainID: rw.ChainID,
		})
	}
	return out
}

func toCWEResultMembers(items []memberTypes.Member, cache map[string]*cweTypes.CWE) []CWEResultMember {
	if len(items) == 0 {
		return nil
	}
	out := make([]CWEResultMember, 0, len(items))
	for _, m := range items {
		out = append(out, CWEResultMember{
			CWE:    toCWERef(m.CWEID, cache),
			ViewID: m.ViewID,
		})
	}
	return out
}

func toCWEResult(c *cweTypes.CWE, cache map[string]*cweTypes.CWE) CWEResult {
	if c == nil {
		return CWEResult{}
	}
	r := CWEResult{
		ID:          c.ID,
		Kind:        c.Kind,
		Name:        c.Name,
		Status:      c.Status,
		Description: c.Description,
		References:  c.References,
		DataSource:  c.DataSource,
	}
	switch c.Kind {
	case "weakness":
		w := c.Weakness
		r.Weakness = CWEResultWeakness{
			Abstraction:           w.Abstraction,
			Structure:             w.Structure,
			Diagram:               w.Diagram,
			ExtendedDescription:   w.ExtendedDescription,
			LikelihoodOfExploit:   w.LikelihoodOfExploit,
			BackgroundDetails:     w.BackgroundDetails,
			ModesOfIntroduction:   w.ModesOfIntroduction,
			RelatedWeaknesses:     toCWEResultRelatedWeaknesses(w.RelatedWeaknesses, cache),
			RelatedAttackPatterns: w.RelatedAttackPatterns,
			WeaknessOrdinalities:  w.WeaknessOrdinalities,
			ApplicablePlatforms:   w.ApplicablePlatforms,
			AffectedResources:     w.AffectedResources,
			FunctionalAreas:       w.FunctionalAreas,
			AlternateTerms:        w.AlternateTerms,
			CommonConsequences:    w.CommonConsequences,
			PotentialMitigations:  w.PotentialMitigations,
			DemonstrativeExamples: w.DemonstrativeExamples,
			DetectionMethods:      w.DetectionMethods,
			TaxonomyMappings:      w.TaxonomyMappings,
			Notes:                 w.Notes,
			MappingNotes:          w.MappingNotes,
		}
	case "category":
		cat := c.Category
		r.Category = CWEResultCategory{
			Members:          toCWEResultMembers(cat.Members, cache),
			TaxonomyMappings: cat.TaxonomyMappings,
			Notes:            cat.Notes,
			MappingNotes:     cat.MappingNotes,
		}
	case "view":
		v := c.View
		r.View = CWEResultView{
			Type:         v.Type,
			Audience:     v.Audience,
			Members:      toCWEResultMembers(v.Members, cache),
			Notes:        v.Notes,
			MappingNotes: v.MappingNotes,
		}
	}
	return r
}
