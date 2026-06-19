package types

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
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
)

// CWEData is the session-layer view of a CWE record returned by
// Session.GetCWEData. Carries per-source contents under Contents and
// the union of contributing data-source provenance under DataSources.
type CWEData struct {
	ID          string                              `json:"id"`
	Contents    map[sourceTypes.SourceID]CWEContent `json:"contents,omitempty"`
	DataSources []datasourceTypes.DataSource        `json:"datasources,omitempty"`
}

// CWEContent is the per-source body of a CWE record. Mirrors
// cweTypes.CWE with within-catalog ID references (Weakness.
// RelatedWeaknesses / Category.Members / View.Members) replaced by
// CWERef. RelatedAttackPatterns stays as raw CAPEC IDs since it crosses
// catalogs.
type CWEContent struct {
	Kind        string `json:"kind,omitempty"`
	Name        string `json:"name,omitempty"`
	Status      string `json:"status,omitempty"`
	Description string `json:"description,omitempty"`

	Weakness CWEContentWeakness `json:"weakness,omitzero"`
	Category CWEContentCategory `json:"category,omitzero"`
	View     CWEContentView     `json:"view,omitzero"`

	References []referenceTypes.Reference `json:"references,omitempty"`
	DataSource sourceTypes.Source         `json:"data_source,omitzero"`
}

// CWERef is the minimal CWE reference embedded inside a CWEContent
// whenever the source record carries another CWE's ID.
type CWERef struct {
	ID          string `json:"id"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

// CWEContentRelatedWeakness mirrors relatedweaknessTypes.RelatedWeakness
// but embeds CWERef for the referenced weakness.
type CWEContentRelatedWeakness struct {
	Nature  string `json:"nature,omitempty"`
	CWE     CWERef `json:"cwe,omitzero"`
	ViewID  string `json:"view_id,omitempty"`
	Ordinal string `json:"ordinal,omitempty"`
	ChainID string `json:"chain_id,omitempty"`
}

// CWEContentMember mirrors a Category/View member with the referenced
// CWE expanded into a CWERef.
type CWEContentMember struct {
	CWE    CWERef `json:"cwe"`
	ViewID string `json:"view_id,omitempty"`
}

type CWEContentWeakness struct {
	Abstraction           string                                           `json:"abstraction,omitempty"`
	Structure             string                                           `json:"structure,omitempty"`
	Diagram               string                                           `json:"diagram,omitempty"`
	ExtendedDescription   string                                           `json:"extended_description,omitempty"`
	LikelihoodOfExploit   string                                           `json:"likelihood_of_exploit,omitempty"`
	BackgroundDetails     []string                                         `json:"background_details,omitempty"`
	ModesOfIntroduction   []modeofintroductionTypes.ModeOfIntroduction     `json:"modes_of_introduction,omitempty"`
	RelatedWeaknesses     []CWEContentRelatedWeakness                      `json:"related_weaknesses,omitempty"`
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

type CWEContentCategory struct {
	Members          []CWEContentMember                     `json:"members,omitempty"`
	TaxonomyMappings []taxonomymappingTypes.TaxonomyMapping `json:"taxonomy_mappings,omitempty"`
	Notes            []noteTypes.Note                       `json:"notes,omitempty"`
	MappingNotes     mappingnotesTypes.MappingNotes         `json:"mapping_notes,omitzero"`
}

type CWEContentView struct {
	Type         string                         `json:"type,omitempty"`
	Audience     []audienceTypes.Audience       `json:"audience,omitempty"`
	Members      []CWEContentMember             `json:"members,omitempty"`
	Notes        []noteTypes.Note               `json:"notes,omitempty"`
	MappingNotes mappingnotesTypes.MappingNotes `json:"mapping_notes,omitzero"`
}

// ToCWERef converts a CWE ID to a CWERef by looking up the cache. When
// the ID isn't cached, only the ID is set.
func ToCWERef(id string, cache map[string]*cweTypes.CWE) CWERef {
	if id == "" {
		return CWERef{}
	}
	if c, ok := cache[id]; ok && c != nil {
		return CWERef{ID: c.ID, Name: c.Name, Description: c.Description}
	}
	return CWERef{ID: id}
}

func toCWEContentRelatedWeaknesses(items []relatedweaknessTypes.RelatedWeakness, cache map[string]*cweTypes.CWE) []CWEContentRelatedWeakness {
	if len(items) == 0 {
		return nil
	}
	out := make([]CWEContentRelatedWeakness, 0, len(items))
	for _, rw := range items {
		out = append(out, CWEContentRelatedWeakness{
			Nature:  rw.Nature,
			CWE:     ToCWERef(rw.CWEID, cache),
			ViewID:  rw.ViewID,
			Ordinal: rw.Ordinal,
			ChainID: rw.ChainID,
		})
	}
	return out
}

func toCWEContentMembers(items []memberTypes.Member, cache map[string]*cweTypes.CWE) []CWEContentMember {
	if len(items) == 0 {
		return nil
	}
	out := make([]CWEContentMember, 0, len(items))
	for _, m := range items {
		out = append(out, CWEContentMember{
			CWE:    ToCWERef(m.CWEID, cache),
			ViewID: m.ViewID,
		})
	}
	return out
}

// ToCWEContent converts a per-source cweTypes.CWE into the embedded-refs
// CWEContent view.
func ToCWEContent(c cweTypes.CWE, cache map[string]*cweTypes.CWE) CWEContent {
	r := CWEContent{
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
		r.Weakness = CWEContentWeakness{
			Abstraction:           w.Abstraction,
			Structure:             w.Structure,
			Diagram:               w.Diagram,
			ExtendedDescription:   w.ExtendedDescription,
			LikelihoodOfExploit:   w.LikelihoodOfExploit,
			BackgroundDetails:     w.BackgroundDetails,
			ModesOfIntroduction:   w.ModesOfIntroduction,
			RelatedWeaknesses:     toCWEContentRelatedWeaknesses(w.RelatedWeaknesses, cache),
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
		r.Category = CWEContentCategory{
			Members:          toCWEContentMembers(cat.Members, cache),
			TaxonomyMappings: cat.TaxonomyMappings,
			Notes:            cat.Notes,
			MappingNotes:     cat.MappingNotes,
		}
	case "view":
		v := c.View
		r.View = CWEContentView{
			Type:         v.Type,
			Audience:     v.Audience,
			Members:      toCWEContentMembers(v.Members, cache),
			Notes:        v.Notes,
			MappingNotes: v.MappingNotes,
		}
	}
	return r
}

// CollectCWERefs returns every CWE ID referenced by the record's
// Weakness.RelatedWeaknesses, Category.Members and View.Members.
// RelatedAttackPatterns (CAPEC IDs) is cross-catalog and not included.
func CollectCWERefs(c cweTypes.CWE) []string {
	out := make([]string, 0, len(c.Weakness.RelatedWeaknesses)+len(c.Category.Members)+len(c.View.Members))
	for _, rw := range c.Weakness.RelatedWeaknesses {
		if rw.CWEID != "" {
			out = append(out, rw.CWEID)
		}
	}
	for _, m := range c.Category.Members {
		if m.CWEID != "" {
			out = append(out, m.CWEID)
		}
	}
	for _, m := range c.View.Members {
		if m.CWEID != "" {
			out = append(out, m.CWEID)
		}
	}
	return out
}
