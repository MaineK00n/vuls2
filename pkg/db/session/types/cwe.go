package types

import (
	"slices"

	cweTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe"
	groupingTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/grouping"
	mappingnotesTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/mappingnotes"
	memberTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/member"
	noteTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/note"
	taxonomymappingTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/taxonomymapping"
	audienceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/view/audience"
	alternatetermTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/alternateterm"
	applicableplatformTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/applicableplatform"
	commonconsequenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/commonconsequence"
	customphaseTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe/weakness/customphase"
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
// RelatedWeaknesses / Grouping.Members / View.Members) replaced by
// CWERef. RelatedAttackPatterns stays as raw CAPEC IDs since it crosses
// catalogs.
//
// The shape does not depend on whether the DB was built from data
// extracted before or after vuls-data-update supported CWE 5.0: a
// pre-CWE 5.0 "category" is output as a "grouping", and every mode of
// introduction lists its phases in Phases.
type CWEContent struct {
	Kind        string `json:"kind,omitempty"` // "weakness" | "grouping" | "view"
	Name        string `json:"name,omitempty"`
	Status      string `json:"status,omitempty"`
	Description string `json:"description,omitempty"`

	Weakness CWEContentWeakness `json:"weakness,omitzero"`
	Grouping CWEContentGrouping `json:"grouping,omitzero"`
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

// CWEContentMember mirrors a Grouping/View member with the referenced
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
	ModesOfIntroduction   []CWEContentModeOfIntroduction                   `json:"modes_of_introduction,omitempty"`
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

// CWEContentModeOfIntroduction mirrors modeofintroductionTypes.
// ModeOfIntroduction in its CWE 5.0 shape, which lists the phases in
// Phases. The single Phase of data extracted before CWE 5.0 is moved
// into Phases.
type CWEContentModeOfIntroduction struct {
	Phases       []string                       `json:"phases,omitempty"`
	CustomPhases []customphaseTypes.CustomPhase `json:"custom_phases,omitempty"`
	Notes        []string                       `json:"notes,omitempty"`
}

// CWEContentGrouping mirrors groupingTypes.Grouping with the members
// expanded into CWERef. CWE 5.0 renamed categories to groupings; a
// category of data extracted before that is output as a grouping too.
type CWEContentGrouping struct {
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
func ToCWERef(id string, cache map[string]cweTypes.CWE) CWERef {
	if c, ok := cache[id]; ok {
		return CWERef{ID: c.ID, Name: c.Name, Description: c.Description}
	}
	return CWERef{ID: id}
}

func toCWEContentRelatedWeaknesses(items []relatedweaknessTypes.RelatedWeakness, cache map[string]cweTypes.CWE) []CWEContentRelatedWeakness {
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

func toCWEContentMembers(items []memberTypes.Member, cache map[string]cweTypes.CWE) []CWEContentMember {
	out := make([]CWEContentMember, 0, len(items))
	for _, m := range items {
		out = append(out, CWEContentMember{
			CWE:    ToCWERef(m.CWEID, cache),
			ViewID: m.ViewID,
		})
	}
	return out
}

func toCWEContentModesOfIntroduction(items []modeofintroductionTypes.ModeOfIntroduction) []CWEContentModeOfIntroduction {
	out := make([]CWEContentModeOfIntroduction, 0, len(items))
	for _, m := range items {
		phases := m.Phases
		// Data extracted before CWE 5.0 has its phase in Phase, not Phases.
		if p := m.Phase; p != "" && !slices.Contains(phases, p) { //nolint:staticcheck // SA1019: Phase is read to support DBs built from data extracted before CWE 5.0
			phases = append(slices.Clone(phases), p)
		}
		out = append(out, CWEContentModeOfIntroduction{
			Phases:       phases,
			CustomPhases: m.CustomPhases,
			Notes:        m.Notes,
		})
	}
	return out
}

func toCWEContentGrouping(g groupingTypes.Grouping, cache map[string]cweTypes.CWE) CWEContentGrouping {
	return CWEContentGrouping{
		Members:          toCWEContentMembers(g.Members, cache),
		TaxonomyMappings: g.TaxonomyMappings,
		Notes:            g.Notes,
		MappingNotes:     g.MappingNotes,
	}
}

// ToCWEContent converts a per-source cweTypes.CWE into the embedded-refs
// CWEContent view. Data extracted before CWE 5.0 is converted to the
// CWE 5.0 shape: a "category" becomes a "grouping", and the Phase of a
// mode of introduction moves into Phases.
func ToCWEContent(c cweTypes.CWE, cache map[string]cweTypes.CWE) CWEContent {
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
			ModesOfIntroduction:   toCWEContentModesOfIntroduction(w.ModesOfIntroduction),
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
	case "grouping":
		r.Grouping = toCWEContentGrouping(c.Grouping, cache)
	case "category":
		// CWE 5.0 renamed categories to groupings. A category has the
		// same fields as a grouping, so convert it and output it as one.
		r.Kind = "grouping"
		r.Grouping = toCWEContentGrouping(groupingTypes.Grouping(c.Category), cache) //nolint:staticcheck // SA1019: Category is read to support DBs built from data extracted before CWE 5.0
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
