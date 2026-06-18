package types

import (
	"time"

	attackTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack"
	analyticTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/analytic"
	assetTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/asset"
	datacomponentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/datacomponent"
	kindTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/kind"
	procedureTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/procedure"
	relatedrefTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/relatedref"
	tacticrefTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/tacticref"
	techniqueusedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/techniqueused"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
)

// AttackRefID is the composite primary key for an ATT&CK record:
// (Kind, external_id). Pre-2019 "1 Technique = 1 Mitigation"
// course-of-action records still ship a paired attack-pattern's
// T#### id, so keying by id alone collapses the legacy stub onto
// its live Technique. AttackRefID disambiguates them both on disk
// (attack/<kind>/<id>.json) and in storage (per-kind bucket / table).
type AttackRefID struct {
	Kind kindTypes.Kind `json:"kind"`
	ID   string         `json:"id"`
}

// AttackData is the session-layer view of a MITRE ATT&CK record returned
// by Session.GetAttackData. The header carries the composite primary
// key (Kind + ID) so callers can render "T1047 (Technique)" vs.
// "T1047 (Mitigation)" unambiguously when both records exist. Contents
// is the per-source body parallel to VulnerabilityDataAdvisory.Contents
// and DataSources is the union of contributing data-source provenance
// parallel to VulnerabilityData.DataSources.
type AttackData struct {
	Kind        kindTypes.Kind                         `json:"kind,omitempty"`
	ID          string                                 `json:"id"`
	Contents    map[sourceTypes.SourceID]AttackContent `json:"contents,omitempty"`
	DataSources []datasourceTypes.DataSource           `json:"datasources,omitempty"`
}

// AttackContent is the per-source body of an ATT&CK record. It mirrors
// attackTypes.Attack but replaces every within-catalog ID reference
// with an AttackRef so a single query renders the same ID/Name/
// Description triples shown on the ATT&CK web UI.
type AttackContent struct {
	Kind        kindTypes.Kind `json:"kind,omitempty"`
	Name        string           `json:"name,omitempty"`
	Description string           `json:"description,omitempty"`
	Domains     []string         `json:"domains,omitempty"`
	Deprecated  bool             `json:"deprecated,omitempty"`
	Revoked     bool             `json:"revoked,omitempty"`
	Version     string           `json:"version,omitempty"`
	Created     time.Time        `json:"created,omitzero"`
	Modified    time.Time        `json:"modified,omitzero"`

	Technique         AttackContentTechnique         `json:"technique,omitzero"`
	Tactic            AttackContentTactic            `json:"tactic,omitzero"`
	Mitigation        AttackContentMitigation        `json:"mitigation,omitzero"`
	Group             AttackContentGroup             `json:"group,omitzero"`
	Software          AttackContentSoftware          `json:"software,omitzero"`
	Campaign          AttackContentCampaign          `json:"campaign,omitzero"`
	Asset             AttackContentAsset             `json:"asset,omitzero"`
	DetectionStrategy AttackContentDetectionStrategy `json:"detection_strategy,omitzero"`
	AttackDataSource  AttackContentDataSource        `json:"attack_data_source,omitzero"`
	DataComponent     AttackContentDataComponent     `json:"data_component,omitzero"`
	Analytic          AttackContentAnalytic          `json:"analytic,omitzero"`

	References []referenceTypes.Reference `json:"references,omitempty"`
	DataSource sourceTypes.Source         `json:"data_source,omitzero"`
}

// AttackRef is the minimal ATT&CK reference embedded inside an
// AttackContent whenever the source record carries another ATT&CK
// record's external ID. Carries the columns shown on the ATT&CK web
// UI's relationship tables (Domain / ID / Name / Use), plus parent +
// is_subtechnique so consumers can render sub-technique grouping
// (e.g., T1078.001 indented under T1078 on the Mitigation page).
type AttackRef struct {
	// ID is omitempty so the shortname-only fallback in toAttackTactics
	// (where a Technique's kill_chain_phase shortname couldn't resolve
	// to an x-mitre-tactic record) doesn't ship a misleading "id":""
	// to consumers. Every resolved ref still carries the ext-id.
	ID             string         `json:"id,omitempty"`
	Kind           kindTypes.Kind `json:"kind,omitempty"`
	Name           string         `json:"name,omitempty"`
	Description    string         `json:"description,omitempty"`
	Domains        []string       `json:"domains,omitempty"`
	Parent         string         `json:"parent,omitempty"`
	IsSubtechnique bool           `json:"is_subtechnique,omitempty"`
}

// Role-specific embed types pair an AttackRef with the per-edge
// description and citations carried by the underlying STIX
// relationship. The role-specific field name (Mitigation, Technique,
// Software, Group, Campaign, ...) tells callers which side of the edge
// the embedded ref points at; the JSON shape stays parallel across all
// of them: { "<role>": AttackRef, "description": "<Use>", "references": [...] }.

type AttackContentProcedure struct {
	Attacker    AttackRef                  `json:"attacker"`
	Description string                     `json:"description,omitempty"`
	References  []referenceTypes.Reference `json:"references,omitempty"`
}

type AttackContentTechniqueUsed struct {
	Technique   AttackRef                  `json:"technique"`
	Description string                     `json:"description,omitempty"`
	References  []referenceTypes.Reference `json:"references,omitempty"`
}

// AttackContentMitigationApplied is the Technique-side view of a STIX
// "mitigates" edge.
type AttackContentMitigationApplied struct {
	Mitigation  AttackRef                  `json:"mitigation"`
	Description string                     `json:"description,omitempty"`
	References  []referenceTypes.Reference `json:"references,omitempty"`
}

// AttackContentTechniqueMitigated is the Mitigation-side view of a STIX
// "mitigates" edge.
type AttackContentTechniqueMitigated struct {
	Technique   AttackRef                  `json:"technique"`
	Description string                     `json:"description,omitempty"`
	References  []referenceTypes.Reference `json:"references,omitempty"`
}

// AttackContentDetectionApplied is the Technique-side view of a STIX
// "detects" edge.
type AttackContentDetectionApplied struct {
	DetectionStrategy AttackRef                  `json:"detection_strategy"`
	Description       string                     `json:"description,omitempty"`
	References        []referenceTypes.Reference `json:"references,omitempty"`
}

// AttackContentTechniqueDetected is the DetectionStrategy-side view of
// a STIX "detects" edge.
type AttackContentTechniqueDetected struct {
	Technique   AttackRef                  `json:"technique"`
	Description string                     `json:"description,omitempty"`
	References  []referenceTypes.Reference `json:"references,omitempty"`
}

// AttackContentAssetTargeted is the Technique-side view of a STIX
// "targets" edge.
type AttackContentAssetTargeted struct {
	Asset       AttackRef                  `json:"asset"`
	Description string                     `json:"description,omitempty"`
	References  []referenceTypes.Reference `json:"references,omitempty"`
}

// AttackContentTechniqueTargeting is the Asset-side view of a STIX
// "targets" edge.
type AttackContentTechniqueTargeting struct {
	Technique   AttackRef                  `json:"technique"`
	Description string                     `json:"description,omitempty"`
	References  []referenceTypes.Reference `json:"references,omitempty"`
}

// AttackContentSoftwareUsed is the Group/Campaign-side view of a STIX
// "uses" edge pointing at a Software.
type AttackContentSoftwareUsed struct {
	Software    AttackRef                  `json:"software"`
	Description string                     `json:"description,omitempty"`
	References  []referenceTypes.Reference `json:"references,omitempty"`
}

// AttackContentGroupUsing is the Software-side view of a STIX "uses"
// edge (reverse of Group uses Software).
type AttackContentGroupUsing struct {
	Group       AttackRef                  `json:"group"`
	Description string                     `json:"description,omitempty"`
	References  []referenceTypes.Reference `json:"references,omitempty"`
}

// AttackContentCampaignUsing is the Software-side view of a STIX "uses"
// edge (reverse of Campaign uses Software).
type AttackContentCampaignUsing struct {
	Campaign    AttackRef                  `json:"campaign"`
	Description string                     `json:"description,omitempty"`
	References  []referenceTypes.Reference `json:"references,omitempty"`
}

// AttackContentGroupAttributed is the Campaign-side view of a STIX
// "attributed-to" edge (Campaign attributed-to Group).
type AttackContentGroupAttributed struct {
	Group       AttackRef                  `json:"group"`
	Description string                     `json:"description,omitempty"`
	References  []referenceTypes.Reference `json:"references,omitempty"`
}

// AttackContentCampaignAttributed is the Group-side view of a STIX
// "attributed-to" edge (reverse of Campaign attributed-to Group).
type AttackContentCampaignAttributed struct {
	Campaign    AttackRef                  `json:"campaign"`
	Description string                     `json:"description,omitempty"`
	References  []referenceTypes.Reference `json:"references,omitempty"`
}

type AttackContentTechnique struct {
	Platforms            []string                         `json:"platforms,omitempty"`
	Tactics              []AttackRef                      `json:"tactics,omitempty"`
	IsSubtechnique       bool                             `json:"is_subtechnique,omitempty"`
	Parent               *AttackRef                       `json:"parent,omitempty"`
	Detection            string                           `json:"detection,omitempty"`
	DataSources          []string                         `json:"data_sources,omitempty"`
	Mitigations          []AttackContentMitigationApplied `json:"mitigations,omitempty"`
	Procedures           []AttackContentProcedure         `json:"procedures,omitempty"`
	PermissionsRequired  []string                         `json:"permissions_required,omitempty"`
	EffectivePermissions []string                         `json:"effective_permissions,omitempty"`
	DefenseBypassed      []string                         `json:"defense_bypassed,omitempty"`
	ImpactType           []string                         `json:"impact_type,omitempty"`
	NetworkRequirements  bool                             `json:"network_requirements,omitempty"`
	RemoteSupport        bool                             `json:"remote_support,omitempty"`
	Subtechniques        []AttackRef                      `json:"subtechniques,omitempty"`
	AssetsTargeted       []AttackContentAssetTargeted     `json:"assets_targeted,omitempty"`
	DetectionStrategies  []AttackContentDetectionApplied  `json:"detection_strategies,omitempty"`
}

type AttackContentTactic struct {
	Shortname  string      `json:"shortname,omitempty"`
	Techniques []AttackRef `json:"techniques,omitempty"`
}

type AttackContentMitigation struct {
	TechniquesMitigated []AttackContentTechniqueMitigated `json:"techniques_mitigated,omitempty"`
}

type AttackContentGroup struct {
	Aliases             []string                          `json:"aliases,omitempty"`
	TechniquesUsed      []AttackContentTechniqueUsed      `json:"techniques_used,omitempty"`
	SoftwaresUsed       []AttackContentSoftwareUsed       `json:"softwares_used,omitempty"`
	CampaignsAttributed []AttackContentCampaignAttributed `json:"campaigns_attributed,omitempty"`
}

type AttackContentSoftware struct {
	Type           string                       `json:"type,omitempty"`
	Aliases        []string                     `json:"aliases,omitempty"`
	Platforms      []string                     `json:"platforms,omitempty"`
	TechniquesUsed []AttackContentTechniqueUsed `json:"techniques_used,omitempty"`
	GroupsUsing    []AttackContentGroupUsing    `json:"groups_using,omitempty"`
	CampaignsUsing []AttackContentCampaignUsing `json:"campaigns_using,omitempty"`
}

type AttackContentCampaign struct {
	Aliases          []string                       `json:"aliases,omitempty"`
	FirstSeen        time.Time                      `json:"first_seen,omitzero"`
	LastSeen         time.Time                      `json:"last_seen,omitzero"`
	TechniquesUsed   []AttackContentTechniqueUsed   `json:"techniques_used,omitempty"`
	GroupsAttributed []AttackContentGroupAttributed `json:"groups_attributed,omitempty"`
	SoftwaresUsed    []AttackContentSoftwareUsed    `json:"softwares_used,omitempty"`
}

type AttackContentAsset struct {
	Platforms           []string                          `json:"platforms,omitempty"`
	Sectors             []string                          `json:"sectors,omitempty"`
	RelatedAssets       []assetTypes.RelatedAsset         `json:"related_assets,omitempty"`
	TechniquesTargeting []AttackContentTechniqueTargeting `json:"techniques_targeting,omitempty"`
}

type AttackContentDetectionStrategy struct {
	Analytics          []AttackRef                      `json:"analytics,omitempty"`
	TechniquesDetected []AttackContentTechniqueDetected `json:"techniques_detected,omitempty"`
}

type AttackContentDataSource struct {
	Platforms        []string    `json:"platforms,omitempty"`
	CollectionLayers []string    `json:"collection_layers,omitempty"`
	DataComponents   []AttackRef `json:"data_components,omitempty"`
}

type AttackContentDataComponent struct {
	DataSource *AttackRef                     `json:"data_source,omitempty"`
	LogSources []datacomponentTypes.LogSource `json:"log_sources,omitempty"`
}

type AttackContentAnalytic struct {
	DetectionStrategy   *AttackRef                         `json:"detection_strategy,omitempty"`
	Platforms           []string                           `json:"platforms,omitempty"`
	LogSourceReferences []analyticTypes.LogSourceReference `json:"log_source_references,omitempty"`
	MutableElements     []analyticTypes.MutableElement     `json:"mutable_elements,omitempty"`
}

// ToAttackRef converts an Attack (Kind, ID) pair to an AttackRef by
// looking up the cache keyed by AttackRefID. When the entry isn't
// cached, only the Kind and ID are set so callers can still see the
// unresolved reference.
func ToAttackRef(kind kindTypes.Kind, id string, cache map[AttackRefID]*attackTypes.Attack) AttackRef {
	if id == "" {
		return AttackRef{}
	}
	if a, ok := cache[AttackRefID{Kind: kind, ID: id}]; ok && a != nil {
		return AttackRef{
			ID:             a.ID,
			Kind:           a.Kind,
			Name:           a.Name,
			Description:    a.Description,
			Domains:        a.Domains,
			Parent:         a.Technique.Parent,
			IsSubtechnique: a.Technique.IsSubtechnique,
		}
	}
	return AttackRef{ID: id, Kind: kind}
}

// ToAttackRefs is the slice form of ToAttackRef. The Kind argument
// applies to every ID — used for fields where every entry is the
// same Kind by the enclosing field's name (e.g.,
// Tactic.Techniques is always Technique).
func ToAttackRefs(kind kindTypes.Kind, ids []string, cache map[AttackRefID]*attackTypes.Attack) []AttackRef {
	if len(ids) == 0 {
		return nil
	}
	out := make([]AttackRef, 0, len(ids))
	for _, id := range ids {
		out = append(out, ToAttackRef(kind, id, cache))
	}
	return out
}

// ToAttackContent converts a per-source attackTypes.Attack into the
// embedded-refs AttackContent view used inside AttackData.Contents.
func ToAttackContent(a attackTypes.Attack, cache map[AttackRefID]*attackTypes.Attack) AttackContent {
	c := AttackContent{
		Kind:        a.Kind,
		Name:        a.Name,
		Description: a.Description,
		Domains:     a.Domains,
		Deprecated:  a.Deprecated,
		Revoked:     a.Revoked,
		Version:     a.Version,
		Created:     a.Created,
		Modified:    a.Modified,
		References:  a.References,
		DataSource:  a.DataSource,
	}
	switch a.Kind {
	case kindTypes.Technique:
		t := a.Technique
		c.Technique = AttackContentTechnique{
			Platforms:      t.Platforms,
			Tactics:        toAttackTactics(t.Tactics, cache),
			IsSubtechnique: t.IsSubtechnique,
			Parent: func() *AttackRef {
				if t.Parent == "" {
					return nil
				}
				ref := ToAttackRef(kindTypes.Technique, t.Parent, cache)
				return &ref
			}(),
			Detection:            t.Detection,
			DataSources:          t.DataSources,
			Mitigations:          toAttackContentMitigationsApplied(t.Mitigations, cache),
			Procedures:           toAttackContentProcedures(t.Procedures, cache),
			PermissionsRequired:  t.PermissionsRequired,
			EffectivePermissions: t.EffectivePermissions,
			DefenseBypassed:      t.DefenseBypassed,
			ImpactType:           t.ImpactType,
			NetworkRequirements:  t.NetworkRequirements,
			RemoteSupport:        t.RemoteSupport,
			Subtechniques:        ToAttackRefs(kindTypes.Technique, t.Subtechniques, cache),
			AssetsTargeted:       toAttackContentAssetsTargeted(t.AssetsTargeted, cache),
			DetectionStrategies:  toAttackContentDetectionsApplied(t.DetectionStrategies, cache),
		}
	case kindTypes.Tactic:
		c.Tactic = AttackContentTactic{
			Shortname:  a.Tactic.Shortname,
			Techniques: ToAttackRefs(kindTypes.Technique, a.Tactic.Techniques, cache),
		}
	case kindTypes.Mitigation:
		c.Mitigation = AttackContentMitigation{
			TechniquesMitigated: toAttackContentTechniquesMitigated(a.Mitigation.TechniquesMitigated, cache),
		}
	case kindTypes.Group:
		g := a.Group
		c.Group = AttackContentGroup{
			Aliases:             g.Aliases,
			TechniquesUsed:      toAttackContentTechniquesUsed(g.TechniquesUsed, cache),
			SoftwaresUsed:       toAttackContentSoftwaresUsed(g.SoftwaresUsed, cache),
			CampaignsAttributed: toAttackContentCampaignsAttributed(g.CampaignsAttributed, cache),
		}
	case kindTypes.Software:
		s := a.Software
		c.Software = AttackContentSoftware{
			Type:           s.Type,
			Aliases:        s.Aliases,
			Platforms:      s.Platforms,
			TechniquesUsed: toAttackContentTechniquesUsed(s.TechniquesUsed, cache),
			GroupsUsing:    toAttackContentGroupsUsing(s.GroupsUsing, cache),
			CampaignsUsing: toAttackContentCampaignsUsing(s.CampaignsUsing, cache),
		}
	case kindTypes.Campaign:
		cp := a.Campaign
		c.Campaign = AttackContentCampaign{
			Aliases:          cp.Aliases,
			FirstSeen:        cp.FirstSeen,
			LastSeen:         cp.LastSeen,
			TechniquesUsed:   toAttackContentTechniquesUsed(cp.TechniquesUsed, cache),
			GroupsAttributed: toAttackContentGroupsAttributed(cp.GroupsAttributed, cache),
			SoftwaresUsed:    toAttackContentSoftwaresUsed(cp.SoftwaresUsed, cache),
		}
	case kindTypes.Asset:
		as := a.Asset
		c.Asset = AttackContentAsset{
			Platforms:           as.Platforms,
			Sectors:             as.Sectors,
			RelatedAssets:       as.RelatedAssets,
			TechniquesTargeting: toAttackContentTechniquesTargeting(as.TechniquesTargeting, cache),
		}
	case kindTypes.DetectStrategy:
		d := a.DetectionStrategy
		c.DetectionStrategy = AttackContentDetectionStrategy{
			Analytics:          ToAttackRefs(kindTypes.Analytic, d.Analytics, cache),
			TechniquesDetected: toAttackContentTechniquesDetected(d.TechniquesDetected, cache),
		}
	case kindTypes.DataSource:
		d := a.AttackDataSource
		c.AttackDataSource = AttackContentDataSource{
			Platforms:        d.Platforms,
			CollectionLayers: d.CollectionLayers,
			DataComponents:   ToAttackRefs(kindTypes.DataComponent, d.DataComponents, cache),
		}
	case kindTypes.DataComponent:
		d := a.DataComponent
		c.DataComponent = AttackContentDataComponent{
			DataSource: func() *AttackRef {
				if d.DataSource == "" {
					return nil
				}
				ref := ToAttackRef(kindTypes.DataSource, d.DataSource, cache)
				return &ref
			}(),
			LogSources: d.LogSources,
		}
	case kindTypes.Analytic:
		an := a.Analytic
		c.Analytic = AttackContentAnalytic{
			DetectionStrategy: func() *AttackRef {
				if an.DetectionStrategy == "" {
					return nil
				}
				ref := ToAttackRef(kindTypes.DetectStrategy, an.DetectionStrategy, cache)
				return &ref
			}(),
			Platforms:           an.Platforms,
			LogSourceReferences: an.LogSourceReferences,
			MutableElements:     an.MutableElements,
		}
	}
	return c
}

// toAttackTactics expands the Tactic shortname+ID pairs that Technique
// carries into AttackRefs. If the underlying TacticRef has an ID we
// resolve it through the cache (which yields the full Tactic Name and
// Description). When the extractor couldn't resolve a shortname to a
// Tactic record the resulting AttackRef carries the shortname in Name
// so consumers still see a non-empty label.
func toAttackTactics(items []tacticrefTypes.TacticRef, cache map[AttackRefID]*attackTypes.Attack) []AttackRef {
	if len(items) == 0 {
		return nil
	}
	out := make([]AttackRef, 0, len(items))
	for _, tr := range items {
		if tr.ID != "" {
			out = append(out, ToAttackRef(kindTypes.Tactic, tr.ID, cache))
			continue
		}
		out = append(out, AttackRef{Name: tr.Shortname})
	}
	return out
}

func toAttackContentProcedures(items []procedureTypes.Procedure, cache map[AttackRefID]*attackTypes.Attack) []AttackContentProcedure {
	if len(items) == 0 {
		return nil
	}
	out := make([]AttackContentProcedure, 0, len(items))
	for _, p := range items {
		out = append(out, AttackContentProcedure{
			Attacker:    ToAttackRef(p.AttackerKind, p.AttackerID, cache),
			Description: p.Description,
			References:  p.References,
		})
	}
	return out
}

func toAttackContentTechniquesUsed(items []techniqueusedTypes.TechniqueUsed, cache map[AttackRefID]*attackTypes.Attack) []AttackContentTechniqueUsed {
	if len(items) == 0 {
		return nil
	}
	out := make([]AttackContentTechniqueUsed, 0, len(items))
	for _, t := range items {
		out = append(out, AttackContentTechniqueUsed{
			Technique:   ToAttackRef(kindTypes.Technique, t.ID, cache),
			Description: t.Description,
			References:  t.References,
		})
	}
	return out
}

func toAttackContentMitigationsApplied(items []relatedrefTypes.RelatedRef, cache map[AttackRefID]*attackTypes.Attack) []AttackContentMitigationApplied {
	if len(items) == 0 {
		return nil
	}
	out := make([]AttackContentMitigationApplied, 0, len(items))
	for _, r := range items {
		out = append(out, AttackContentMitigationApplied{
			Mitigation:  ToAttackRef(kindTypes.Mitigation, r.ID, cache),
			Description: r.Description,
			References:  r.References,
		})
	}
	return out
}

func toAttackContentTechniquesMitigated(items []relatedrefTypes.RelatedRef, cache map[AttackRefID]*attackTypes.Attack) []AttackContentTechniqueMitigated {
	if len(items) == 0 {
		return nil
	}
	out := make([]AttackContentTechniqueMitigated, 0, len(items))
	for _, r := range items {
		out = append(out, AttackContentTechniqueMitigated{
			Technique:   ToAttackRef(kindTypes.Technique, r.ID, cache),
			Description: r.Description,
			References:  r.References,
		})
	}
	return out
}

func toAttackContentDetectionsApplied(items []relatedrefTypes.RelatedRef, cache map[AttackRefID]*attackTypes.Attack) []AttackContentDetectionApplied {
	if len(items) == 0 {
		return nil
	}
	out := make([]AttackContentDetectionApplied, 0, len(items))
	for _, r := range items {
		out = append(out, AttackContentDetectionApplied{
			DetectionStrategy: ToAttackRef(kindTypes.DetectStrategy, r.ID, cache),
			Description:       r.Description,
			References:        r.References,
		})
	}
	return out
}

func toAttackContentTechniquesDetected(items []relatedrefTypes.RelatedRef, cache map[AttackRefID]*attackTypes.Attack) []AttackContentTechniqueDetected {
	if len(items) == 0 {
		return nil
	}
	out := make([]AttackContentTechniqueDetected, 0, len(items))
	for _, r := range items {
		out = append(out, AttackContentTechniqueDetected{
			Technique:   ToAttackRef(kindTypes.Technique, r.ID, cache),
			Description: r.Description,
			References:  r.References,
		})
	}
	return out
}

func toAttackContentAssetsTargeted(items []relatedrefTypes.RelatedRef, cache map[AttackRefID]*attackTypes.Attack) []AttackContentAssetTargeted {
	if len(items) == 0 {
		return nil
	}
	out := make([]AttackContentAssetTargeted, 0, len(items))
	for _, r := range items {
		out = append(out, AttackContentAssetTargeted{
			Asset:       ToAttackRef(kindTypes.Asset, r.ID, cache),
			Description: r.Description,
			References:  r.References,
		})
	}
	return out
}

func toAttackContentTechniquesTargeting(items []relatedrefTypes.RelatedRef, cache map[AttackRefID]*attackTypes.Attack) []AttackContentTechniqueTargeting {
	if len(items) == 0 {
		return nil
	}
	out := make([]AttackContentTechniqueTargeting, 0, len(items))
	for _, r := range items {
		out = append(out, AttackContentTechniqueTargeting{
			Technique:   ToAttackRef(kindTypes.Technique, r.ID, cache),
			Description: r.Description,
			References:  r.References,
		})
	}
	return out
}

func toAttackContentSoftwaresUsed(items []relatedrefTypes.RelatedRef, cache map[AttackRefID]*attackTypes.Attack) []AttackContentSoftwareUsed {
	if len(items) == 0 {
		return nil
	}
	out := make([]AttackContentSoftwareUsed, 0, len(items))
	for _, r := range items {
		out = append(out, AttackContentSoftwareUsed{
			Software:    ToAttackRef(kindTypes.Software, r.ID, cache),
			Description: r.Description,
			References:  r.References,
		})
	}
	return out
}

func toAttackContentGroupsUsing(items []relatedrefTypes.RelatedRef, cache map[AttackRefID]*attackTypes.Attack) []AttackContentGroupUsing {
	if len(items) == 0 {
		return nil
	}
	out := make([]AttackContentGroupUsing, 0, len(items))
	for _, r := range items {
		out = append(out, AttackContentGroupUsing{
			Group:       ToAttackRef(kindTypes.Group, r.ID, cache),
			Description: r.Description,
			References:  r.References,
		})
	}
	return out
}

func toAttackContentCampaignsUsing(items []relatedrefTypes.RelatedRef, cache map[AttackRefID]*attackTypes.Attack) []AttackContentCampaignUsing {
	if len(items) == 0 {
		return nil
	}
	out := make([]AttackContentCampaignUsing, 0, len(items))
	for _, r := range items {
		out = append(out, AttackContentCampaignUsing{
			Campaign:    ToAttackRef(kindTypes.Campaign, r.ID, cache),
			Description: r.Description,
			References:  r.References,
		})
	}
	return out
}

func toAttackContentGroupsAttributed(items []relatedrefTypes.RelatedRef, cache map[AttackRefID]*attackTypes.Attack) []AttackContentGroupAttributed {
	if len(items) == 0 {
		return nil
	}
	out := make([]AttackContentGroupAttributed, 0, len(items))
	for _, r := range items {
		out = append(out, AttackContentGroupAttributed{
			Group:       ToAttackRef(kindTypes.Group, r.ID, cache),
			Description: r.Description,
			References:  r.References,
		})
	}
	return out
}

func toAttackContentCampaignsAttributed(items []relatedrefTypes.RelatedRef, cache map[AttackRefID]*attackTypes.Attack) []AttackContentCampaignAttributed {
	if len(items) == 0 {
		return nil
	}
	out := make([]AttackContentCampaignAttributed, 0, len(items))
	for _, r := range items {
		out = append(out, AttackContentCampaignAttributed{
			Campaign:    ToAttackRef(kindTypes.Campaign, r.ID, cache),
			Description: r.Description,
			References:  r.References,
		})
	}
	return out
}

// CollectAttackRefs returns every cross-record AttackRefID referenced
// by the record's kind-specific fields. Used by Session.GetAttackData
// to walk one level of references and build the AttackRef cache. The
// Kind for each ref is statically determined by the enclosing field
// name (e.g., Technique.Mitigations is always KindMitigation), with
// the single exception of Procedure.AttackerKind which is carried
// inline on the source struct.
func CollectAttackRefs(a attackTypes.Attack) []AttackRefID {
	out := make([]AttackRefID, 0)
	// Technique
	for _, r := range a.Technique.Mitigations {
		if r.ID != "" {
			out = append(out, AttackRefID{Kind: kindTypes.Mitigation, ID: r.ID})
		}
	}
	for _, id := range a.Technique.Subtechniques {
		if id != "" {
			out = append(out, AttackRefID{Kind: kindTypes.Technique, ID: id})
		}
	}
	for _, r := range a.Technique.AssetsTargeted {
		if r.ID != "" {
			out = append(out, AttackRefID{Kind: kindTypes.Asset, ID: r.ID})
		}
	}
	for _, r := range a.Technique.DetectionStrategies {
		if r.ID != "" {
			out = append(out, AttackRefID{Kind: kindTypes.DetectStrategy, ID: r.ID})
		}
	}
	for _, tr := range a.Technique.Tactics {
		if tr.ID != "" {
			out = append(out, AttackRefID{Kind: kindTypes.Tactic, ID: tr.ID})
		}
	}
	if a.Technique.Parent != "" {
		out = append(out, AttackRefID{Kind: kindTypes.Technique, ID: a.Technique.Parent})
	}
	for _, p := range a.Technique.Procedures {
		if p.AttackerID != "" {
			out = append(out, AttackRefID{Kind: p.AttackerKind, ID: p.AttackerID})
		}
	}
	// Tactic
	for _, id := range a.Tactic.Techniques {
		if id != "" {
			out = append(out, AttackRefID{Kind: kindTypes.Technique, ID: id})
		}
	}
	// Mitigation
	for _, r := range a.Mitigation.TechniquesMitigated {
		if r.ID != "" {
			out = append(out, AttackRefID{Kind: kindTypes.Technique, ID: r.ID})
		}
	}
	// Group
	for _, t := range a.Group.TechniquesUsed {
		if t.ID != "" {
			out = append(out, AttackRefID{Kind: kindTypes.Technique, ID: t.ID})
		}
	}
	for _, r := range a.Group.SoftwaresUsed {
		if r.ID != "" {
			out = append(out, AttackRefID{Kind: kindTypes.Software, ID: r.ID})
		}
	}
	for _, r := range a.Group.CampaignsAttributed {
		if r.ID != "" {
			out = append(out, AttackRefID{Kind: kindTypes.Campaign, ID: r.ID})
		}
	}
	// Software
	for _, t := range a.Software.TechniquesUsed {
		if t.ID != "" {
			out = append(out, AttackRefID{Kind: kindTypes.Technique, ID: t.ID})
		}
	}
	for _, r := range a.Software.GroupsUsing {
		if r.ID != "" {
			out = append(out, AttackRefID{Kind: kindTypes.Group, ID: r.ID})
		}
	}
	for _, r := range a.Software.CampaignsUsing {
		if r.ID != "" {
			out = append(out, AttackRefID{Kind: kindTypes.Campaign, ID: r.ID})
		}
	}
	// Campaign
	for _, t := range a.Campaign.TechniquesUsed {
		if t.ID != "" {
			out = append(out, AttackRefID{Kind: kindTypes.Technique, ID: t.ID})
		}
	}
	for _, r := range a.Campaign.GroupsAttributed {
		if r.ID != "" {
			out = append(out, AttackRefID{Kind: kindTypes.Group, ID: r.ID})
		}
	}
	for _, r := range a.Campaign.SoftwaresUsed {
		if r.ID != "" {
			out = append(out, AttackRefID{Kind: kindTypes.Software, ID: r.ID})
		}
	}
	// Asset
	for _, r := range a.Asset.TechniquesTargeting {
		if r.ID != "" {
			out = append(out, AttackRefID{Kind: kindTypes.Technique, ID: r.ID})
		}
	}
	// DetectionStrategy
	for _, id := range a.DetectionStrategy.Analytics {
		if id != "" {
			out = append(out, AttackRefID{Kind: kindTypes.Analytic, ID: id})
		}
	}
	for _, r := range a.DetectionStrategy.TechniquesDetected {
		if r.ID != "" {
			out = append(out, AttackRefID{Kind: kindTypes.Technique, ID: r.ID})
		}
	}
	// DataSource (kind)
	for _, id := range a.AttackDataSource.DataComponents {
		if id != "" {
			out = append(out, AttackRefID{Kind: kindTypes.DataComponent, ID: id})
		}
	}
	// DataComponent
	if a.DataComponent.DataSource != "" {
		out = append(out, AttackRefID{Kind: kindTypes.DataSource, ID: a.DataComponent.DataSource})
	}
	// Analytic
	if a.Analytic.DetectionStrategy != "" {
		out = append(out, AttackRefID{Kind: kindTypes.DetectStrategy, ID: a.Analytic.DetectionStrategy})
	}
	return out
}
