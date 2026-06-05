package types

import (
	"time"

	attackTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack"
	analyticTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/analytic"
	assetTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/asset"
	datacomponentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/datacomponent"
	procedureTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/procedure"
	relatedrefTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/relatedref"
	techniqueusedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/techniqueused"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
)

// AttackData is the session-layer view of a MITRE ATT&CK record returned
// by Session.GetAttackData. It carries per-source contents under
// Contents (parallel to VulnerabilityDataAdvisory.Contents) and the
// union of contributing data-source provenance under DataSources
// (parallel to VulnerabilityData.DataSources).
type AttackData struct {
	ID          string                                 `json:"id"`
	Contents    map[sourceTypes.SourceID]AttackContent `json:"contents,omitempty"`
	DataSources []datasourceTypes.DataSource           `json:"datasources,omitempty"`
}

// AttackContent is the per-source body of an ATT&CK record. It mirrors
// attackTypes.Attack but replaces every within-catalog ID reference
// with an AttackRef so a single query renders the same ID/Name/
// Description triples shown on the ATT&CK web UI.
type AttackContent struct {
	Kind        attackTypes.Kind `json:"kind,omitempty"`
	Name        string           `json:"name,omitempty"`
	Description string           `json:"description,omitempty"`
	Domains     []string         `json:"domains,omitempty"`
	Deprecated  bool             `json:"deprecated,omitempty"`
	Revoked     bool             `json:"revoked,omitempty"`
	Version     string           `json:"version,omitempty"`
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
// record's external ID.
type AttackRef struct {
	ID          string           `json:"id"`
	Kind        attackTypes.Kind `json:"kind,omitempty"`
	Name        string           `json:"name,omitempty"`
	Description string           `json:"description,omitempty"`
}

type AttackContentProcedure struct {
	Attacker    AttackRef `json:"attacker"`
	Description string    `json:"description,omitempty"`
}

type AttackContentTechniqueUsed struct {
	Technique   AttackRef `json:"technique"`
	Description string    `json:"description,omitempty"`
}

// AttackContentMitigationApplied is the Technique-side view of a STIX
// "mitigates" edge — the Mitigation that addresses this technique plus
// the per-edge "Use" description from the relationship object (the
// text shown on the ATT&CK web UI's Mitigations table).
type AttackContentMitigationApplied struct {
	Mitigation  AttackRef `json:"mitigation"`
	Description string    `json:"description,omitempty"`
}

// AttackContentTechniqueMitigated is the Mitigation-side view of a STIX
// "mitigates" edge — a technique this mitigation addresses plus the
// per-edge "Use" description (the text shown on the Mitigation page's
// Techniques Addressed table).
type AttackContentTechniqueMitigated struct {
	Technique   AttackRef `json:"technique"`
	Description string    `json:"description,omitempty"`
}

// AttackContentDetectionApplied is the Technique-side view of a STIX
// "detects" edge — a Detection Strategy targeting this technique plus
// the per-edge description.
type AttackContentDetectionApplied struct {
	DetectionStrategy AttackRef `json:"detection_strategy"`
	Description       string    `json:"description,omitempty"`
}

// AttackContentTechniqueDetected is the DetectionStrategy-side view of
// a STIX "detects" edge — a technique this strategy detects plus the
// per-edge description.
type AttackContentTechniqueDetected struct {
	Technique   AttackRef `json:"technique"`
	Description string    `json:"description,omitempty"`
}

// AttackContentAssetTargeted is the Technique-side view of a STIX
// "targets" edge — an Asset this technique targets plus the per-edge
// description.
type AttackContentAssetTargeted struct {
	Asset       AttackRef `json:"asset"`
	Description string    `json:"description,omitempty"`
}

// AttackContentTechniqueTargeting is the Asset-side view of a STIX
// "targets" edge — a technique that targets this asset plus the
// per-edge description.
type AttackContentTechniqueTargeting struct {
	Technique   AttackRef `json:"technique"`
	Description string    `json:"description,omitempty"`
}

type AttackContentTechnique struct {
	Platforms            []string                         `json:"platforms,omitempty"`
	Tactics              []string                         `json:"tactics,omitempty"`
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
	Aliases             []string                     `json:"aliases,omitempty"`
	TechniquesUsed      []AttackContentTechniqueUsed `json:"techniques_used,omitempty"`
	SoftwaresUsed       []AttackRef                  `json:"softwares_used,omitempty"`
	CampaignsAttributed []AttackRef                  `json:"campaigns_attributed,omitempty"`
}

type AttackContentSoftware struct {
	Type           string                       `json:"type,omitempty"`
	Aliases        []string                     `json:"aliases,omitempty"`
	Platforms      []string                     `json:"platforms,omitempty"`
	TechniquesUsed []AttackContentTechniqueUsed `json:"techniques_used,omitempty"`
	GroupsUsing    []AttackRef                  `json:"groups_using,omitempty"`
	CampaignsUsing []AttackRef                  `json:"campaigns_using,omitempty"`
}

type AttackContentCampaign struct {
	Aliases          []string                     `json:"aliases,omitempty"`
	FirstSeen        time.Time                    `json:"first_seen,omitzero"`
	LastSeen         time.Time                    `json:"last_seen,omitzero"`
	TechniquesUsed   []AttackContentTechniqueUsed `json:"techniques_used,omitempty"`
	GroupsAttributed []AttackRef                  `json:"groups_attributed,omitempty"`
	SoftwaresUsed    []AttackRef                  `json:"softwares_used,omitempty"`
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

// ToAttackRef converts an Attack external ID to an AttackRef by looking
// up the cache. When the ID isn't cached, only the ID is set so callers
// can still see the unresolved reference.
func ToAttackRef(id string, cache map[string]*attackTypes.Attack) AttackRef {
	if id == "" {
		return AttackRef{}
	}
	if a, ok := cache[id]; ok && a != nil {
		return AttackRef{
			ID:          a.ID,
			Kind:        a.Kind,
			Name:        a.Name,
			Description: a.Description,
		}
	}
	return AttackRef{ID: id}
}

// ToAttackRefs is the slice form of ToAttackRef. Returns nil for an
// empty input so JSON omitempty drops the field.
func ToAttackRefs(ids []string, cache map[string]*attackTypes.Attack) []AttackRef {
	if len(ids) == 0 {
		return nil
	}
	out := make([]AttackRef, 0, len(ids))
	for _, id := range ids {
		out = append(out, ToAttackRef(id, cache))
	}
	return out
}

// ToAttackContent converts a per-source attackTypes.Attack into the
// embedded-refs AttackContent view used inside AttackData.Contents.
func ToAttackContent(a attackTypes.Attack, cache map[string]*attackTypes.Attack) AttackContent {
	c := AttackContent{
		Kind:        a.Kind,
		Name:        a.Name,
		Description: a.Description,
		Domains:     a.Domains,
		Deprecated:  a.Deprecated,
		Revoked:     a.Revoked,
		Version:     a.Version,
		Modified:    a.Modified,
		References:  a.References,
		DataSource:  a.DataSource,
	}
	switch a.Kind {
	case attackTypes.KindTechnique:
		t := a.Technique
		c.Technique = AttackContentTechnique{
			Platforms:      t.Platforms,
			Tactics:        t.Tactics,
			IsSubtechnique: t.IsSubtechnique,
			Parent: func() *AttackRef {
				if t.Parent == "" {
					return nil
				}
				ref := ToAttackRef(t.Parent, cache)
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
			Subtechniques:        ToAttackRefs(t.Subtechniques, cache),
			AssetsTargeted:       toAttackContentAssetsTargeted(t.AssetsTargeted, cache),
			DetectionStrategies:  toAttackContentDetectionsApplied(t.DetectionStrategies, cache),
		}
	case attackTypes.KindTactic:
		c.Tactic = AttackContentTactic{
			Shortname:  a.Tactic.Shortname,
			Techniques: ToAttackRefs(a.Tactic.Techniques, cache),
		}
	case attackTypes.KindMitigation:
		c.Mitigation = AttackContentMitigation{
			TechniquesMitigated: toAttackContentTechniquesMitigated(a.Mitigation.TechniquesMitigated, cache),
		}
	case attackTypes.KindGroup:
		g := a.Group
		c.Group = AttackContentGroup{
			Aliases:             g.Aliases,
			TechniquesUsed:      toAttackContentTechniquesUsed(g.TechniquesUsed, cache),
			SoftwaresUsed:       ToAttackRefs(g.SoftwaresUsed, cache),
			CampaignsAttributed: ToAttackRefs(g.CampaignsAttributed, cache),
		}
	case attackTypes.KindSoftware:
		s := a.Software
		c.Software = AttackContentSoftware{
			Type:           s.Type,
			Aliases:        s.Aliases,
			Platforms:      s.Platforms,
			TechniquesUsed: toAttackContentTechniquesUsed(s.TechniquesUsed, cache),
			GroupsUsing:    ToAttackRefs(s.GroupsUsing, cache),
			CampaignsUsing: ToAttackRefs(s.CampaignsUsing, cache),
		}
	case attackTypes.KindCampaign:
		cp := a.Campaign
		c.Campaign = AttackContentCampaign{
			Aliases:          cp.Aliases,
			FirstSeen:        cp.FirstSeen,
			LastSeen:         cp.LastSeen,
			TechniquesUsed:   toAttackContentTechniquesUsed(cp.TechniquesUsed, cache),
			GroupsAttributed: ToAttackRefs(cp.GroupsAttributed, cache),
			SoftwaresUsed:    ToAttackRefs(cp.SoftwaresUsed, cache),
		}
	case attackTypes.KindAsset:
		as := a.Asset
		c.Asset = AttackContentAsset{
			Platforms:           as.Platforms,
			Sectors:             as.Sectors,
			RelatedAssets:       as.RelatedAssets,
			TechniquesTargeting: toAttackContentTechniquesTargeting(as.TechniquesTargeting, cache),
		}
	case attackTypes.KindDetectStrategy:
		d := a.DetectionStrategy
		c.DetectionStrategy = AttackContentDetectionStrategy{
			Analytics:          ToAttackRefs(d.Analytics, cache),
			TechniquesDetected: toAttackContentTechniquesDetected(d.TechniquesDetected, cache),
		}
	case attackTypes.KindDataSource:
		d := a.AttackDataSource
		c.AttackDataSource = AttackContentDataSource{
			Platforms:        d.Platforms,
			CollectionLayers: d.CollectionLayers,
			DataComponents:   ToAttackRefs(d.DataComponents, cache),
		}
	case attackTypes.KindDataComponent:
		d := a.DataComponent
		c.DataComponent = AttackContentDataComponent{
			DataSource: func() *AttackRef {
				if d.DataSource == "" {
					return nil
				}
				ref := ToAttackRef(d.DataSource, cache)
				return &ref
			}(),
			LogSources: d.LogSources,
		}
	case attackTypes.KindAnalytic:
		an := a.Analytic
		c.Analytic = AttackContentAnalytic{
			DetectionStrategy: func() *AttackRef {
				if an.DetectionStrategy == "" {
					return nil
				}
				ref := ToAttackRef(an.DetectionStrategy, cache)
				return &ref
			}(),
			Platforms:           an.Platforms,
			LogSourceReferences: an.LogSourceReferences,
			MutableElements:     an.MutableElements,
		}
	}
	return c
}

func toAttackContentProcedures(items []procedureTypes.Procedure, cache map[string]*attackTypes.Attack) []AttackContentProcedure {
	if len(items) == 0 {
		return nil
	}
	out := make([]AttackContentProcedure, 0, len(items))
	for _, p := range items {
		out = append(out, AttackContentProcedure{
			Attacker:    ToAttackRef(p.AttackerID, cache),
			Description: p.Description,
		})
	}
	return out
}

func toAttackContentTechniquesUsed(items []techniqueusedTypes.TechniqueUsed, cache map[string]*attackTypes.Attack) []AttackContentTechniqueUsed {
	if len(items) == 0 {
		return nil
	}
	out := make([]AttackContentTechniqueUsed, 0, len(items))
	for _, t := range items {
		out = append(out, AttackContentTechniqueUsed{
			Technique:   ToAttackRef(t.ID, cache),
			Description: t.Description,
		})
	}
	return out
}

func toAttackContentMitigationsApplied(items []relatedrefTypes.RelatedRef, cache map[string]*attackTypes.Attack) []AttackContentMitigationApplied {
	if len(items) == 0 {
		return nil
	}
	out := make([]AttackContentMitigationApplied, 0, len(items))
	for _, r := range items {
		out = append(out, AttackContentMitigationApplied{
			Mitigation:  ToAttackRef(r.ID, cache),
			Description: r.Description,
		})
	}
	return out
}

func toAttackContentTechniquesMitigated(items []relatedrefTypes.RelatedRef, cache map[string]*attackTypes.Attack) []AttackContentTechniqueMitigated {
	if len(items) == 0 {
		return nil
	}
	out := make([]AttackContentTechniqueMitigated, 0, len(items))
	for _, r := range items {
		out = append(out, AttackContentTechniqueMitigated{
			Technique:   ToAttackRef(r.ID, cache),
			Description: r.Description,
		})
	}
	return out
}

func toAttackContentDetectionsApplied(items []relatedrefTypes.RelatedRef, cache map[string]*attackTypes.Attack) []AttackContentDetectionApplied {
	if len(items) == 0 {
		return nil
	}
	out := make([]AttackContentDetectionApplied, 0, len(items))
	for _, r := range items {
		out = append(out, AttackContentDetectionApplied{
			DetectionStrategy: ToAttackRef(r.ID, cache),
			Description:       r.Description,
		})
	}
	return out
}

func toAttackContentTechniquesDetected(items []relatedrefTypes.RelatedRef, cache map[string]*attackTypes.Attack) []AttackContentTechniqueDetected {
	if len(items) == 0 {
		return nil
	}
	out := make([]AttackContentTechniqueDetected, 0, len(items))
	for _, r := range items {
		out = append(out, AttackContentTechniqueDetected{
			Technique:   ToAttackRef(r.ID, cache),
			Description: r.Description,
		})
	}
	return out
}

func toAttackContentAssetsTargeted(items []relatedrefTypes.RelatedRef, cache map[string]*attackTypes.Attack) []AttackContentAssetTargeted {
	if len(items) == 0 {
		return nil
	}
	out := make([]AttackContentAssetTargeted, 0, len(items))
	for _, r := range items {
		out = append(out, AttackContentAssetTargeted{
			Asset:       ToAttackRef(r.ID, cache),
			Description: r.Description,
		})
	}
	return out
}

func toAttackContentTechniquesTargeting(items []relatedrefTypes.RelatedRef, cache map[string]*attackTypes.Attack) []AttackContentTechniqueTargeting {
	if len(items) == 0 {
		return nil
	}
	out := make([]AttackContentTechniqueTargeting, 0, len(items))
	for _, r := range items {
		out = append(out, AttackContentTechniqueTargeting{
			Technique:   ToAttackRef(r.ID, cache),
			Description: r.Description,
		})
	}
	return out
}

// CollectAttackRefs returns every Attack external ID referenced by the
// record's kind-specific fields. Used by Session.GetAttackData to walk
// one level of references and build the AttackRef cache.
func CollectAttackRefs(a attackTypes.Attack) []string {
	out := make([]string, 0)
	// Technique
	for _, r := range a.Technique.Mitigations {
		if r.ID != "" {
			out = append(out, r.ID)
		}
	}
	out = append(out, a.Technique.Subtechniques...)
	for _, r := range a.Technique.AssetsTargeted {
		if r.ID != "" {
			out = append(out, r.ID)
		}
	}
	for _, r := range a.Technique.DetectionStrategies {
		if r.ID != "" {
			out = append(out, r.ID)
		}
	}
	if a.Technique.Parent != "" {
		out = append(out, a.Technique.Parent)
	}
	for _, p := range a.Technique.Procedures {
		if p.AttackerID != "" {
			out = append(out, p.AttackerID)
		}
	}
	// Tactic
	out = append(out, a.Tactic.Techniques...)
	// Mitigation
	for _, r := range a.Mitigation.TechniquesMitigated {
		if r.ID != "" {
			out = append(out, r.ID)
		}
	}
	// Group
	for _, t := range a.Group.TechniquesUsed {
		if t.ID != "" {
			out = append(out, t.ID)
		}
	}
	out = append(out, a.Group.SoftwaresUsed...)
	out = append(out, a.Group.CampaignsAttributed...)
	// Software
	for _, t := range a.Software.TechniquesUsed {
		if t.ID != "" {
			out = append(out, t.ID)
		}
	}
	out = append(out, a.Software.GroupsUsing...)
	out = append(out, a.Software.CampaignsUsing...)
	// Campaign
	for _, t := range a.Campaign.TechniquesUsed {
		if t.ID != "" {
			out = append(out, t.ID)
		}
	}
	out = append(out, a.Campaign.GroupsAttributed...)
	out = append(out, a.Campaign.SoftwaresUsed...)
	// Asset
	for _, r := range a.Asset.TechniquesTargeting {
		if r.ID != "" {
			out = append(out, r.ID)
		}
	}
	// DetectionStrategy
	out = append(out, a.DetectionStrategy.Analytics...)
	for _, r := range a.DetectionStrategy.TechniquesDetected {
		if r.ID != "" {
			out = append(out, r.ID)
		}
	}
	// DataSource (kind)
	out = append(out, a.AttackDataSource.DataComponents...)
	// DataComponent
	if a.DataComponent.DataSource != "" {
		out = append(out, a.DataComponent.DataSource)
	}
	// Analytic
	if a.Analytic.DetectionStrategy != "" {
		out = append(out, a.Analytic.DetectionStrategy)
	}
	return out
}
