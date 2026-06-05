package search

import (
	"time"

	attackTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack"
	analyticTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/analytic"
	assetTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/asset"
	datacomponentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/datacomponent"
	techniqueusedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack/techniqueused"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
)

// AttackRef is the minimal reference embedded in an AttackResult whenever
// the underlying Attack record holds another Attack record's external ID.
// Carries just enough information (ID, Kind, Name, Description) for a
// single response to render the same bidirectional links as the MITRE
// ATT&CK web UI without the client having to fetch each referenced
// record separately.
type AttackRef struct {
	ID          string           `json:"id"`
	Kind        attackTypes.Kind `json:"kind,omitempty"`
	Name        string           `json:"name,omitempty"`
	Description string           `json:"description,omitempty"`
}

// AttackResult mirrors attackTypes.Attack but replaces every kind-specific
// ID reference with an AttackRef so callers receive embedded minimal
// records instead of just IDs.
type AttackResult struct {
	ID          string           `json:"id"`
	Kind        attackTypes.Kind `json:"kind,omitempty"`
	Name        string           `json:"name,omitempty"`
	Description string           `json:"description,omitempty"`
	Domains     []string         `json:"domains,omitempty"`
	Deprecated  bool             `json:"deprecated,omitempty"`
	Revoked     bool             `json:"revoked,omitempty"`
	Version     string           `json:"version,omitempty"`
	Modified    time.Time        `json:"modified,omitzero"`

	Technique         AttackResultTechnique         `json:"technique,omitzero"`
	Tactic            AttackResultTactic            `json:"tactic,omitzero"`
	Mitigation        AttackResultMitigation        `json:"mitigation,omitzero"`
	Group             AttackResultGroup             `json:"group,omitzero"`
	Software          AttackResultSoftware          `json:"software,omitzero"`
	Campaign          AttackResultCampaign          `json:"campaign,omitzero"`
	Asset             AttackResultAsset             `json:"asset,omitzero"`
	DetectionStrategy AttackResultDetectionStrategy `json:"detection_strategy,omitzero"`
	AttackDataSource  AttackResultDataSource        `json:"attack_data_source,omitzero"`
	DataComponent     AttackResultDataComponent     `json:"data_component,omitzero"`
	Analytic          AttackResultAnalytic          `json:"analytic,omitzero"`

	References []referenceTypes.Reference `json:"references,omitempty"`
	DataSource sourceTypes.Source         `json:"data_source,omitzero"`
}

type AttackResultProcedure struct {
	Attacker    AttackRef `json:"attacker"`
	Description string    `json:"description,omitempty"`
}

type AttackResultTechniqueUsed struct {
	Technique   AttackRef `json:"technique"`
	Description string    `json:"description,omitempty"`
}

type AttackResultTechnique struct {
	Platforms            []string                `json:"platforms,omitempty"`
	Tactics              []string                `json:"tactics,omitempty"`
	IsSubtechnique       bool                    `json:"is_subtechnique,omitempty"`
	Parent               *AttackRef              `json:"parent,omitempty"`
	Detection            string                  `json:"detection,omitempty"`
	DataSources          []string                `json:"data_sources,omitempty"`
	Mitigations          []AttackRef             `json:"mitigations,omitempty"`
	Procedures           []AttackResultProcedure `json:"procedures,omitempty"`
	PermissionsRequired  []string                `json:"permissions_required,omitempty"`
	EffectivePermissions []string                `json:"effective_permissions,omitempty"`
	DefenseBypassed      []string                `json:"defense_bypassed,omitempty"`
	ImpactType           []string                `json:"impact_type,omitempty"`
	NetworkRequirements  bool                    `json:"network_requirements,omitempty"`
	RemoteSupport        bool                    `json:"remote_support,omitempty"`
	Subtechniques        []AttackRef             `json:"subtechniques,omitempty"`
	AssetsTargeted       []AttackRef             `json:"assets_targeted,omitempty"`
	DetectionStrategies  []AttackRef             `json:"detection_strategies,omitempty"`
}

type AttackResultTactic struct {
	Shortname  string      `json:"shortname,omitempty"`
	Techniques []AttackRef `json:"techniques,omitempty"`
}

type AttackResultMitigation struct {
	TechniquesMitigated []AttackRef `json:"techniques_mitigated,omitempty"`
}

type AttackResultGroup struct {
	Aliases             []string                    `json:"aliases,omitempty"`
	TechniquesUsed      []AttackResultTechniqueUsed `json:"techniques_used,omitempty"`
	SoftwaresUsed       []AttackRef                 `json:"softwares_used,omitempty"`
	CampaignsAttributed []AttackRef                 `json:"campaigns_attributed,omitempty"`
}

type AttackResultSoftware struct {
	Type           string                      `json:"type,omitempty"`
	Aliases        []string                    `json:"aliases,omitempty"`
	Platforms      []string                    `json:"platforms,omitempty"`
	TechniquesUsed []AttackResultTechniqueUsed `json:"techniques_used,omitempty"`
	GroupsUsing    []AttackRef                 `json:"groups_using,omitempty"`
	CampaignsUsing []AttackRef                 `json:"campaigns_using,omitempty"`
}

type AttackResultCampaign struct {
	Aliases          []string                    `json:"aliases,omitempty"`
	FirstSeen        time.Time                   `json:"first_seen,omitzero"`
	LastSeen         time.Time                   `json:"last_seen,omitzero"`
	TechniquesUsed   []AttackResultTechniqueUsed `json:"techniques_used,omitempty"`
	GroupsAttributed []AttackRef                 `json:"groups_attributed,omitempty"`
	SoftwaresUsed    []AttackRef                 `json:"softwares_used,omitempty"`
}

type AttackResultAsset struct {
	Platforms           []string                  `json:"platforms,omitempty"`
	Sectors             []string                  `json:"sectors,omitempty"`
	RelatedAssets       []assetTypes.RelatedAsset `json:"related_assets,omitempty"`
	TechniquesTargeting []AttackRef               `json:"techniques_targeting,omitempty"`
}

type AttackResultDetectionStrategy struct {
	Analytics          []AttackRef `json:"analytics,omitempty"`
	TechniquesDetected []AttackRef `json:"techniques_detected,omitempty"`
}

type AttackResultDataSource struct {
	Platforms        []string    `json:"platforms,omitempty"`
	CollectionLayers []string    `json:"collection_layers,omitempty"`
	DataComponents   []AttackRef `json:"data_components,omitempty"`
}

type AttackResultDataComponent struct {
	DataSource *AttackRef                     `json:"data_source,omitempty"`
	LogSources []datacomponentTypes.LogSource `json:"log_sources,omitempty"`
}

type AttackResultAnalytic struct {
	DetectionStrategy   *AttackRef                         `json:"detection_strategy,omitempty"`
	Platforms           []string                           `json:"platforms,omitempty"`
	LogSourceReferences []analyticTypes.LogSourceReference `json:"log_source_references,omitempty"`
	MutableElements     []analyticTypes.MutableElement     `json:"mutable_elements,omitempty"`
}

// toAttackRef converts an Attack external ID to an AttackRef by looking
// up the cache. If the ID isn't in cache the returned ref carries only
// the ID so callers can still see the unresolved reference.
func toAttackRef(id string, cache map[string]*attackTypes.Attack) AttackRef {
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

func toAttackRefs(ids []string, cache map[string]*attackTypes.Attack) []AttackRef {
	if len(ids) == 0 {
		return nil
	}
	out := make([]AttackRef, 0, len(ids))
	for _, id := range ids {
		out = append(out, toAttackRef(id, cache))
	}
	return out
}

// toAttackResult expands an Attack record's kind-specific reference IDs
// into embedded AttackRef values, returning the search-time view.
func toAttackResult(a *attackTypes.Attack, cache map[string]*attackTypes.Attack) AttackResult {
	if a == nil {
		return AttackResult{}
	}
	r := AttackResult{
		ID:          a.ID,
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
		r.Technique = AttackResultTechnique{
			Platforms:      t.Platforms,
			Tactics:        t.Tactics,
			IsSubtechnique: t.IsSubtechnique,
			Parent: func() *AttackRef {
				if t.Parent == "" {
					return nil
				}
				ref := toAttackRef(t.Parent, cache)
				return &ref
			}(),
			Detection:   t.Detection,
			DataSources: t.DataSources,
			Mitigations: toAttackRefs(t.Mitigations, cache),
			Procedures: func() []AttackResultProcedure {
				if len(t.Procedures) == 0 {
					return nil
				}
				out := make([]AttackResultProcedure, 0, len(t.Procedures))
				for _, p := range t.Procedures {
					out = append(out, AttackResultProcedure{
						Attacker:    toAttackRef(p.AttackerID, cache),
						Description: p.Description,
					})
				}
				return out
			}(),
			PermissionsRequired:  t.PermissionsRequired,
			EffectivePermissions: t.EffectivePermissions,
			DefenseBypassed:      t.DefenseBypassed,
			ImpactType:           t.ImpactType,
			NetworkRequirements:  t.NetworkRequirements,
			RemoteSupport:        t.RemoteSupport,
			Subtechniques:        toAttackRefs(t.Subtechniques, cache),
			AssetsTargeted:       toAttackRefs(t.AssetsTargeted, cache),
			DetectionStrategies:  toAttackRefs(t.DetectionStrategies, cache),
		}
	case attackTypes.KindTactic:
		r.Tactic = AttackResultTactic{
			Shortname:  a.Tactic.Shortname,
			Techniques: toAttackRefs(a.Tactic.Techniques, cache),
		}
	case attackTypes.KindMitigation:
		r.Mitigation = AttackResultMitigation{
			TechniquesMitigated: toAttackRefs(a.Mitigation.TechniquesMitigated, cache),
		}
	case attackTypes.KindGroup:
		g := a.Group
		r.Group = AttackResultGroup{
			Aliases:             g.Aliases,
			TechniquesUsed:      convertTechniquesUsed(g.TechniquesUsed, cache),
			SoftwaresUsed:       toAttackRefs(g.SoftwaresUsed, cache),
			CampaignsAttributed: toAttackRefs(g.CampaignsAttributed, cache),
		}
	case attackTypes.KindSoftware:
		s := a.Software
		r.Software = AttackResultSoftware{
			Type:           s.Type,
			Aliases:        s.Aliases,
			Platforms:      s.Platforms,
			TechniquesUsed: convertTechniquesUsed(s.TechniquesUsed, cache),
			GroupsUsing:    toAttackRefs(s.GroupsUsing, cache),
			CampaignsUsing: toAttackRefs(s.CampaignsUsing, cache),
		}
	case attackTypes.KindCampaign:
		c := a.Campaign
		r.Campaign = AttackResultCampaign{
			Aliases:          c.Aliases,
			FirstSeen:        c.FirstSeen,
			LastSeen:         c.LastSeen,
			TechniquesUsed:   convertTechniquesUsed(c.TechniquesUsed, cache),
			GroupsAttributed: toAttackRefs(c.GroupsAttributed, cache),
			SoftwaresUsed:    toAttackRefs(c.SoftwaresUsed, cache),
		}
	case attackTypes.KindAsset:
		as := a.Asset
		r.Asset = AttackResultAsset{
			Platforms:           as.Platforms,
			Sectors:             as.Sectors,
			RelatedAssets:       as.RelatedAssets,
			TechniquesTargeting: toAttackRefs(as.TechniquesTargeting, cache),
		}
	case attackTypes.KindDetectStrategy:
		d := a.DetectionStrategy
		r.DetectionStrategy = AttackResultDetectionStrategy{
			Analytics:          toAttackRefs(d.Analytics, cache),
			TechniquesDetected: toAttackRefs(d.TechniquesDetected, cache),
		}
	case attackTypes.KindDataSource:
		d := a.AttackDataSource
		r.AttackDataSource = AttackResultDataSource{
			Platforms:        d.Platforms,
			CollectionLayers: d.CollectionLayers,
			DataComponents:   toAttackRefs(d.DataComponents, cache),
		}
	case attackTypes.KindDataComponent:
		d := a.DataComponent
		r.DataComponent = AttackResultDataComponent{
			DataSource: func() *AttackRef {
				if d.DataSource == "" {
					return nil
				}
				ref := toAttackRef(d.DataSource, cache)
				return &ref
			}(),
			LogSources: d.LogSources,
		}
	case attackTypes.KindAnalytic:
		an := a.Analytic
		r.Analytic = AttackResultAnalytic{
			DetectionStrategy: func() *AttackRef {
				if an.DetectionStrategy == "" {
					return nil
				}
				ref := toAttackRef(an.DetectionStrategy, cache)
				return &ref
			}(),
			Platforms:           an.Platforms,
			LogSourceReferences: an.LogSourceReferences,
			MutableElements:     an.MutableElements,
		}
	}
	return r
}

func convertTechniquesUsed(items []techniqueusedTypes.TechniqueUsed, cache map[string]*attackTypes.Attack) []AttackResultTechniqueUsed {
	if len(items) == 0 {
		return nil
	}
	out := make([]AttackResultTechniqueUsed, 0, len(items))
	for _, t := range items {
		out = append(out, AttackResultTechniqueUsed{
			Technique:   toAttackRef(t.ID, cache),
			Description: t.Description,
		})
	}
	return out
}
