package db

var (
	GetEcosystems      = getEcosystems
	DiffEcosystem      = diffEcosystem
	CompareCriterions  = compareCriterions
	CountCriterions    = countCriterions
	CompareKBs         = compareKBs
	KBSources          = kbSources
	GenerateReport     = generateReport
	EffectiveThreshold = effectiveThreshold
)

// Tally exposes the per-source unit tally type for external tests.
type Tally = tally
