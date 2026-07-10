package db

var (
	GetEcosystems     = getEcosystems
	DiffEcosystem     = diffEcosystem
	CompareCriterions = compareCriterions
	CountCriterions   = countCriterions
	CompareKBs        = compareKBs
	KBSources         = kbSources
	GenerateReport    = generateReport
)

// UnitTally exposes the per-source unit tally type for external tests.
type UnitTally = unitTally
