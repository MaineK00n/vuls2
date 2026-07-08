package db

var (
	GetEcosystems     = getEcosystems
	DiffEcosystem     = diffEcosystem
	CompareCriterions = compareCriterions
	CountCriterions   = countCriterions
	CompareKBs        = compareKBs
	CountKBs          = countKBs
	GenerateReport    = generateReport
)

// Counts exposes the per-source unit counts type for external tests.
type Counts = counts
