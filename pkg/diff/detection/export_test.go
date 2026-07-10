package detection

type DetectFunc = func(baselineBin, baselineDB, targetBin, targetDB string, files map[string]string) (map[string]CVEIDs, error)

func WithDetectFunc(f DetectFunc) Option {
	return detectFuncOption{f: f}
}

type detectFuncOption struct{ f DetectFunc }

func (o detectFuncOption) apply(opts *options) {
	opts.detectFunc = o.f
}

type (
	VulnInfo   = vulnInfo
	CveContent = cveContent
	CVEIDs     = cveIDs
)

var (
	Subtract       = subtract
	DiffDetection  = diffDetection
	GenerateReport = generateReport
	CollectSources = collectSources
)
