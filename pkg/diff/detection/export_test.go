package detection

type DetectFunc = func(baselineBin, baselineDB, targetBin, targetDB string, files map[string]string) (map[string]FileDiff, error)

func WithDetectFunc(f DetectFunc) Option {
	return detectFuncOption{f: f}
}

type detectFuncOption struct{ f DetectFunc }

func (o detectFuncOption) apply(opts *options) {
	opts.detectFunc = o.f
}

type (
	VulnInfo   = vulnInfo
	Confidence = confidence
)

var (
	Subtract              = subtract
	DiffDetection         = diffDetection
	GenerateReport        = generateReport
	DetectionMethodFamily = detectionMethodFamily
	CollectFamilies       = collectFamilies
)
