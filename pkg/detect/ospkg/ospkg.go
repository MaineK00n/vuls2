package ospkg

import (
	"iter"

	"github.com/pkg/errors"

	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
	"github.com/MaineK00n/vuls2/pkg/db/session"
	"github.com/MaineK00n/vuls2/pkg/detect/ospkg/base"
	"github.com/MaineK00n/vuls2/pkg/detect/ospkg/microsoft"
	"github.com/MaineK00n/vuls2/pkg/detect/util"
	scanTypes "github.com/MaineK00n/vuls2/pkg/scan/types"
)

// Detect yields each rootID's detection (full criteria trees) as it is
// produced, so the consumer can apply its own retention policy per element
// instead of holding the whole result. A yielded non-nil error is
// terminal.
func Detect(s session.Storage, sr scanTypes.ScanResult, concurrency int) iter.Seq2[util.RootDetection, error] {
	return func(yield func(util.RootDetection, error) bool) {
		ecosystem, err := ecosystemTypes.GetEcosystem(string(sr.Family), sr.Release)
		if err != nil {
			yield(util.RootDetection{}, errors.Wrapf(err, "get ecosystem. family: %s, release: %s", sr.Family, sr.Release))
			return
		}

		seq := func() iter.Seq2[util.RootDetection, error] {
			switch ecosystem {
			case ecosystemTypes.EcosystemTypeMicrosoft:
				return microsoft.Detect(s, ecosystem, sr, concurrency)
			default:
				return base.Detect(s, ecosystem, sr, concurrency)
			}
		}()
		for rd, err := range seq {
			if !yield(rd, err) {
				return
			}
		}
	}
}
