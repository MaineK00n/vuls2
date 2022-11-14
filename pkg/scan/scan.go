package scan

import (
	"context"
	"runtime"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls2/pkg/cmd/version"
	"github.com/MaineK00n/vuls2/pkg/scan/cpe"
	"github.com/MaineK00n/vuls2/pkg/scan/os"
	"github.com/MaineK00n/vuls2/pkg/scan/systeminfo"
	scanTypes "github.com/MaineK00n/vuls2/pkg/scan/types"
	"github.com/MaineK00n/vuls2/pkg/types"
)

func Scan(ctx context.Context, host *types.Host) error {
	ah := scanTypes.AnalyzerHost{Host: host}
	if ah.Host.Config.Scan.OSPkg != nil {
		if runtime.GOOS == "windows" {
			ah.Analyzers = append(ah.Analyzers, systeminfo.Analyzer{})
		} else {
			ah.Analyzers = append(ah.Analyzers, os.Analyzer{})
		}
	}
	if len(ah.Host.Config.Scan.CPE) > 0 {
		ah.Analyzers = append(ah.Analyzers, cpe.Analyzer{})
	}

	var (
		err error
	)
	for {
		if len(ah.Analyzers) == 0 {
			break
		}
		a := ah.Analyzers[0]
		if err = a.Analyze(ctx, &ah); err != nil {
			break
		}
		ah.Analyzers = ah.Analyzers[1:]
	}

	t := time.Now()
	ah.Host.ScannedAt = &t
	ah.Host.ScannedVersion = version.Version
	ah.Host.ScannedRevision = version.Revision

	if err != nil {
		return errors.Wrapf(err, "analyze %s", ah.Host.Name)
	}
	return nil
}
