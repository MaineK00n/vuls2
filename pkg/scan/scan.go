package scan

import (
	"context"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls2/pkg/cmd/version"
	"github.com/MaineK00n/vuls2/pkg/scan/cpe"
	"github.com/MaineK00n/vuls2/pkg/scan/os"
	scanTypes "github.com/MaineK00n/vuls2/pkg/scan/types"
	"github.com/MaineK00n/vuls2/pkg/types"
)

func Scan(ctx context.Context, host *types.Host) error {
	if err := Validate(host.Config); err != nil {
		return errors.Wrap(err, "validate config for scan")
	}

	ah := scanTypes.AnalyzerHost{Host: host}
	if ah.Host.Config.Scan.OSPkg != nil {
		ah.Analyzers = append(ah.Analyzers, os.Analyzer{})
	}
	if len(ah.Host.Config.Scan.CPE) > 0 {
		ah.Analyzers = append(ah.Analyzers, cpe.Analyzer{})
	}

	var (
		index int
		err   error
	)
	for {
		if len(ah.Analyzers) == 0 {
			break
		}
		a := ah.Analyzers[index]
		if err = a.Analyze(ctx, &ah); err != nil {
			break
		}
		ah.Analyzers = ah.Analyzers[index+1:]
	}

	ah.Host.ScannedAt = time.Now()
	ah.Host.ScannedVersion = version.Version
	ah.Host.ScannedRevision = version.Revision

	if err != nil {
		return errors.Wrapf(err, "analyze %s", ah.Host.Name)
	}
	return nil
}

func Validate(c types.Config) error {
	switch c.Type {
	case "local":
	case "remote":
	case "ssh-config":
	default:
		return errors.Errorf("%s is not implemented", c.Type)
	}

	if c.Scan == nil {
		return errors.Errorf("%s is not set Scan Config")
	}

	return nil
}
