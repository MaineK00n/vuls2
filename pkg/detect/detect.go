package detect

import (
	"context"
	"time"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls2/pkg/cmd/version"
	"github.com/MaineK00n/vuls2/pkg/detect/debian"
	detectTypes "github.com/MaineK00n/vuls2/pkg/detect/types"
	"github.com/MaineK00n/vuls2/pkg/detect/ubuntu"
	"github.com/MaineK00n/vuls2/pkg/types"
)

func Detect(ctx context.Context, host *types.Host) error {
	if host.Error != "" {
		return errors.Errorf("scan error: %s", host.Error)
	}

	var detectors []detectTypes.Detector
	if len(host.Packages.OSPkg) > 0 {
		switch host.Family {
		case "debian":
			detectors = append(detectors, debian.Detector{})
		case "ubuntu":
			detectors = append(detectors, ubuntu.Detector{})
		default:
			return errors.New("not implemented")
		}
	}

	var err error
	for {
		if len(detectors) == 0 {
			break
		}
		d := detectors[0]
		if err = d.Detect(ctx, host); err != nil {
			break
		}
		detectors = detectors[1:]
	}

	t := time.Now()
	host.DetecteddAt = &t
	host.DetectedVersion = version.Version
	host.DetectedRevision = version.Revision

	if err != nil {
		return errors.Wrapf(err, "detect %s", host.Name)
	}

	return nil
}
