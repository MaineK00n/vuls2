package types

import (
	"context"

	"github.com/MaineK00n/vuls2/pkg/types"
)

type Detector interface {
	Name() string
	Detect(context.Context, *types.Host) error
}
