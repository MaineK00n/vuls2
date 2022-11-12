package cpe

import (
	"context"

	"github.com/MaineK00n/vuls2/pkg/scan/types"
)

type Analyzer struct {
}

func (a Analyzer) Name() string {
	return "cpe analyzer"
}

func (a Analyzer) Analyze(ctx context.Context, ah *types.AnalyzerHost) error {
	return nil
}
