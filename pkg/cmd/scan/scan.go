package scan

import (
	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"
)

type ScanOptions struct {
	Config string
}

func NewCmdScan() *cobra.Command {
	opts := &ScanOptions{
		Config: "config.json",
	}

	cmd := &cobra.Command{
		Use:   "scan ([\"host\"])",
		Short: "Vuls scan your machine information",
		RunE: func(_ *cobra.Command, _ []string) error {
			return nil
		},
		Example: heredoc.Doc(`
			$ vuls scan
			$ vuls scan host
		`),
	}

	cmd.Flags().StringVarP(&opts.Config, "config", "c", "config.json", "vuls config file path")

	return cmd
}
