package scan

import (
	"path/filepath"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls2/pkg/scan"
	utilos "github.com/MaineK00n/vuls2/pkg/util/os"
)

func NewCmd() *cobra.Command {
	options := struct {
		resultsDir string
		debug      bool
	}{
		resultsDir: filepath.Join(utilos.UserCacheDir(), "results"),
		debug:      false,
	}

	cmd := &cobra.Command{
		Use:   "scan <vuls v1 results rootdir>",
		Short: "translate vuls v1 scan result to vuls nightly scan result",
		Example: heredoc.Doc(`
		$ vuls scan results
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := scan.Scan(args[0], scan.WithResultsDir(options.resultsDir), scan.WithDebug(options.debug)); err != nil {
				return errors.Wrap(err, "scan")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.resultsDir, "results-dir", "", options.resultsDir, "vuls results path")
	cmd.Flags().BoolVarP(&options.debug, "debug", "d", options.debug, "debug mode")

	return cmd
}
