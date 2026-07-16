package validate

import (
	"encoding/json/v2"
	"fmt"
	"runtime"
	"strings"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls2/pkg/data/validate"
)

func NewCmd() *cobra.Command {
	options := struct {
		checks      []string
		format      string
		concurrency int
	}{
		checks:      nil,
		format:      "text",
		concurrency: runtime.NumCPU(),
	}

	cmd := &cobra.Command{
		Use:   "validate <extracted repository>",
		Short: "validate extracted data semantically",
		Example: heredoc.Doc(`
		$ vuls data validate vuls-data-extracted-nvd-api-cve
		$ vuls data validate --checks cpe-pvp,orphan-segment --format json vuls-data-extracted-redhat-ovalv2
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			findings, err := validate.Validate(args[0], validate.WithChecks(options.checks), validate.WithConcurrency(options.concurrency))
			if err != nil {
				return errors.Wrap(err, "data validate")
			}

			for _, f := range findings {
				switch options.format {
				case "text":
					fmt.Printf("%s: %s: %s\n", f.Path, f.Check, f.Message)
				case "json":
					bs, err := json.Marshal(f)
					if err != nil {
						return errors.Wrap(err, "marshal finding")
					}
					fmt.Printf("%s\n", bs)
				default:
					return errors.Errorf("unexpected format. expected: %q, actual: %q", []string{"text", "json"}, options.format)
				}
			}

			if len(findings) > 0 {
				return errors.Errorf("validation failed. %d finding(s)", len(findings))
			}
			return nil
		},
	}

	cmd.Flags().StringSliceVarP(&options.checks, "checks", "", options.checks, fmt.Sprintf("checks to run (default: all, accepts: [%s])", strings.Join(func() []string {
		var names []string
		for _, c := range validate.Checks() {
			names = append(names, c.Name)
		}
		return names
	}(), ", ")))
	cmd.Flags().StringVarP(&options.format, "format", "", options.format, "output format (default: text, accepts: [text, json])")
	cmd.Flags().IntVarP(&options.concurrency, "concurrency", "", options.concurrency, "number of files validated in parallel")

	return cmd
}
