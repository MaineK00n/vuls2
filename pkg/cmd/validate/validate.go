package validate

import (
	"encoding/json/v2"
	"fmt"
	"runtime"
	"slices"
	"strings"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls2/pkg/validate"
)

func NewCmd() *cobra.Command {
	options := struct {
		rules       []string
		format      string
		concurrency int
	}{
		rules:       nil,
		format:      "text",
		concurrency: runtime.NumCPU(),
	}

	cmd := &cobra.Command{
		Use:   "validate <extracted repository>",
		Short: "validate an extracted repository semantically",
		Long: heredoc.Doc(`
		Validate an extracted repository. The repository layout is checked as a
		whole, and content directories (data, ...) are discovered automatically and
		validated with their own rules when present.
		`),
		Example: heredoc.Doc(`
		$ vuls validate vuls-data-extracted-redhat-cve
		$ vuls validate --rules cpe-pvp,orphan-segment --format json vuls-data-extracted-nvd-feed-cve-v2
		`),
		Args: cobra.ExactArgs(1),
		PreRunE: func(_ *cobra.Command, _ []string) error {
			switch options.format {
			case "text", "json":
				return nil
			default:
				return errors.Errorf("unexpected format. expected: %q, actual: %q", []string{"text", "json"}, options.format)
			}
		},
		RunE: func(_ *cobra.Command, args []string) error {
			findings, err := validate.Validate(args[0], validate.WithRules(options.rules), validate.WithConcurrency(options.concurrency))
			if err != nil {
				return errors.Wrap(err, "validate")
			}

			slices.SortFunc(findings, validate.Finding.Compare)
			for _, f := range findings {
				switch options.format {
				case "text":
					switch {
					case f.Line > 0:
						fmt.Printf("%s:%d: %s: %s\n", f.Path, f.Line, f.Rule, f.Message)
					default:
						fmt.Printf("%s: %s: %s\n", f.Path, f.Rule, f.Message)
					}
				case "json":
					bs, err := json.Marshal(f)
					if err != nil {
						return errors.Wrap(err, "marshal finding")
					}
					fmt.Printf("%s\n", bs)
				default:
					// Unreachable: PreRunE already validated the format.
					return errors.Errorf("unexpected format. expected: %q, actual: %q", []string{"text", "json"}, options.format)
				}
			}

			if len(findings) > 0 {
				// An expected outcome, not an execution failure: use a plain
				// error so main's %+v does not print a stack trace after the
				// findings.
				return fmt.Errorf("validation failed. %d finding(s)", len(findings))
			}
			return nil
		},
	}

	cmd.Flags().StringSliceVarP(&options.rules, "rules", "", options.rules, fmt.Sprintf("rules to run (default: all, accepts: [%s])", strings.Join(func() []string {
		var names []string
		for _, c := range validate.RepositoryRules() {
			names = append(names, c.Name)
		}
		for _, c := range validate.DataRules() {
			names = append(names, c.Name)
		}
		for _, c := range validate.CriteriaRules() {
			names = append(names, c.Name)
		}
		return names
	}(), ", ")))
	cmd.Flags().StringVarP(&options.format, "format", "", options.format, "output format (default: text, accepts: [text, json])")
	cmd.Flags().IntVarP(&options.concurrency, "concurrency", "", options.concurrency, "number of files validated in parallel")

	return cmd
}
