package fetch

import (
	"path/filepath"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	db "github.com/MaineK00n/vuls2/pkg/db/fetch"
	utilos "github.com/MaineK00n/vuls2/pkg/util/os"
)

func NewCmd() *cobra.Command {
	options := struct {
		dbpath     string
		repository string
		proxy      string
		noProgress bool
		debug      bool
	}{
		dbpath:     filepath.Join(utilos.UserCacheDir(), "vuls.db"),
		repository: "ghcr.io/mainek00n/vuls2:latest",
		proxy:      "",
		noProgress: false,
		debug:      false,
	}

	cmd := &cobra.Command{
		Use:   "fetch",
		Short: "fetch vuls.db from GHCR",
		Example: heredoc.Doc(`
		$ vuls db fetch
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := db.Fetch(db.WithDBPath(options.dbpath), db.WithRepository(options.repository), db.WithProxy(options.proxy), db.WithNoProgress(options.noProgress), db.WithDebug(options.debug)); err != nil {
				return errors.Wrap(err, "db fetch")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dbpath, "dbpath", "", options.dbpath, "vuls db path")
	cmd.Flags().StringVarP(&options.repository, "repository", "", options.repository, "vuls db repository")
	cmd.Flags().StringVarP(&options.proxy, "proxy", "", options.proxy, "http proxy")
	cmd.Flags().BoolVarP(&options.noProgress, "no-progress", "", options.noProgress, "no progress bar")
	cmd.Flags().BoolVarP(&options.debug, "debug", "d", options.debug, "debug mode")

	return cmd
}
