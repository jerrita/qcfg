// Package cli implements the qcfg commands.
package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/jerrita/qcfg/internal/client"
	"github.com/jerrita/qcfg/internal/state"
)

var (
	dryRun  bool
	jsonOut bool
)

func Root() *cobra.Command {
	root := &cobra.Command{
		Use:           "qcfg",
		Short:         "Cross-platform config sync",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().BoolVar(&dryRun, "dry-run", false, "show what would change without writing")
	root.PersistentFlags().BoolVar(&jsonOut, "json", false, "machine-readable output")
	root.AddCommand(authCmd(), lsCmd(), statusCmd(), syncCmd(), pullCmd(), pushCmd(), diffCmd(),
		addCmd(), rmCmd(), unsubscribeCmd(), logCmd(), restoreCmd(), serveCmd())
	return root
}

// session loads the config, state and an authenticated client.
func session() (*state.Config, state.State, *client.Client, error) {
	cfg, err := state.LoadConfig()
	if err != nil {
		return nil, nil, nil, err
	}
	if cfg.Server == "" || cfg.Token == "" {
		return nil, nil, nil, errors.New("not logged in, run `qcfg auth login`")
	}
	st, err := state.LoadState()
	if err != nil {
		return nil, nil, nil, err
	}
	return cfg, st, client.New(cfg.Server, cfg.Token), nil
}

func subscribed(cfg *state.Config) []string {
	ps := make([]string, 0, len(cfg.Projects))
	for p := range cfg.Projects {
		ps = append(ps, p)
	}
	sort.Strings(ps)
	return ps
}

func printJSON(v any) error {
	e := json.NewEncoder(os.Stdout)
	e.SetIndent("", "  ")
	return e.Encode(v)
}

func table(fn func(w io.Writer)) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fn(w)
	w.Flush()
}

func splitFileArg(s string) (string, string, error) {
	for i := range len(s) {
		if s[i] == '/' {
			if i > 0 && i < len(s)-1 {
				return s[:i], s[i+1:], nil
			}
			break
		}
	}
	return "", "", fmt.Errorf("expected <project>/<file>, got %q", s)
}
