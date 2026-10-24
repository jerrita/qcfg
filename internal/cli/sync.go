package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/jerrita/qcfg/internal/client"
	"github.com/jerrita/qcfg/internal/pathx"
	"github.com/jerrita/qcfg/internal/state"
	"github.com/jerrita/qcfg/internal/syncer"
)

// targetsFor parses "project" / "project/file" args; no args selects all
// subscribed projects.
func targetsFor(cfg *state.Config, args []string) ([]syncer.Target, error) {
	if len(args) == 0 {
		ps := subscribed(cfg)
		if len(ps) == 0 {
			return nil, errors.New("no subscribed projects, run `qcfg pull <project>` first")
		}
		ts := make([]syncer.Target, len(ps))
		for i, p := range ps {
			ts[i] = syncer.Target{Project: p}
		}
		return ts, nil
	}
	ts := make([]syncer.Target, len(args))
	for i, a := range args {
		ts[i] = syncer.ParseTarget(a)
	}
	return ts, nil
}

// projectTargets builds targets from "<project> [file...]".
func projectTargets(args []string) []syncer.Target {
	if len(args) == 1 {
		return []syncer.Target{{Project: args[0]}}
	}
	ts := make([]syncer.Target, 0, len(args)-1)
	for _, f := range args[1:] {
		ts = append(ts, syncer.Target{Project: args[0], File: f})
	}
	return ts
}

func statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status [project[/file]...]",
		Short: "Show sync status without writing",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, st, c, err := session()
			if err != nil {
				return err
			}
			ts, err := targetsFor(cfg, args)
			if err != nil {
				return err
			}
			items, err := syncer.Plan(c, cfg, st, ts)
			if err != nil {
				return err
			}
			if jsonOut {
				return printJSON(items)
			}
			table(func(w io.Writer) {
				for _, it := range items {
					fmt.Fprintf(w, "%s\t%s\t%s\n", it.Status, it.Key(), describe(it.Path, it.Reason))
				}
			})
			return nil
		},
	}
}

func describe(path, reason string) string {
	p := pathx.Contract(path)
	switch {
	case path == "":
		return "(" + reason + ")"
	case reason != "":
		return p + "  (" + reason + ")"
	}
	return p
}

type result struct {
	Project string        `json:"project"`
	Name    string        `json:"name"`
	Path    string        `json:"path,omitempty"`
	Action  syncer.Action `json:"action"`
	Reason  string        `json:"reason,omitempty"`
	Error   string        `json:"error,omitempty"`
}

// run plans the targets, applies allowed actions and saves state.
func run(cfg *state.Config, st state.State, c *client.Client, ts []syncer.Target, o syncer.Options, message string) error {
	items, err := syncer.Plan(c, cfg, st, ts)
	if err != nil {
		return err
	}
	var results []result
	failed, upToDate := 0, 0
	for _, it := range items {
		act, reason := syncer.Resolve(it, o)
		r := result{Project: it.Project, Name: it.Name, Path: it.Path, Action: act, Reason: reason}
		if !dryRun {
			if err := syncer.Apply(c, st, it, act, message); err != nil {
				var ce *client.ConflictError
				if errors.As(err, &ce) {
					r.Action, r.Reason = syncer.Conflict, "remote changed during sync"
				} else {
					r.Error = err.Error()
				}
			}
		}
		if r.Action == syncer.Conflict || r.Error != "" {
			failed++
		}
		if r.Action == syncer.OK {
			upToDate++
		}
		results = append(results, r)
	}
	if !dryRun {
		if err := state.SaveState(st); err != nil {
			return err
		}
	}
	if jsonOut {
		if err := printJSON(results); err != nil {
			return err
		}
	} else {
		table(func(w io.Writer) {
			for _, r := range results {
				if r.Action == syncer.OK {
					continue
				}
				reason := r.Reason
				if r.Error != "" {
					reason = "error: " + r.Error
				}
				fmt.Fprintf(w, "%s\t%s/%s\t%s\n", r.Action, r.Project, r.Name, describe(r.Path, reason))
			}
		})
		fmt.Printf("%d up to date\n", upToDate)
	}
	if failed > 0 {
		return fmt.Errorf("%d file(s) need attention", failed)
	}
	return nil
}

func syncCmd() *cobra.Command {
	var ours, theirs bool
	var message string
	cmd := &cobra.Command{
		Use:   "sync [project[/file]...]",
		Short: "Pull remote changes and push local changes",
		RunE: func(cmd *cobra.Command, args []string) error {
			if ours && theirs {
				return errors.New("--ours and --theirs are exclusive")
			}
			cfg, st, c, err := session()
			if err != nil {
				return err
			}
			ts, err := targetsFor(cfg, args)
			if err != nil {
				return err
			}
			o := syncer.Options{Pull: true, Push: true}
			if ours {
				o.Prefer = syncer.PreferLocal
			} else if theirs {
				o.Prefer = syncer.PreferRemote
			}
			return run(cfg, st, c, ts, o, message)
		},
	}
	cmd.Flags().BoolVar(&ours, "ours", false, "resolve conflicts with the local version")
	cmd.Flags().BoolVar(&theirs, "theirs", false, "resolve conflicts with the remote version")
	cmd.Flags().StringVarP(&message, "message", "m", "", "version message for pushed files")
	return cmd
}

func pullCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "pull <project> [file...]",
		Short: "Pull remote changes; the first pull subscribes the project",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, st, c, err := session()
			if err != nil {
				return err
			}
			o := syncer.Options{Pull: true}
			if force {
				o.Prefer = syncer.PreferRemote
			}
			if !dryRun && !cfg.Subscribed(args[0]) {
				if _, err := c.Project(args[0]); err != nil {
					return fmt.Errorf("project %q: %w", args[0], err)
				}
				cfg.Subscribe(args[0])
				if err := state.SaveConfig(cfg); err != nil {
					return err
				}
			}
			return run(cfg, st, c, projectTargets(args), o, "")
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "overwrite local changes and conflicts")
	return cmd
}

func pushCmd() *cobra.Command {
	var force bool
	var message string
	cmd := &cobra.Command{
		Use:   "push <project> [file...]",
		Short: "Push local changes",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, st, c, err := session()
			if err != nil {
				return err
			}
			o := syncer.Options{Push: true}
			if force {
				o.Prefer = syncer.PreferLocal
			}
			return run(cfg, st, c, projectTargets(args), o, message)
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "overwrite remote changes and conflicts")
	cmd.Flags().StringVarP(&message, "message", "m", "", "version message")
	return cmd
}

func diffCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "diff [project[/file]...]",
		Short: "Show differences between remote head and local files",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, st, c, err := session()
			if err != nil {
				return err
			}
			ts, err := targetsFor(cfg, args)
			if err != nil {
				return err
			}
			items, err := syncer.Plan(c, cfg, st, ts)
			if err != nil {
				return err
			}
			for _, it := range items {
				if it.Status == syncer.OK || it.Status == syncer.Skip || it.Status == syncer.Empty {
					continue
				}
				d, err := syncer.Diff(c, it)
				if err != nil {
					return err
				}
				fmt.Print(d)
			}
			return nil
		},
	}
}
