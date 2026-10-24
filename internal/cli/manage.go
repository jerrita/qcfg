package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jerrita/qcfg/internal/client"
	"github.com/jerrita/qcfg/internal/model"
	"github.com/jerrita/qcfg/internal/pathx"
	"github.com/jerrita/qcfg/internal/state"
)

const timeFmt = "2006-01-02 15:04"

func lsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls [project]",
		Short: "List projects, or files of a project",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, _, c, err := session()
			if err != nil {
				return err
			}
			if len(args) == 0 {
				ps, err := c.Projects()
				if err != nil {
					return err
				}
				if jsonOut {
					return printJSON(ps)
				}
				table(func(w io.Writer) {
					fmt.Fprintln(w, "\tPROJECT\tFILES\tUPDATED\tDESCRIPTION")
					for _, p := range ps {
						mark := ""
						if cfg.Subscribed(p.Name) {
							mark = "*"
						}
						fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\n", mark, p.Name, p.FileCount, p.UpdatedAt.Format(timeFmt), p.Description)
					}
				})
				return nil
			}
			p, err := c.Project(args[0])
			if err != nil {
				return fmt.Errorf("project %q: %w", args[0], err)
			}
			if jsonOut {
				return printJSON(p)
			}
			table(func(w io.Writer) {
				fmt.Fprintln(w, "FILE\tREV\tLOCAL PATH")
				for _, f := range p.Files {
					local, ok, err := pathx.Resolve(f, runtime.GOOS)
					switch {
					case err != nil:
						local = "(error: " + err.Error() + ")"
					case !ok:
						local = "(not on " + runtime.GOOS + ")"
					case cfg.Excluded(p.Name, f.Name):
						local = pathx.Contract(local) + "  (excluded)"
					default:
						local = pathx.Contract(local)
					}
					fmt.Fprintf(w, "%s\t%d\t%s\n", f.Name, f.HeadRev, local)
				}
			})
			return nil
		},
	}
}

func addCmd() *cobra.Command {
	var name, mode, message string
	var osPaths, platforms []string
	cmd := &cobra.Command{
		Use:   "add <project> <path>",
		Short: "Track a local file in a project and push it",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, st, c, err := session()
			if err != nil {
				return err
			}
			project := args[0]
			abs, err := filepath.Abs(args[1])
			if err != nil {
				return err
			}
			fi, err := os.Stat(abs)
			if err != nil {
				return err
			}
			if !fi.Mode().IsRegular() {
				return fmt.Errorf("%s is not a regular file", abs)
			}
			data, err := os.ReadFile(abs)
			if err != nil {
				return err
			}
			f := model.File{Name: name, Path: pathx.Contract(abs), Platforms: platforms, Mode: mode}
			if f.Name == "" {
				f.Name = filepath.Base(abs)
			}
			if f.Mode == "" && runtime.GOOS != "windows" {
				f.Mode = fmt.Sprintf("%04o", fi.Mode().Perm())
			}
			for _, kv := range osPaths {
				k, v, ok := strings.Cut(kv, "=")
				if !ok {
					return fmt.Errorf("--os expects OS=PATH, got %q", kv)
				}
				if f.Paths == nil {
					f.Paths = map[string]string{}
				}
				f.Paths[k] = v
			}
			if err := model.ValidateFile(f); err != nil {
				return err
			}
			if dryRun {
				fmt.Printf("would add %s/%s -> %s\n", project, f.Name, f.Path)
				return nil
			}
			created, err := c.CreateFile(project, f)
			if errors.Is(err, client.ErrNotFound) {
				if err := c.CreateProject(project); err != nil {
					return err
				}
				created, err = c.CreateFile(project, f)
			}
			if err != nil {
				return err
			}
			v, err := c.Put(project, f.Name, created.HeadRev, data, message)
			if err != nil {
				if created.HeadRev == 0 {
					_ = c.DeleteFile(project, f.Name)
				}
				return err
			}
			cfg.Subscribe(project)
			if err := state.SaveConfig(cfg); err != nil {
				return err
			}
			st[state.Key(project, f.Name)] = state.Base{Rev: v.Rev, Sha256: v.Sha256, Path: abs}
			if err := state.SaveState(st); err != nil {
				return err
			}
			fmt.Printf("added %s/%s (rev %d) -> %s\n", project, f.Name, v.Rev, f.Path)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "name", "", "file name in the project (default: basename)")
	cmd.Flags().StringArrayVar(&osPaths, "os", nil, "per-OS path override OS=PATH (repeatable)")
	cmd.Flags().StringSliceVar(&platforms, "platforms", nil, "only sync on these OSes (comma separated)")
	cmd.Flags().StringVar(&mode, "mode", "", "file mode, octal (default: current mode)")
	cmd.Flags().StringVarP(&message, "message", "m", "", "version message")
	return cmd
}

func rmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm <project>/<file>",
		Short: "Stop tracking a file on the server; the local file is kept",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, st, c, err := session()
			if err != nil {
				return err
			}
			p, f, err := splitFileArg(args[0])
			if err != nil {
				return err
			}
			if dryRun {
				fmt.Printf("would remove %s/%s\n", p, f)
				return nil
			}
			if err := c.DeleteFile(p, f); err != nil {
				return err
			}
			delete(st, state.Key(p, f))
			return state.SaveState(st)
		},
	}
}

func unsubscribeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unsubscribe <project>",
		Short: "Stop syncing a project on this machine; local files are kept",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := state.LoadConfig()
			if err != nil {
				return err
			}
			st, err := state.LoadState()
			if err != nil {
				return err
			}
			if !cfg.Subscribed(args[0]) {
				return fmt.Errorf("project %q is not subscribed", args[0])
			}
			if dryRun {
				return nil
			}
			delete(cfg.Projects, args[0])
			for k := range st {
				if strings.HasPrefix(k, args[0]+"/") {
					delete(st, k)
				}
			}
			if err := state.SaveConfig(cfg); err != nil {
				return err
			}
			return state.SaveState(st)
		},
	}
}

func logCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "log <project>/<file>",
		Short: "Show version history of a file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, _, c, err := session()
			if err != nil {
				return err
			}
			p, f, err := splitFileArg(args[0])
			if err != nil {
				return err
			}
			vs, err := c.Versions(p, f)
			if err != nil {
				return err
			}
			if jsonOut {
				return printJSON(vs)
			}
			table(func(w io.Writer) {
				fmt.Fprintln(w, "REV\tTIME\tDEVICE\tSIZE\tMESSAGE")
				for _, v := range vs {
					fmt.Fprintf(w, "%d\t%s\t%s\t%d\t%s\n", v.Rev, v.CreatedAt.Format(timeFmt), v.Device, v.Size, v.Message)
				}
			})
			return nil
		},
	}
}

func restoreCmd() *cobra.Command {
	var rev int64
	cmd := &cobra.Command{
		Use:   "restore <project>/<file> --rev N",
		Short: "Make a previous version the new head",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, _, c, err := session()
			if err != nil {
				return err
			}
			p, f, err := splitFileArg(args[0])
			if err != nil {
				return err
			}
			if dryRun {
				fmt.Printf("would restore %s/%s to rev %d\n", p, f, rev)
				return nil
			}
			v, err := c.Restore(p, f, rev)
			if err != nil {
				return err
			}
			fmt.Printf("restored %s/%s rev %d as rev %d; run `qcfg sync` to apply locally\n", p, f, rev, v.Rev)
			return nil
		},
	}
	cmd.Flags().Int64Var(&rev, "rev", 0, "revision to restore")
	_ = cmd.MarkFlagRequired("rev")
	return cmd
}
