// Package syncer compares local, base and remote file states and applies
// pulls and pushes.
package syncer

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pmezard/go-difflib/difflib"

	"github.com/jerrita/qcfg/internal/client"
	"github.com/jerrita/qcfg/internal/crypto"
	"github.com/jerrita/qcfg/internal/model"
	"github.com/jerrita/qcfg/internal/pathx"
	"github.com/jerrita/qcfg/internal/state"
)

type Action string

const (
	OK       Action = "ok"
	Pull     Action = "pull"
	Push     Action = "push"
	Conflict Action = "conflict"
	Skip     Action = "skip"  // not synced on this machine
	Empty    Action = "empty" // no content on either side
)

// Item is the sync status of one file.
type Item struct {
	Project  string      `json:"project"`
	Name     string      `json:"name"`
	Path     string      `json:"path,omitempty"`
	Status   Action      `json:"status"`
	Reason   string      `json:"reason,omitempty"`
	LocalSha string      `json:"local_sha256,omitempty"`
	File     model.File  `json:"-"`
	Base     *state.Base `json:"-"`
}

func (it Item) Key() string { return state.Key(it.Project, it.Name) }

// Target selects a whole project or a single file.
type Target struct {
	Project string
	File    string
}

// ParseTarget parses "project" or "project/file".
func ParseTarget(s string) Target {
	p, f, _ := strings.Cut(s, "/")
	return Target{Project: p, File: f}
}

// Decide classifies a file from its local, base and remote checksums.
// Empty local means the file is missing; empty remote means no content yet.
func Decide(local string, base *state.Base, remote string) Action {
	switch {
	case remote == "" && local == "":
		return Empty
	case remote == "":
		return Push
	case local == "":
		return Pull
	case local == remote:
		return OK
	case base == nil:
		return Conflict
	case local == base.Sha256:
		return Pull
	case remote == base.Sha256:
		return Push
	default:
		return Conflict
	}
}

// Plan computes items for the targets. Files of fully targeted projects that
// no longer exist remotely are dropped from st.
func Plan(c *client.Client, cfg *state.Config, st state.State, targets []Target) ([]Item, error) {
	var items []Item
	for _, t := range targets {
		p, err := c.Project(t.Project)
		if errors.Is(err, client.ErrNotFound) {
			return nil, fmt.Errorf("project %q not found", t.Project)
		}
		if err != nil {
			return nil, err
		}
		found := false
		live := map[string]bool{}
		for _, f := range p.Files {
			live[f.Name] = true
			if t.File != "" && f.Name != t.File {
				continue
			}
			found = true
			it, err := planFile(cfg, st, p.Name, f)
			if err != nil {
				return nil, err
			}
			items = append(items, it)
		}
		if t.File != "" && !found {
			return nil, fmt.Errorf("file %s/%s not found", t.Project, t.File)
		}
		if t.File == "" {
			for k := range st {
				if pp, f, _ := strings.Cut(k, "/"); pp == p.Name && !live[f] {
					delete(st, k)
				}
			}
		}
	}
	return items, nil
}

func planFile(cfg *state.Config, st state.State, project string, f model.File) (Item, error) {
	it := Item{Project: project, Name: f.Name, File: f}
	if cfg.Excluded(project, f.Name) {
		it.Status, it.Reason = Skip, "excluded"
		return it, nil
	}
	path, ok, err := pathx.Resolve(f, runtime.GOOS)
	if err != nil {
		return it, fmt.Errorf("%s: %w", it.Key(), err)
	}
	if !ok {
		it.Status, it.Reason = Skip, "not on "+runtime.GOOS
		return it, nil
	}
	it.Path = path
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		it.LocalSha = crypto.Sha256Hex(data)
	case !errors.Is(err, fs.ErrNotExist):
		return it, err
	}
	if b, ok := st[it.Key()]; ok {
		it.Base = &b
	}
	it.Status = Decide(it.LocalSha, it.Base, f.Sha256)
	return it, nil
}

// Options controls which directions may be applied.
type Options struct {
	Pull, Push bool
	// Prefer resolves conflicts and held changes: "local" or "remote".
	Prefer string
}

const (
	PreferLocal  = "local"
	PreferRemote = "remote"
)

// Resolve returns the action to perform for it under o. OK, Skip and Empty
// pass through; an action that is not allowed returns Skip with a reason.
func Resolve(it Item, o Options) (Action, string) {
	switch it.Status {
	case Conflict:
		switch {
		case o.Prefer == PreferLocal && o.Push:
			return Push, ""
		case o.Prefer == PreferRemote && o.Pull:
			return Pull, ""
		}
		return Conflict, "local and remote both changed"
	case Push:
		if o.Push {
			return Push, ""
		}
		if o.Prefer == PreferRemote && o.Pull && it.File.HeadRev > 0 {
			return Pull, ""
		}
		return Skip, "local changes not pushed"
	case Pull:
		if o.Pull {
			return Pull, ""
		}
		if o.Prefer == PreferLocal && o.Push && it.LocalSha != "" {
			return Push, ""
		}
		return Skip, "remote changes not pulled"
	}
	return it.Status, it.Reason
}

// Apply performs act for it and updates st.
func Apply(c *client.Client, st state.State, it Item, act Action, message string) error {
	switch act {
	case OK:
		if it.Base == nil || it.Base.Sha256 != it.LocalSha || it.Base.Rev != it.File.HeadRev {
			st[it.Key()] = state.Base{Rev: it.File.HeadRev, Sha256: it.LocalSha, Path: it.Path}
		}
		return nil
	case Pull:
		data, rev, err := c.Get(it.Project, it.Name, 0)
		if err != nil {
			return err
		}
		if err := backup(it); err != nil {
			return fmt.Errorf("backup: %w", err)
		}
		if err := WriteAtomic(it.Path, data, it.File.Mode); err != nil {
			return err
		}
		st[it.Key()] = state.Base{Rev: rev, Sha256: crypto.Sha256Hex(data), Path: it.Path}
		return nil
	case Push:
		data, err := os.ReadFile(it.Path)
		if err != nil {
			return err
		}
		v, err := c.Put(it.Project, it.Name, it.File.HeadRev, data, message)
		if err != nil {
			return err
		}
		st[it.Key()] = state.Base{Rev: v.Rev, Sha256: v.Sha256, Path: it.Path}
		return nil
	}
	return nil
}

// WriteAtomic writes data to path through a temp file in the same directory.
// mode is octal; empty keeps the existing mode or uses 0644.
func WriteAtomic(path string, data []byte, mode string) error {
	perm := fs.FileMode(0o644)
	if fi, err := os.Stat(path); err == nil {
		perm = fi.Mode().Perm()
	}
	if mode != "" {
		m, err := strconv.ParseUint(mode, 8, 32)
		if err != nil {
			return fmt.Errorf("invalid mode %q", mode)
		}
		perm = fs.FileMode(m)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".qcfg-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if runtime.GOOS != "windows" {
		if err := tmp.Chmod(perm); err != nil {
			tmp.Close()
			return err
		}
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

const keepBackups = 10

func backup(it Item) error {
	data, err := os.ReadFile(it.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	sd, err := state.StateDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(sd, "backup", it.Project)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	name := it.Name + "." + time.Now().Format("20060102T150405.000")
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
		return err
	}
	old, err := filepath.Glob(filepath.Join(dir, it.Name+".*"))
	if err != nil {
		return err
	}
	sort.Strings(old)
	for len(old) > keepBackups {
		_ = os.Remove(old[0])
		old = old[1:]
	}
	return nil
}

// Diff returns a unified diff from the remote head to the local file.
func Diff(c *client.Client, it Item) (string, error) {
	var remote, local []byte
	var err error
	if it.File.HeadRev > 0 {
		if remote, _, err = c.Get(it.Project, it.Name, 0); err != nil {
			return "", err
		}
	}
	if it.LocalSha != "" {
		if local, err = os.ReadFile(it.Path); err != nil {
			return "", err
		}
	}
	return UnifiedDiff(remote, local, fmt.Sprintf("remote/%s@%d", it.Key(), it.File.HeadRev), "local/"+it.Key())
}

// UnifiedDiff diffs two contents; binary contents yield a one-line notice.
func UnifiedDiff(a, b []byte, nameA, nameB string) (string, error) {
	if IsBinary(a) || IsBinary(b) {
		if string(a) == string(b) {
			return "", nil
		}
		return fmt.Sprintf("Binary files %s and %s differ\n", nameA, nameB), nil
	}
	return difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A: splitLines(a), B: splitLines(b),
		FromFile: nameA, ToFile: nameB, Context: 3,
	})
}

func splitLines(b []byte) []string {
	lines := strings.SplitAfter(string(b), "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	} else {
		lines[len(lines)-1] += "\n\\ No newline at end of file\n"
	}
	return lines
}

// IsBinary reports whether data looks like binary content.
func IsBinary(data []byte) bool {
	n := min(len(data), 8000)
	for _, c := range data[:n] {
		if c == 0 {
			return true
		}
	}
	return false
}
