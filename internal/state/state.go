// Package state reads and writes the client config and sync state.
package state

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"

	"github.com/BurntSushi/toml"
)

type ProjectConfig struct {
	Exclude []string `toml:"exclude,omitempty"`
}

type Config struct {
	Server   string                   `toml:"server"`
	Token    string                   `toml:"token"`
	Device   string                   `toml:"device"`
	Projects map[string]ProjectConfig `toml:"projects"`
}

// Excluded reports whether file is excluded from project on this machine.
func (c *Config) Excluded(project, file string) bool {
	return slices.Contains(c.Projects[project].Exclude, file)
}

func (c *Config) Subscribed(project string) bool {
	_, ok := c.Projects[project]
	return ok
}

func (c *Config) Subscribe(project string) {
	if c.Projects == nil {
		c.Projects = map[string]ProjectConfig{}
	}
	if _, ok := c.Projects[project]; !ok {
		c.Projects[project] = ProjectConfig{}
	}
}

// Base is the last synced version of a file.
type Base struct {
	Rev    int64  `json:"rev"`
	Sha256 string `json:"sha256"`
	Path   string `json:"path"`
}

// State maps "project/file" to its base.
type State map[string]Base

func Key(project, file string) string { return project + "/" + file }

func ConfigDir() (string, error) {
	d, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "qcfg"), nil
}

// StateDir is $XDG_STATE_HOME/qcfg (~/.local/state/qcfg) or %LOCALAPPDATA%\qcfg.
func StateDir() (string, error) {
	if runtime.GOOS == "windows" {
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			return filepath.Join(d, "qcfg"), nil
		}
	}
	if d := os.Getenv("XDG_STATE_HOME"); d != "" {
		return filepath.Join(d, "qcfg"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "state", "qcfg"), nil
}

func configPath() (string, error) {
	d, err := ConfigDir()
	return filepath.Join(d, "config.toml"), err
}

func statePath() (string, error) {
	d, err := StateDir()
	return filepath.Join(d, "state.json"), err
}

// LoadConfig returns an empty config when the file does not exist.
func LoadConfig() (*Config, error) {
	c := &Config{Projects: map[string]ProjectConfig{}}
	p, err := configPath()
	if err != nil {
		return nil, err
	}
	if _, err := toml.DecodeFile(p, c); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if c.Projects == nil {
		c.Projects = map[string]ProjectConfig{}
	}
	return c, nil
}

func SaveConfig(c *Config) error {
	p, err := configPath()
	if err != nil {
		return err
	}
	return writeFile(p, func(f *os.File) error { return toml.NewEncoder(f).Encode(c) })
}

func LoadState() (State, error) {
	s := State{}
	p, err := statePath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	return s, json.Unmarshal(b, &s)
}

func SaveState(s State) error {
	p, err := statePath()
	if err != nil {
		return err
	}
	return writeFile(p, func(f *os.File) error {
		e := json.NewEncoder(f)
		e.SetIndent("", "  ")
		return e.Encode(s)
	})
}

func writeFile(path string, enc func(*os.File) error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := enc(tmp); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil && runtime.GOOS != "windows" {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
