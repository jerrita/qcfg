// Package pathx resolves file definitions to local paths.
package pathx

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/jerrita/qcfg/internal/model"
)

// Resolve returns the absolute local path of f for goos. ok is false when f
// is not synced on goos.
func Resolve(f model.File, goos string) (path string, ok bool, err error) {
	if len(f.Platforms) > 0 && !slices.Contains(f.Platforms, goos) {
		return "", false, nil
	}
	p := f.Path
	if o, has := f.Paths[goos]; has && o != "" {
		p = o
	}
	path, err = Expand(p)
	return path, err == nil, err
}

// Expand expands ~, $VAR, ${VAR} and %VAR% and returns a clean absolute path.
// $XDG_CONFIG_HOME, %APPDATA% and %LOCALAPPDATA% fall back to platform defaults.
func Expand(p string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		p = home + p[1:]
	}
	p = expandPercent(p, home)
	p = os.Expand(p, func(k string) string { return lookup(k, home) })
	p = filepath.Clean(filepath.FromSlash(p))
	return filepath.Abs(p)
}

func expandPercent(p, home string) string {
	var b strings.Builder
	for {
		i := strings.IndexByte(p, '%')
		if i < 0 {
			break
		}
		j := strings.IndexByte(p[i+1:], '%')
		if j < 0 {
			break
		}
		b.WriteString(p[:i])
		b.WriteString(lookup(p[i+1:i+1+j], home))
		p = p[i+2+j:]
	}
	b.WriteString(p)
	return b.String()
}

func lookup(k, home string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	switch strings.ToUpper(k) {
	case "HOME", "USERPROFILE":
		return home
	case "XDG_CONFIG_HOME":
		return filepath.Join(home, ".config")
	case "APPDATA":
		if runtime.GOOS == "windows" {
			return filepath.Join(home, "AppData", "Roaming")
		}
		return filepath.Join(home, ".config")
	case "LOCALAPPDATA":
		if runtime.GOOS == "windows" {
			return filepath.Join(home, "AppData", "Local")
		}
		return filepath.Join(home, ".local", "share")
	}
	return ""
}

// Contract turns an absolute path under the home directory into "~/..." form.
func Contract(abs string) string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.ToSlash(abs)
	}
	rel, err := filepath.Rel(home, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return filepath.ToSlash(abs)
	}
	if rel == "." {
		return "~"
	}
	return "~/" + filepath.ToSlash(rel)
}
