// Package model defines types shared by the API server and client.
package model

import (
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

type Project struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	FileCount   int       `json:"file_count"`
	UpdatedAt   time.Time `json:"updated_at"`
	Files       []File    `json:"files,omitempty"`
}

// File is a file definition plus its head version summary.
type File struct {
	Name      string            `json:"name"`
	Path      string            `json:"path"`
	Paths     map[string]string `json:"paths,omitempty"`
	Platforms []string          `json:"platforms,omitempty"`
	Mode      string            `json:"mode,omitempty"`
	HeadRev   int64             `json:"head_rev"`
	Sha256    string            `json:"sha256,omitempty"`
	Size      int64             `json:"size"`
	UpdatedBy string            `json:"updated_by,omitempty"`
	UpdatedAt time.Time         `json:"updated_at"`
}

type Version struct {
	Rev       int64     `json:"rev"`
	Sha256    string    `json:"sha256"`
	Size      int64     `json:"size"`
	Device    string    `json:"device"`
	Message   string    `json:"message,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type Device struct {
	Name        string    `json:"name"`
	CreatedAt   time.Time `json:"created_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
	LastIP      string    `json:"last_ip"`
	Revoked     bool      `json:"revoked"`
	AllProjects bool      `json:"all_projects"`
	Projects    []string  `json:"projects,omitempty"`
}

type DeviceCodeRequest struct {
	Name string `json:"name"`
}

type DeviceCode struct {
	DeviceCode string `json:"device_code"`
	UserCode   string `json:"user_code"`
	ExpiresIn  int    `json:"expires_in"`
	Interval   int    `json:"interval"`
}

type DeviceTokenRequest struct {
	DeviceCode string `json:"device_code"`
}

type DeviceToken struct {
	Token  string `json:"token"`
	Device string `json:"device"`
}

// Errors returned by the device token endpoint.
const (
	AuthPending = "authorization_pending"
	AuthDenied  = "access_denied"
	AuthExpired = "expired_token"
)

type WhoAmI struct {
	Device string `json:"device"`
}

type Error struct {
	Error   string `json:"error"`
	HeadRev int64  `json:"head_rev,omitempty"`
}

type RestoreRequest struct {
	Rev int64 `json:"rev"`
}

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// ValidName reports whether s is usable as a project or file name.
func ValidName(s string) bool { return nameRe.MatchString(s) }

// WebDevice is the device name recorded for changes made in the WebUI.
const WebDevice = "web"

// ValidDeviceName reports whether s is usable as a device name.
func ValidDeviceName(s string) bool { return ValidName(s) && s != WebDevice }

// Platforms supported in File.Paths and File.Platforms.
var Platforms = []string{"linux", "darwin", "windows", "freebsd"}

// ValidateFile checks a file definition.
func ValidateFile(f File) error {
	if !ValidName(f.Name) {
		return errors.New("invalid file name")
	}
	if strings.TrimSpace(f.Path) == "" {
		return errors.New("path is required")
	}
	for p := range f.Paths {
		if !slices.Contains(Platforms, p) {
			return errors.New("unknown platform in paths: " + p)
		}
	}
	for _, p := range f.Platforms {
		if !slices.Contains(Platforms, p) {
			return errors.New("unknown platform: " + p)
		}
	}
	if f.Mode != "" {
		if m, err := strconv.ParseUint(f.Mode, 8, 32); err != nil || m > 0o777 {
			return errors.New("mode must be octal like 0600")
		}
	}
	return nil
}
