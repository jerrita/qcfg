// Package client is the qcfg API client.
package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jerrita/qcfg/internal/crypto"
	"github.com/jerrita/qcfg/internal/model"
)

var ErrNotFound = errors.New("not found")

// ConflictError is returned when the server head differs from the base rev.
type ConflictError struct{ HeadRev int64 }

func (e *ConflictError) Error() string {
	return fmt.Sprintf("conflict: remote head is rev %d", e.HeadRev)
}

type Client struct {
	base  string
	token string
	http  *http.Client
}

func New(server, token string) *Client {
	return &Client{
		base:  strings.TrimRight(server, "/") + "/api/v1",
		token: token,
		http:  &http.Client{Timeout: 60 * time.Second},
	}
}

func esc(s string) string { return url.PathEscape(s) }

func fileURL(p, f string) string { return "/projects/" + esc(p) + "/files/" + esc(f) }

func (c *Client) do(method, path string, body io.Reader, hdr map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 300 {
		return resp, nil
	}
	defer resp.Body.Close()
	var e model.Error
	_ = json.NewDecoder(resp.Body).Decode(&e)
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, ErrNotFound
	case resp.StatusCode == http.StatusConflict && e.HeadRev > 0:
		return nil, &ConflictError{HeadRev: e.HeadRev}
	case e.Error != "":
		return nil, fmt.Errorf("server: %s", e.Error)
	default:
		return nil, fmt.Errorf("server: %s", resp.Status)
	}
}

func (c *Client) json(method, path string, in, out any) error {
	var body io.Reader
	hdr := map[string]string{}
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
		hdr["Content-Type"] = "application/json"
	}
	resp, err := c.do(method, path, body, hdr)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) WhoAmI() (model.WhoAmI, error) {
	var w model.WhoAmI
	return w, c.json("GET", "/whoami", nil, &w)
}

func (c *Client) Projects() ([]model.Project, error) {
	var ps []model.Project
	return ps, c.json("GET", "/projects", nil, &ps)
}

func (c *Client) Project(name string) (model.Project, error) {
	var p model.Project
	return p, c.json("GET", "/projects/"+esc(name), nil, &p)
}

func (c *Client) CreateProject(name string) error {
	return c.json("POST", "/projects", model.Project{Name: name}, nil)
}

func (c *Client) CreateFile(project string, f model.File) (model.File, error) {
	var out model.File
	return out, c.json("POST", "/projects/"+esc(project)+"/files", f, &out)
}

func (c *Client) DeleteFile(project, name string) error {
	return c.json("DELETE", fileURL(project, name), nil, nil)
}

// Get downloads rev (0 for head) and verifies its checksum.
func (c *Client) Get(project, name string, rev int64) ([]byte, int64, error) {
	path := fileURL(project, name) + "/raw"
	if rev > 0 {
		path += "?rev=" + strconv.FormatInt(rev, 10)
	}
	resp, err := c.do("GET", path, nil, nil)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}
	if sum := resp.Header.Get("X-Qcfg-Sha256"); sum != crypto.Sha256Hex(data) {
		return nil, 0, fmt.Errorf("%s/%s: checksum mismatch", project, name)
	}
	got, _ := strconv.ParseInt(resp.Header.Get("X-Qcfg-Rev"), 10, 64)
	return data, got, nil
}

// Put uploads content on top of baseRev.
func (c *Client) Put(project, name string, baseRev int64, data []byte, message string) (model.Version, error) {
	var v model.Version
	path := fileURL(project, name) + "/raw"
	if message != "" {
		path += "?message=" + url.QueryEscape(message)
	}
	resp, err := c.do("PUT", path, bytes.NewReader(data), map[string]string{
		"If-Match":     strconv.FormatInt(baseRev, 10),
		"Content-Type": "application/octet-stream",
	})
	if err != nil {
		return v, err
	}
	defer resp.Body.Close()
	return v, json.NewDecoder(resp.Body).Decode(&v)
}

func (c *Client) Versions(project, name string) ([]model.Version, error) {
	var vs []model.Version
	return vs, c.json("GET", fileURL(project, name)+"/versions", nil, &vs)
}

func (c *Client) Restore(project, name string, rev int64) (model.Version, error) {
	var v model.Version
	return v, c.json("POST", fileURL(project, name)+"/restore", model.RestoreRequest{Rev: rev}, &v)
}
