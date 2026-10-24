// Package server implements the REST API and mounts the WebUI.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/jerrita/qcfg/internal/model"
	"github.com/jerrita/qcfg/internal/store"
)

type Options struct {
	MaxFileSize int64
}

type Server struct {
	store *store.Store
	opts  Options
}

type ctxKey struct{}

// New returns the API handler; web is mounted at "/".
func New(st *store.Store, opts Options, web http.Handler) http.Handler {
	s := &Server{store: st, opts: opts}
	api := http.NewServeMux()
	api.HandleFunc("GET /api/v1/whoami", s.whoami)
	api.HandleFunc("GET /api/v1/projects", s.listProjects)
	api.HandleFunc("POST /api/v1/projects", s.createProject)
	api.HandleFunc("GET /api/v1/projects/{p}", s.scoped(s.getProject))
	api.HandleFunc("PATCH /api/v1/projects/{p}", s.scoped(s.updateProject))
	api.HandleFunc("DELETE /api/v1/projects/{p}", s.scoped(s.deleteProject))
	api.HandleFunc("POST /api/v1/projects/{p}/files", s.scoped(s.createFile))
	api.HandleFunc("PATCH /api/v1/projects/{p}/files/{f}", s.scoped(s.updateFile))
	api.HandleFunc("DELETE /api/v1/projects/{p}/files/{f}", s.scoped(s.deleteFile))
	api.HandleFunc("GET /api/v1/projects/{p}/files/{f}/raw", s.scoped(s.getRaw))
	api.HandleFunc("PUT /api/v1/projects/{p}/files/{f}/raw", s.scoped(s.putRaw))
	api.HandleFunc("GET /api/v1/projects/{p}/files/{f}/versions", s.scoped(s.versions))
	api.HandleFunc("POST /api/v1/projects/{p}/files/{f}/restore", s.scoped(s.restore))

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/device/code", s.deviceCode)
	mux.HandleFunc("POST /api/v1/device/token", s.deviceToken)
	mux.Handle("/api/", s.auth(api))
	mux.Handle("/", web)
	return mux
}

// ClientIP returns the remote IP of r.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok {
			writeErr(w, http.StatusUnauthorized, "missing bearer token")
			return
		}
		p, err := s.store.Authenticate(token, ClientIP(r))
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "invalid token")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, p)))
	})
}

func principal(r *http.Request) *store.Principal {
	return r.Context().Value(ctxKey{}).(*store.Principal)
}

func device(r *http.Request) string { return principal(r).Name }

// scoped rejects requests for projects the device may not access.
func (s *Server) scoped(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !principal(r).CanAccess(r.PathValue("p")) {
			writeErr(w, http.StatusNotFound, "not found")
			return
		}
		next(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, model.Error{Error: msg})
}

func storeErr(w http.ResponseWriter, err error) {
	var ce *store.ConflictError
	switch {
	case errors.As(err, &ce):
		writeJSON(w, http.StatusConflict, model.Error{Error: err.Error(), HeadRev: ce.HeadRev})
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not found")
	case errors.Is(err, store.ErrExists):
		writeErr(w, http.StatusConflict, "already exists")
	case errors.Is(err, store.ErrLimit):
		writeErr(w, http.StatusTooManyRequests, "too many requests")
	default:
		log.Printf("error: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
	}
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return false
	}
	return true
}

func (s *Server) deviceCode(w http.ResponseWriter, r *http.Request) {
	var req model.DeviceCodeRequest
	if !readJSON(w, r, &req) {
		return
	}
	if !model.ValidDeviceName(req.Name) {
		writeErr(w, http.StatusBadRequest, "invalid device name")
		return
	}
	code, user, err := s.store.CreateDeviceRequest(req.Name, ClientIP(r))
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, model.DeviceCode{
		DeviceCode: code,
		UserCode:   user,
		ExpiresIn:  int(store.DeviceCodeTTL.Seconds()),
		Interval:   5,
	})
}

func (s *Server) deviceToken(w http.ResponseWriter, r *http.Request) {
	var req model.DeviceTokenRequest
	if !readJSON(w, r, &req) {
		return
	}
	token, name, err := s.store.ClaimDeviceToken(req.DeviceCode)
	switch {
	case errors.Is(err, store.ErrPending):
		writeErr(w, http.StatusBadRequest, model.AuthPending)
	case errors.Is(err, store.ErrDenied):
		writeErr(w, http.StatusBadRequest, model.AuthDenied)
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusBadRequest, model.AuthExpired)
	case err != nil:
		storeErr(w, err)
	default:
		writeJSON(w, http.StatusOK, model.DeviceToken{Token: token, Device: name})
	}
}

func (s *Server) whoami(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, model.WhoAmI{Device: device(r)})
}

func (s *Server) listProjects(w http.ResponseWriter, r *http.Request) {
	ps, err := s.store.ListProjects()
	if err != nil {
		storeErr(w, err)
		return
	}
	pr := principal(r)
	ps = slices.DeleteFunc(ps, func(p model.Project) bool { return !pr.CanAccess(p.Name) })
	writeJSON(w, http.StatusOK, ps)
}

func (s *Server) createProject(w http.ResponseWriter, r *http.Request) {
	var p model.Project
	if !readJSON(w, r, &p) {
		return
	}
	if !model.ValidName(p.Name) {
		writeErr(w, http.StatusBadRequest, "invalid project name")
		return
	}
	if err := s.store.CreateProject(p.Name, p.Description); err != nil {
		storeErr(w, err)
		return
	}
	if pr := principal(r); !pr.AllProjects {
		if err := s.store.GrantProject(pr.ID, p.Name); err != nil {
			storeErr(w, err)
			return
		}
	}
	writeJSON(w, http.StatusCreated, p)
}

func (s *Server) getProject(w http.ResponseWriter, r *http.Request) {
	p, err := s.store.GetProject(r.PathValue("p"))
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (s *Server) updateProject(w http.ResponseWriter, r *http.Request) {
	cur, err := s.store.GetProject(r.PathValue("p"))
	if err != nil {
		storeErr(w, err)
		return
	}
	req := struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
	}{}
	if !readJSON(w, r, &req) {
		return
	}
	if req.Name != nil {
		cur.Name = *req.Name
	}
	if req.Description != nil {
		cur.Description = *req.Description
	}
	if !model.ValidName(cur.Name) {
		writeErr(w, http.StatusBadRequest, "invalid project name")
		return
	}
	if err := s.store.UpdateProject(r.PathValue("p"), cur.Name, cur.Description); err != nil {
		storeErr(w, err)
		return
	}
	cur.Files = nil
	writeJSON(w, http.StatusOK, cur)
}

func (s *Server) deleteProject(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteProject(r.PathValue("p")); err != nil {
		storeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) createFile(w http.ResponseWriter, r *http.Request) {
	var f model.File
	if !readJSON(w, r, &f) {
		return
	}
	if err := model.ValidateFile(f); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.CreateFile(r.PathValue("p"), f); err != nil {
		storeErr(w, err)
		return
	}
	s.writeFile(w, r, f.Name, http.StatusCreated)
}

func (s *Server) writeFile(w http.ResponseWriter, r *http.Request, name string, code int) {
	f, err := s.store.GetFile(r.PathValue("p"), name)
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, code, f)
}

func (s *Server) updateFile(w http.ResponseWriter, r *http.Request) {
	cur, err := s.store.GetFile(r.PathValue("p"), r.PathValue("f"))
	if err != nil {
		storeErr(w, err)
		return
	}
	req := struct {
		Path      *string            `json:"path"`
		Paths     *map[string]string `json:"paths"`
		Platforms *[]string          `json:"platforms"`
		Mode      *string            `json:"mode"`
	}{}
	if !readJSON(w, r, &req) {
		return
	}
	if req.Path != nil {
		cur.Path = *req.Path
	}
	if req.Paths != nil {
		cur.Paths = *req.Paths
	}
	if req.Platforms != nil {
		cur.Platforms = *req.Platforms
	}
	if req.Mode != nil {
		cur.Mode = *req.Mode
	}
	if err := model.ValidateFile(cur); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.store.UpdateFile(r.PathValue("p"), cur.Name, cur); err != nil {
		storeErr(w, err)
		return
	}
	s.writeFile(w, r, cur.Name, http.StatusOK)
}

func (s *Server) deleteFile(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteFile(r.PathValue("p"), r.PathValue("f")); err != nil {
		storeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) getRaw(w http.ResponseWriter, r *http.Request) {
	var rev int64
	if q := r.URL.Query().Get("rev"); q != "" {
		var err error
		if rev, err = strconv.ParseInt(q, 10, 64); err != nil || rev < 1 {
			writeErr(w, http.StatusBadRequest, "invalid rev")
			return
		}
	}
	data, v, err := s.store.Content(r.PathValue("p"), r.PathValue("f"), rev)
	if err != nil {
		storeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Qcfg-Rev", strconv.FormatInt(v.Rev, 10))
	w.Header().Set("X-Qcfg-Sha256", v.Sha256)
	_, _ = w.Write(data)
}

func (s *Server) putRaw(w http.ResponseWriter, r *http.Request) {
	base, err := strconv.ParseInt(r.Header.Get("If-Match"), 10, 64)
	if err != nil || base < 0 {
		writeErr(w, http.StatusPreconditionRequired, "If-Match header with base rev required")
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, s.opts.MaxFileSize+1))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if int64(len(data)) > s.opts.MaxFileSize {
		writeErr(w, http.StatusRequestEntityTooLarge, "file too large")
		return
	}
	v, created, err := s.store.Put(r.PathValue("p"), r.PathValue("f"), base, data, device(r), r.URL.Query().Get("message"))
	if err != nil {
		storeErr(w, err)
		return
	}
	code := http.StatusOK
	if created {
		code = http.StatusCreated
	}
	writeJSON(w, code, v)
}

func (s *Server) versions(w http.ResponseWriter, r *http.Request) {
	vs, err := s.store.Versions(r.PathValue("p"), r.PathValue("f"))
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, vs)
}

func (s *Server) restore(w http.ResponseWriter, r *http.Request) {
	var req model.RestoreRequest
	if !readJSON(w, r, &req) {
		return
	}
	v, err := s.store.Restore(r.PathValue("p"), r.PathValue("f"), req.Rev, device(r))
	if err != nil {
		storeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, v)
}
