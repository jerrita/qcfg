// Package web implements the server-rendered WebUI.
package web

import (
	"bytes"
	"context"
	"crypto/subtle"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/jerrita/qcfg/internal/crypto"
	"github.com/jerrita/qcfg/internal/model"
	"github.com/jerrita/qcfg/internal/server"
	"github.com/jerrita/qcfg/internal/store"
	"github.com/jerrita/qcfg/internal/syncer"
)

const (
	cookieName  = "qcfg_session"
	sessionTTL  = 7 * 24 * time.Hour
	maxFailures = 5
	failWindow  = 15 * time.Minute
	maxVerifies = 2 // concurrent password checks, each uses 64 MiB
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

type Options struct {
	MaxFileSize int64
	SecureOnly  bool // set Secure on cookies
}

type session struct {
	user    model.User
	csrf    string
	expires time.Time
}

type Web struct {
	store *store.Store
	opts  Options
	pages map[string]*template.Template

	mu       sync.Mutex
	sessions map[string]session
	failures map[string][]time.Time
	inFlight map[string]int
	verify   chan struct{}
}

var funcs = template.FuncMap{
	"time": func(t time.Time) string {
		if t.IsZero() {
			return "-"
		}
		return t.Format("2006-01-02 15:04")
	},
	"size": func(n int64) string {
		switch {
		case n < 1024:
			return fmt.Sprintf("%d B", n)
		case n < 1<<20:
			return fmt.Sprintf("%.1f KiB", float64(n)/1024)
		}
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	},
	"join": func(s []string) string { return strings.Join(s, ",") },
	"pathsText": func(m map[string]string) string {
		var b strings.Builder
		for _, p := range model.Platforms {
			if v, ok := m[p]; ok {
				fmt.Fprintf(&b, "%s=%s\n", p, v)
			}
		}
		return b.String()
	},
	"esc":   url.PathEscape,
	"dec":   func(n int64) int64 { return n - 1 },
	"short": func(s string) string { return s[:min(len(s), 12)] },
}

func New(st *store.Store, opts Options) http.Handler {
	w := &Web{
		store:    st,
		opts:     opts,
		pages:    map[string]*template.Template{},
		sessions: map[string]session{},
		failures: map[string][]time.Time{},
		inFlight: map[string]int{},
		verify:   make(chan struct{}, maxVerifies),
	}
	for _, p := range []string{"login", "register", "account", "users", "user", "projects", "project", "file", "history", "devices", "device", "tokens", "token", "activate"} {
		w.pages[p] = template.Must(template.New("layout.html").Funcs(funcs).
			ParseFS(templateFS, "templates/layout.html", "templates/scope.html", "templates/"+p+".html"))
	}

	static, _ := fs.Sub(staticFS, "static")
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /login", w.loginPage)
	mux.HandleFunc("POST /login", w.login)
	mux.HandleFunc("GET /register", w.registerPage)
	mux.HandleFunc("POST /register", w.register)

	auth := http.NewServeMux()
	auth.HandleFunc("POST /logout", w.logout)
	auth.HandleFunc("GET /account", w.accountPage)
	auth.HandleFunc("POST /account/password", w.changePassword)
	auth.HandleFunc("GET /users", w.admin(w.usersPage))
	auth.HandleFunc("POST /users", w.admin(w.createUser))
	auth.HandleFunc("GET /users/{u}", w.admin(w.userPage))
	auth.HandleFunc("POST /users/{u}/name", w.admin(w.setAdminName))
	auth.HandleFunc("POST /users/{u}/access", w.admin(w.setUserAccess))
	auth.HandleFunc("GET /{$}", w.projectsPage)
	auth.HandleFunc("POST /projects", w.admin(w.createProject))
	auth.HandleFunc("GET /p/{p}", w.scoped(w.projectPage))
	auth.HandleFunc("POST /p/{p}/delete", w.admin(w.deleteProject))
	auth.HandleFunc("POST /p/{p}/files", w.scoped(w.createFile))
	auth.HandleFunc("GET /p/{p}/f/{f}", w.scoped(w.filePage))
	auth.HandleFunc("POST /p/{p}/f/{f}/def", w.scoped(w.updateFile))
	auth.HandleFunc("POST /p/{p}/f/{f}/delete", w.scoped(w.deleteFile))
	auth.HandleFunc("POST /p/{p}/f/{f}/content", w.scoped(w.saveContent))
	auth.HandleFunc("GET /p/{p}/f/{f}/raw", w.scoped(w.download))
	auth.HandleFunc("GET /p/{p}/f/{f}/history", w.scoped(w.historyPage))
	auth.HandleFunc("POST /p/{p}/f/{f}/restore", w.scoped(w.restore))
	auth.HandleFunc("GET /devices", w.devicesPage)
	auth.HandleFunc("GET /devices/{d}", w.owned(w.devicePage, false))
	auth.HandleFunc("POST /devices/{d}/access", w.owned(w.setDeviceAccess, false))
	auth.HandleFunc("POST /devices/{d}/revoke", w.owned(w.revokeDevice, false))
	auth.HandleFunc("POST /devices/{d}/delete", w.owned(w.deleteDevice, false))
	auth.HandleFunc("GET /tokens", w.tokensPage)
	auth.HandleFunc("POST /tokens", w.createToken)
	auth.HandleFunc("GET /tokens/{t}", w.owned(w.tokenPage, true))
	auth.HandleFunc("GET /tokens/{t}/secret", w.owned(w.tokenSecret, true))
	auth.HandleFunc("POST /tokens/{t}/access", w.owned(w.setTokenAccess, true))
	auth.HandleFunc("POST /tokens/{t}/revoke", w.owned(w.revokeToken, true))
	auth.HandleFunc("POST /tokens/{t}/delete", w.owned(w.deleteToken, true))
	auth.HandleFunc("GET /activate", w.activatePage)
	auth.HandleFunc("POST /activate", w.activate)
	mux.Handle("/", w.requireSession(auth))
	protected := http.NewCrossOriginProtection().Handler(mux)
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/static/") {
			rw.Header().Set("Cache-Control", "no-store")
		}
		protected.ServeHTTP(rw, r)
	})
}

// ---- sessions ----

func (w *Web) currentSession(r *http.Request) (session, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return session{}, false
	}
	w.mu.Lock()
	s, ok := w.sessions[c.Value]
	if !ok || time.Now().After(s.expires) {
		delete(w.sessions, c.Value)
		w.mu.Unlock()
		return session{}, false
	}
	w.mu.Unlock()
	u, err := w.store.GetUser(s.user.ID)
	if err != nil {
		return session{}, false
	}
	if u.AuthVersion != s.user.AuthVersion {
		w.mu.Lock()
		delete(w.sessions, c.Value)
		w.mu.Unlock()
		return session{}, false
	}
	s.user = u
	return s, true
}

type sessionKey struct{}

func withSession(r *http.Request, s session) context.Context {
	return context.WithValue(r.Context(), sessionKey{}, s)
}

func sessionFrom(r *http.Request) (session, bool) {
	s, ok := r.Context().Value(sessionKey{}).(session)
	return s, ok
}

func (w *Web) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		s, ok := w.currentSession(r)
		if !ok {
			to := "/login"
			if r.Method == http.MethodGet {
				to += "?next=" + url.QueryEscape(r.URL.RequestURI())
			}
			http.Redirect(rw, r, to, http.StatusSeeOther)
			return
		}
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(rw, r.Body, w.opts.MaxFileSize+1<<20)
			if !sameToken(r.Header.Get("X-CSRF-Token"), s.csrf) && !sameToken(formValue(r, "csrf"), s.csrf) {
				http.Error(rw, "invalid csrf token", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(rw, r.WithContext(withSession(r, s)))
	})
}

func sameToken(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

// formValue reads a form field from urlencoded or multipart bodies.
func formValue(r *http.Request, key string) string {
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/") {
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			return ""
		}
	}
	return r.FormValue(key)
}

// nextURL returns the local path to continue to after login.
func nextURL(r *http.Request) string {
	next := r.FormValue("next")
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		return "/"
	}
	return next
}

func (w *Web) loginPage(rw http.ResponseWriter, r *http.Request) {
	open, err := w.store.RegistrationOpen()
	if notFound(rw, err) {
		return
	}
	if open {
		http.Redirect(rw, r, "/register", http.StatusSeeOther)
		return
	}
	if _, ok := w.currentSession(r); ok {
		http.Redirect(rw, r, nextURL(r), http.StatusSeeOther)
		return
	}
	w.render(rw, r, "login", "Login", map[string]any{"Next": nextURL(r)})
}

func (w *Web) login(rw http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(rw, r.Body, 64<<10)
	done, ok := w.acquireVerify(rw, r)
	if !ok {
		return
	}
	u, err := w.store.AuthenticateUser(strings.TrimSpace(r.FormValue("username")), r.FormValue("password"))
	done(err != nil)
	if err != nil {
		w.render(rw, r, "login", "Login", map[string]any{"Err": "Wrong username or password", "Next": nextURL(r)})
		return
	}
	w.startSession(rw, r, u)
}

func (w *Web) startSession(rw http.ResponseWriter, r *http.Request, u model.User) {
	id := crypto.RandomString(32)
	w.mu.Lock()
	for k, s := range w.sessions {
		if time.Now().After(s.expires) {
			delete(w.sessions, k)
		}
	}
	w.sessions[id] = session{user: u, csrf: crypto.RandomString(24), expires: time.Now().Add(sessionTTL)}
	w.mu.Unlock()
	http.SetCookie(rw, &http.Cookie{
		Name: cookieName, Value: id, Path: "/", HttpOnly: true, Secure: w.opts.SecureOnly || server.IsHTTPS(r),
		SameSite: http.SameSiteStrictMode, MaxAge: int(sessionTTL.Seconds()),
	})
	http.Redirect(rw, r, nextURL(r), http.StatusSeeOther)
}

func (w *Web) logout(rw http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		w.mu.Lock()
		delete(w.sessions, c.Value)
		w.mu.Unlock()
	}
	http.SetCookie(rw, &http.Cookie{Name: cookieName, Path: "/", MaxAge: -1, HttpOnly: true,
		Secure: w.opts.SecureOnly || server.IsHTTPS(r), SameSite: http.SameSiteStrictMode})
	http.Redirect(rw, r, "/login", http.StatusSeeOther)
}

// beginAttempt reserves a place in the failure budget before checking a password.
func (w *Web) beginAttempt(ip string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	cut := time.Now().Add(-failWindow)
	for k, fs := range w.failures {
		for len(fs) > 0 && fs[0].Before(cut) {
			fs = fs[1:]
		}
		if len(fs) == 0 {
			delete(w.failures, k)
		} else {
			w.failures[k] = fs
		}
	}
	if len(w.failures[ip])+w.inFlight[ip] >= maxFailures {
		return false
	}
	w.inFlight[ip]++
	return true
}

func (w *Web) finishAttempt(ip string, failed bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.inFlight[ip]--
	if w.inFlight[ip] == 0 {
		delete(w.inFlight, ip)
	}
	if failed {
		w.failures[ip] = append(w.failures[ip], time.Now())
	}
}

func (w *Web) acquireVerify(rw http.ResponseWriter, r *http.Request) (func(bool), bool) {
	ip := limitKey(server.ClientIP(r))
	if !w.beginAttempt(ip) {
		http.Error(rw, "Too many failed attempts, try again later", http.StatusTooManyRequests)
		return nil, false
	}
	select {
	case w.verify <- struct{}{}:
		return func(failed bool) {
			w.finishAttempt(ip, failed)
			<-w.verify
		}, true
	case <-r.Context().Done():
		w.finishAttempt(ip, false)
		return nil, false
	default:
		w.finishAttempt(ip, false)
		http.Error(rw, "Server busy, try again later", http.StatusTooManyRequests)
		return nil, false
	}
}

// limitKey groups IPv6 addresses by /64 for login rate limiting.
func limitKey(ip string) string {
	a := net.ParseIP(ip)
	if a == nil || a.To4() != nil {
		return ip
	}
	return a.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// ---- rendering ----

func (w *Web) render(rw http.ResponseWriter, r *http.Request, page, title string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["Title"] = title
	if s, ok := sessionFrom(r); ok {
		data["CSRF"] = s.csrf
		data["LoggedIn"] = true
		data["User"] = s.user
		data["Admin"] = s.user.Admin
	}
	if _, ok := data["Msg"]; !ok {
		data["Msg"] = r.URL.Query().Get("msg")
	}
	if _, ok := data["Err"]; !ok {
		data["Err"] = r.URL.Query().Get("err")
	}
	var buf bytes.Buffer
	if err := w.pages[page].Execute(&buf, data); err != nil {
		log.Printf("render %s: %v", page, err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return
	}
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = buf.WriteTo(rw)
}

// back redirects to path with a message (msg) or error (err).
func back(rw http.ResponseWriter, r *http.Request, path, kind, text string) {
	if text != "" {
		path += "?" + kind + "=" + url.QueryEscape(text)
	}
	http.Redirect(rw, r, path, http.StatusSeeOther)
}

func errText(err error) string {
	var ce *store.ConflictError
	switch {
	case errors.As(err, &ce):
		return fmt.Sprintf("Conflict: file changed to rev %d meanwhile, reload and retry", ce.HeadRev)
	case errors.Is(err, store.ErrNotFound):
		return "Not found"
	case errors.Is(err, store.ErrExists):
		return "Already exists"
	case errors.Is(err, store.ErrDenied):
		return "Access denied"
	}
	log.Printf("error: %v", err)
	return "Internal error"
}

func notFound(rw http.ResponseWriter, err error) bool {
	if errors.Is(err, store.ErrNotFound) {
		http.NotFound(rw, nil)
		return true
	}
	if err != nil {
		log.Printf("error: %v", err)
		http.Error(rw, "internal error", http.StatusInternalServerError)
		return true
	}
	return false
}

func projectURL(p string) string { return "/p/" + url.PathEscape(p) }
func fileURL(p, f string) string { return projectURL(p) + "/f/" + url.PathEscape(f) }
func isText(data []byte) bool    { return utf8.Valid(data) && !syncer.IsBinary(data) }
func parseRev(s string) int64    { n, _ := strconv.ParseInt(s, 10, 64); return n }

// ---- projects ----

func (w *Web) projectsPage(rw http.ResponseWriter, r *http.Request) {
	ps, err := w.store.ListProjects()
	if notFound(rw, err) {
		return
	}
	s, _ := sessionFrom(r)
	ps = slices.DeleteFunc(ps, func(p model.Project) bool { return !s.user.CanAccess(p.Name) })
	w.render(rw, r, "projects", "Projects", map[string]any{"Projects": ps})
}

func (w *Web) createProject(rw http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	if !model.ValidName(name) {
		back(rw, r, "/", "err", "Invalid project name")
		return
	}
	if err := w.store.CreateProject(name, strings.TrimSpace(r.FormValue("description"))); err != nil {
		back(rw, r, "/", "err", errText(err))
		return
	}
	http.Redirect(rw, r, projectURL(name), http.StatusSeeOther)
}

func (w *Web) deleteProject(rw http.ResponseWriter, r *http.Request) {
	if err := w.store.DeleteProject(r.PathValue("p")); err != nil {
		back(rw, r, "/", "err", errText(err))
		return
	}
	back(rw, r, "/", "msg", "Project deleted")
}

func (w *Web) projectPage(rw http.ResponseWriter, r *http.Request) {
	p, err := w.store.GetProject(r.PathValue("p"))
	if notFound(rw, err) {
		return
	}
	w.render(rw, r, "project", p.Name, map[string]any{"Project": p, "Platforms": model.Platforms})
}

// fileDef builds a file definition from form fields.
func fileDef(r *http.Request, name string) (model.File, error) {
	f := model.File{
		Name: name,
		Path: strings.TrimSpace(r.FormValue("path")),
		Mode: strings.TrimSpace(r.FormValue("mode")),
	}
	for _, line := range strings.Split(r.FormValue("paths"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return f, fmt.Errorf("invalid path override %q, expected os=path", line)
		}
		if f.Paths == nil {
			f.Paths = map[string]string{}
		}
		f.Paths[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	for _, p := range strings.Split(r.FormValue("platforms"), ",") {
		if p = strings.TrimSpace(p); p != "" {
			f.Platforms = append(f.Platforms, p)
		}
	}
	return f, model.ValidateFile(f)
}

func (w *Web) createFile(rw http.ResponseWriter, r *http.Request) {
	p := r.PathValue("p")
	f, err := fileDef(r, strings.TrimSpace(r.FormValue("name")))
	if err != nil {
		back(rw, r, projectURL(p), "err", err.Error())
		return
	}
	if err := w.store.CreateFile(p, f); err != nil {
		back(rw, r, projectURL(p), "err", errText(err))
		return
	}
	http.Redirect(rw, r, fileURL(p, f.Name), http.StatusSeeOther)
}

// ---- files ----

func (w *Web) filePage(rw http.ResponseWriter, r *http.Request) {
	p, name := r.PathValue("p"), r.PathValue("f")
	f, err := w.store.GetFile(p, name)
	if notFound(rw, err) {
		return
	}
	data := map[string]any{"Project": p, "File": f, "Text": true, "Content": ""}
	if f.HeadRev > 0 {
		content, _, err := w.store.Content(p, name, 0)
		if notFound(rw, err) {
			return
		}
		data["Text"] = isText(content)
		if data["Text"] == true {
			data["Content"] = string(content)
		}
	}
	w.render(rw, r, "file", p+"/"+name, data)
}

func (w *Web) updateFile(rw http.ResponseWriter, r *http.Request) {
	p, name := r.PathValue("p"), r.PathValue("f")
	f, err := fileDef(r, name)
	if err != nil {
		back(rw, r, fileURL(p, name), "err", err.Error())
		return
	}
	if err := w.store.UpdateFile(p, name, f); err != nil {
		back(rw, r, fileURL(p, name), "err", errText(err))
		return
	}
	back(rw, r, fileURL(p, name), "msg", "Definition saved")
}

func (w *Web) deleteFile(rw http.ResponseWriter, r *http.Request) {
	p, name := r.PathValue("p"), r.PathValue("f")
	if err := w.store.DeleteFile(p, name); err != nil {
		back(rw, r, fileURL(p, name), "err", errText(err))
		return
	}
	back(rw, r, projectURL(p), "msg", "File removed")
}

func (w *Web) saveContent(rw http.ResponseWriter, r *http.Request) {
	p, name := r.PathValue("p"), r.PathValue("f")
	to := fileURL(p, name)
	var data []byte
	if up, _, err := r.FormFile("upload"); err == nil {
		defer up.Close()
		if data, err = io.ReadAll(io.LimitReader(up, w.opts.MaxFileSize+1)); err != nil {
			back(rw, r, to, "err", err.Error())
			return
		}
	} else {
		data = []byte(r.FormValue("content"))
		if head, _, err := w.store.Content(p, name, 0); err != nil || !bytes.Contains(head, []byte("\r\n")) {
			data = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
		}
	}
	if int64(len(data)) > w.opts.MaxFileSize {
		back(rw, r, to, "err", "File too large")
		return
	}
	v, created, err := w.store.Put(p, name, parseRev(r.FormValue("base")), data, model.WebDevice, r.FormValue("message"))
	if err != nil {
		back(rw, r, to, "err", errText(err))
		return
	}
	if !created {
		back(rw, r, to, "msg", "No changes")
		return
	}
	back(rw, r, to, "msg", fmt.Sprintf("Saved as rev %d", v.Rev))
}

func (w *Web) download(rw http.ResponseWriter, r *http.Request) {
	p, name := r.PathValue("p"), r.PathValue("f")
	data, v, err := w.store.Content(p, name, parseRev(r.URL.Query().Get("rev")))
	if notFound(rw, err) {
		return
	}
	rw.Header().Set("Content-Type", "application/octet-stream")
	rw.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", fmt.Sprintf("%s.rev%d", name, v.Rev)))
	_, _ = rw.Write(data)
}

func (w *Web) historyPage(rw http.ResponseWriter, r *http.Request) {
	p, name := r.PathValue("p"), r.PathValue("f")
	f, err := w.store.GetFile(p, name)
	if notFound(rw, err) {
		return
	}
	vs, err := w.store.Versions(p, name)
	if notFound(rw, err) {
		return
	}
	data := map[string]any{"Project": p, "File": f, "Versions": vs}
	q := r.URL.Query()
	if q.Has("a") && q.Has("b") {
		a, b := parseRev(q.Get("a")), parseRev(q.Get("b"))
		da, _, errA := w.store.Content(p, name, a)
		db, _, errB := w.store.Content(p, name, b)
		if a < 1 || b < 1 || errA != nil || errB != nil {
			data["Err"] = "Version not found"
		} else {
			d, err := syncer.UnifiedDiff(da, db, fmt.Sprintf("rev %d", a), fmt.Sprintf("rev %d", b))
			if err != nil {
				data["Err"] = err.Error()
			}
			if d == "" {
				d = "(no differences)"
			}
			data["Diff"], data["A"], data["B"] = d, a, b
		}
	}
	w.render(rw, r, "history", "History: "+p+"/"+name, data)
}

func (w *Web) restore(rw http.ResponseWriter, r *http.Request) {
	p, name := r.PathValue("p"), r.PathValue("f")
	to := fileURL(p, name) + "/history"
	v, err := w.store.Restore(p, name, parseRev(r.FormValue("rev")), model.WebDevice)
	if err != nil {
		back(rw, r, to, "err", errText(err))
		return
	}
	back(rw, r, to, "msg", fmt.Sprintf("Restored as rev %d", v.Rev))
}

// ---- devices ----

func (w *Web) devicesPage(rw http.ResponseWriter, r *http.Request) {
	ds, err := w.store.ListDevices()
	if notFound(rw, err) {
		return
	}
	s, _ := sessionFrom(r)
	ds = slices.DeleteFunc(ds, func(d model.Device) bool { return !s.user.Admin && d.UserID != s.user.ID })
	w.render(rw, r, "devices", "Devices", map[string]any{"Devices": ds})
}

// scopeData returns template data for the project access form.
func (w *Web) scopeData(r *http.Request, all bool, selected []string) (map[string]any, error) {
	s, _ := sessionFrom(r)
	return w.scopeDataFor(s.user, all, selected)
}

func (w *Web) scopeDataFor(u model.User, all bool, selected []string) (map[string]any, error) {
	ps, err := w.store.ListProjects()
	if err != nil {
		return nil, err
	}
	ps = slices.DeleteFunc(ps, func(p model.Project) bool { return !u.CanAccess(p.Name) })
	sel := map[string]bool{}
	for _, p := range selected {
		sel[p] = true
	}
	return map[string]any{"All": all, "CanGrantAll": u.Admin || u.AllProjects, "Projects": ps, "Selected": sel}, nil
}

func (w *Web) credentialScope(d model.Device) (map[string]any, error) {
	u, err := w.store.GetUser(d.UserID)
	if err != nil {
		return nil, err
	}
	return w.scopeDataFor(u, d.AllProjects, d.Projects)
}

func (w *Web) devicePage(rw http.ResponseWriter, r *http.Request) {
	d, err := w.store.GetDevice(r.PathValue("d"))
	if notFound(rw, err) {
		return
	}
	data, err := w.credentialScope(d)
	if notFound(rw, err) {
		return
	}
	data["Device"] = d
	w.render(rw, r, "device", "Device "+d.Name, data)
}

func (w *Web) setDeviceAccess(rw http.ResponseWriter, r *http.Request) {
	name := r.PathValue("d")
	to := "/devices/" + url.PathEscape(name)
	if err := w.store.SetDeviceAccess(name, r.FormValue("all") != "", r.Form["project"]); err != nil {
		back(rw, r, to, "err", errText(err))
		return
	}
	back(rw, r, to, "msg", "Access saved")
}

func (w *Web) revokeDevice(rw http.ResponseWriter, r *http.Request) {
	if err := w.store.RevokeDevice(r.PathValue("d")); err != nil {
		back(rw, r, "/devices", "err", errText(err))
		return
	}
	back(rw, r, "/devices", "msg", "Device revoked")
}

func (w *Web) deleteDevice(rw http.ResponseWriter, r *http.Request) {
	if err := w.store.DeleteDevice(r.PathValue("d")); err != nil {
		back(rw, r, "/devices", "err", errText(err))
		return
	}
	back(rw, r, "/devices", "msg", "Device deleted")
}

// ---- access tokens ----

func (w *Web) tokensPage(rw http.ResponseWriter, r *http.Request) {
	if err := w.renderTokens(rw, r, nil, ""); err != nil {
		notFound(rw, err)
	}
}

// renderTokens renders the tokens page, including a newly created token.
func (w *Web) renderTokens(rw http.ResponseWriter, r *http.Request, newToken *string, errMsg string) error {
	ts, err := w.store.ListPATs()
	if err != nil {
		return err
	}
	s, _ := sessionFrom(r)
	ts = slices.DeleteFunc(ts, func(d model.Device) bool { return !s.user.Admin && d.UserID != s.user.ID })
	scope, err := w.scopeData(r, false, nil)
	if err != nil {
		return err
	}
	data := map[string]any{"Tokens": ts}
	for k, v := range scope {
		data[k] = v
	}
	if newToken != nil {
		data["NewToken"] = *newToken
		data["Msg"] = "Token created"
	}
	if errMsg != "" {
		data["Err"] = errMsg
	}
	w.render(rw, r, "tokens", "Access tokens", data)
	return nil
}

func (w *Web) createToken(rw http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	if !model.ValidDeviceName(name) {
		_ = w.renderTokens(rw, r, nil, "Invalid token name")
		return
	}
	s, _ := sessionFrom(r)
	token, err := w.store.CreatePAT(s.user.ID, name, r.FormValue("all") != "", r.Form["project"])
	if err != nil {
		_ = w.renderTokens(rw, r, nil, errText(err))
		return
	}
	_ = w.renderTokens(rw, r, &token, "")
}

func (w *Web) tokenPage(rw http.ResponseWriter, r *http.Request) {
	t, err := w.store.GetPAT(r.PathValue("t"))
	if notFound(rw, err) {
		return
	}
	data, err := w.credentialScope(t)
	if notFound(rw, err) {
		return
	}
	data["Token"] = t
	w.render(rw, r, "token", "Token "+t.Name, data)
}

func (w *Web) tokenSecret(rw http.ResponseWriter, r *http.Request) {
	secret, err := w.store.PATSecret(r.PathValue("t"))
	if notFound(rw, err) {
		return
	}
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(rw, secret)
}

func (w *Web) setTokenAccess(rw http.ResponseWriter, r *http.Request) {
	name := r.PathValue("t")
	to := "/tokens/" + url.PathEscape(name)
	if err := w.store.SetPATAccess(name, r.FormValue("all") != "", r.Form["project"]); err != nil {
		back(rw, r, to, "err", errText(err))
		return
	}
	back(rw, r, to, "msg", "Access saved")
}

func (w *Web) revokeToken(rw http.ResponseWriter, r *http.Request) {
	if err := w.store.RevokePAT(r.PathValue("t")); err != nil {
		back(rw, r, "/tokens", "err", errText(err))
		return
	}
	back(rw, r, "/tokens", "msg", "Token revoked")
}

func (w *Web) deleteToken(rw http.ResponseWriter, r *http.Request) {
	if err := w.store.DeletePAT(r.PathValue("t")); err != nil {
		back(rw, r, "/tokens", "err", errText(err))
		return
	}
	back(rw, r, "/tokens", "msg", "Token deleted")
}

// ---- device activation ----

func (w *Web) activatePage(rw http.ResponseWriter, r *http.Request) {
	w.renderActivate(rw, r, r.URL.Query().Get("code"), "")
}

// renderActivate shows the code entry form, or the pending request for code.
func (w *Web) renderActivate(rw http.ResponseWriter, r *http.Request, code, errMsg string) {
	if code == "" {
		w.render(rw, r, "activate", "Activate device", map[string]any{"Err": errMsg})
		return
	}
	req, err := w.store.PendingDeviceRequest(crypto.NormalizeUserCode(code))
	if errors.Is(err, store.ErrNotFound) {
		w.render(rw, r, "activate", "Activate device", map[string]any{"Err": "Code not found or expired", "Code": code})
		return
	}
	if notFound(rw, err) {
		return
	}
	data, err := w.scopeData(r, false, nil)
	if notFound(rw, err) {
		return
	}
	data["Request"], data["Err"] = req, errMsg
	w.render(rw, r, "activate", "Activate device", data)
}

func (w *Web) activate(rw http.ResponseWriter, r *http.Request) {
	code := crypto.NormalizeUserCode(r.FormValue("code"))
	if r.FormValue("action") == "deny" {
		if err := w.store.DenyDeviceRequest(code); err != nil {
			w.renderActivate(rw, r, code, errText(err))
			return
		}
		back(rw, r, "/devices", "msg", "Request denied")
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if !model.ValidDeviceName(name) {
		w.renderActivate(rw, r, code, "Invalid device name")
		return
	}
	s, _ := sessionFrom(r)
	if err := w.store.ApproveDeviceRequest(s.user.ID, code, name, r.FormValue("all") != "", r.Form["project"]); err != nil {
		msg := errText(err)
		if errors.Is(err, store.ErrExists) {
			msg = "Name already in use"
		}
		w.renderActivate(rw, r, code, msg)
		return
	}
	back(rw, r, "/devices", "msg", fmt.Sprintf("Device %s approved", name))
}
