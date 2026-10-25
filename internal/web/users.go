package web

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/jerrita/qcfg/internal/model"
	"github.com/jerrita/qcfg/internal/server"
	"github.com/jerrita/qcfg/internal/store"
)

func (w *Web) admin(next http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		s, _ := sessionFrom(r)
		if !s.user.Admin {
			http.Error(rw, "access denied", http.StatusForbidden)
			return
		}
		next(rw, r)
	}
}

func (w *Web) scoped(next http.HandlerFunc) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		s, _ := sessionFrom(r)
		if !s.user.CanAccess(r.PathValue("p")) {
			http.NotFound(rw, r)
			return
		}
		next(rw, r)
	}
}

func (w *Web) owned(next http.HandlerFunc, token bool) http.HandlerFunc {
	return func(rw http.ResponseWriter, r *http.Request) {
		var d model.Device
		var err error
		if token {
			d, err = w.store.GetPAT(r.PathValue("t"))
		} else {
			d, err = w.store.GetDevice(r.PathValue("d"))
		}
		if notFound(rw, err) {
			return
		}
		s, _ := sessionFrom(r)
		if !s.user.Admin && d.UserID != s.user.ID {
			http.NotFound(rw, r)
			return
		}
		next(rw, r)
	}
}

func (w *Web) registerPage(rw http.ResponseWriter, r *http.Request) {
	open, err := w.store.RegistrationOpen()
	if notFound(rw, err) {
		return
	}
	if !open {
		http.Redirect(rw, r, "/login", http.StatusSeeOther)
		return
	}
	w.render(rw, r, "register", "Create administrator", nil)
}

func (w *Web) register(rw http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(rw, r.Body, 64<<10)
	open, err := w.store.RegistrationOpen()
	if notFound(rw, err) {
		return
	}
	if !open {
		http.Error(rw, "registration closed", http.StatusForbidden)
		return
	}
	ip := limitKey(server.ClientIP(r))
	if w.blocked(ip) {
		http.Error(rw, "too many attempts, try again later", http.StatusTooManyRequests)
		return
	}
	name, password := strings.TrimSpace(r.FormValue("username")), r.FormValue("password")
	if !validCredentials(name, password) {
		w.fail(ip)
		w.render(rw, r, "register", "Create administrator", map[string]any{"Err": "Use a valid username and a password between 8 and 1024 characters"})
		return
	}
	select {
	case w.verify <- struct{}{}:
	case <-r.Context().Done():
		return
	}
	u, err := w.store.RegisterAdmin(name, password)
	<-w.verify
	if err == store.ErrDenied {
		http.Error(rw, "registration closed", http.StatusForbidden)
		return
	}
	if notFound(rw, err) {
		return
	}
	w.startSession(rw, r, u)
}

func validCredentials(name, password string) bool {
	return model.ValidName(name) && len(password) >= 8 && len(password) <= 1024
}

func (w *Web) usersPage(rw http.ResponseWriter, r *http.Request) {
	users, err := w.store.ListUsers()
	if notFound(rw, err) {
		return
	}
	data, err := w.scopeData(r, false, nil)
	if notFound(rw, err) {
		return
	}
	data["Users"] = users
	w.render(rw, r, "users", "Users", data)
}

func (w *Web) createUser(rw http.ResponseWriter, r *http.Request) {
	name, password := strings.TrimSpace(r.FormValue("username")), r.FormValue("password")
	if !validCredentials(name, password) {
		back(rw, r, "/users", "err", "Use a valid username and a password between 8 and 1024 characters")
		return
	}
	s, _ := sessionFrom(r)
	select {
	case w.verify <- struct{}{}:
	case <-r.Context().Done():
		return
	}
	err := w.store.CreateUser(s.user.ID, name, password, r.FormValue("all") != "", r.Form["project"])
	<-w.verify
	if err != nil {
		back(rw, r, "/users", "err", errText(err))
		return
	}
	back(rw, r, "/users", "msg", "User created")
}

func (w *Web) userPage(rw http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("u"), 10, 64)
	u, err := w.store.GetUser(id)
	if notFound(rw, err) {
		return
	}
	data, err := w.scopeData(r, u.AllProjects, u.Projects)
	if notFound(rw, err) {
		return
	}
	data["Account"] = u
	w.render(rw, r, "user", "User "+u.Name, data)
}

func (w *Web) setUserAccess(rw http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("u"), 10, 64)
	s, _ := sessionFrom(r)
	if err := w.store.SetUserAccess(s.user.ID, id, r.FormValue("all") != "", r.Form["project"]); err != nil {
		back(rw, r, "/users", "err", errText(err))
		return
	}
	back(rw, r, "/users/"+strconv.FormatInt(id, 10), "msg", "Access saved")
}
