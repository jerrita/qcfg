package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/jerrita/qcfg/internal/crypto"
	"github.com/jerrita/qcfg/internal/model"
	"github.com/jerrita/qcfg/internal/server"
	"github.com/jerrita/qcfg/internal/store"
)

type browser struct {
	h      http.Handler
	cookie *http.Cookie
	csrf   string
}

func (b *browser) request(method, path string, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if b.cookie != nil {
		r.AddCookie(b.cookie)
		r.Header.Set("X-CSRF-Token", b.csrf)
	}
	rw := httptest.NewRecorder()
	b.h.ServeHTTP(rw, r)
	return rw
}

func (b *browser) signIn(t *testing.T, path, username, password string) {
	t.Helper()
	rw := b.request(http.MethodPost, path, url.Values{"username": {username}, "password": {password}})
	if rw.Code != http.StatusSeeOther || len(rw.Result().Cookies()) == 0 {
		t.Fatalf("sign in: status=%d", rw.Code)
	}
	b.cookie = rw.Result().Cookies()[0]
	rw = b.request(http.MethodGet, "/tokens", nil)
	if rw.Code != http.StatusOK {
		t.Fatalf("session: status=%d", rw.Code)
	}
	match := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(rw.Body.String())
	if len(match) != 2 {
		t.Fatal("missing CSRF token")
	}
	b.csrf = match[1]
}

func TestUsersAndSharedProjectPermissions(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "web.db"), crypto.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	h := server.New(st, server.Options{MaxFileSize: 4096}, New(st, Options{MaxFileSize: 4096}))
	admin := &browser{h: h}
	if rw := admin.request(http.MethodGet, "/login", nil); rw.Code != http.StatusSeeOther || rw.Header().Get("Location") != "/register" {
		t.Fatalf("initial login: status=%d", rw.Code)
	}
	if rw := admin.request(http.MethodGet, "/register", nil); rw.Code != http.StatusOK {
		t.Fatalf("registration page: status=%d", rw.Code)
	}
	adminPassword := crypto.RandomString(18)
	admin.signIn(t, "/register", "owner", adminPassword)
	if rw := admin.request(http.MethodPost, "/register", url.Values{"username": {"extra"}, "password": {crypto.RandomString(18)}}); rw.Code != http.StatusForbidden {
		t.Fatalf("registration remained open: status=%d", rw.Code)
	}
	for _, name := range []string{"alpha", "beta"} {
		rw := admin.request(http.MethodPost, "/projects", url.Values{"name": {name}})
		if rw.Code != http.StatusSeeOther || rw.Header().Get("Location") != "/p/"+name {
			t.Fatalf("create project: status=%d", rw.Code)
		}
	}
	memberPassword := crypto.RandomString(18)
	rw := admin.request(http.MethodPost, "/users", url.Values{"username": {"member"}, "password": {memberPassword}, "project": {"alpha"}})
	if rw.Code != http.StatusSeeOther || strings.Contains(rw.Header().Get("Location"), "err=") {
		t.Fatalf("create user: status=%d", rw.Code)
	}
	member, err := st.AuthenticateUser("member", memberPassword)
	if err != nil {
		t.Fatal(err)
	}
	user := &browser{h: h}
	user.signIn(t, "/login", "member", memberPassword)
	rw = user.request(http.MethodGet, "/", nil)
	if rw.Code != http.StatusOK || !strings.Contains(rw.Body.String(), "/p/alpha") || strings.Contains(rw.Body.String(), "/p/beta") || strings.Contains(rw.Body.String(), "New project") {
		t.Fatalf("filtered projects: status=%d", rw.Code)
	}
	for _, path := range []string{"/users", "/users/1"} {
		if rw := user.request(http.MethodGet, path, nil); rw.Code != http.StatusForbidden {
			t.Fatalf("user admin page %s: status=%d", path, rw.Code)
		}
	}
	for _, path := range []string{"/users", "/users/1/access", "/projects", "/p/alpha/delete"} {
		if rw := user.request(http.MethodPost, path, nil); rw.Code != http.StatusForbidden {
			t.Fatalf("user admin action %s: status=%d", path, rw.Code)
		}
	}
	for _, path := range []string{"/p/beta", "/p/beta/f/settings", "/p/beta/f/settings/raw", "/p/beta/f/settings/history"} {
		if rw := user.request(http.MethodGet, path, nil); rw.Code != http.StatusNotFound {
			t.Fatalf("foreign project %s: status=%d", path, rw.Code)
		}
	}
	for _, action := range []string{"files", "f/settings/def", "f/settings/delete", "f/settings/content", "f/settings/restore"} {
		if rw := user.request(http.MethodPost, "/p/beta/"+action, nil); rw.Code != http.StatusNotFound {
			t.Fatalf("foreign project action %s: status=%d", action, rw.Code)
		}
	}
	rw = user.request(http.MethodPost, "/p/alpha/files", url.Values{"name": {"settings"}, "path": {"~/settings"}})
	if rw.Code != http.StatusSeeOther || strings.Contains(rw.Header().Get("Location"), "err=") {
		t.Fatalf("authorized file creation: status=%d", rw.Code)
	}
	if rw := user.request(http.MethodPost, "/tokens", url.Values{"name": {"blocked"}, "all": {"1"}}); rw.Code != http.StatusOK || !strings.Contains(rw.Body.String(), "Access denied") {
		t.Fatalf("token escalation: status=%d", rw.Code)
	}
	accounts, err := st.ListUsers()
	if err != nil {
		t.Fatal(err)
	}
	var ownerID int64
	for _, u := range accounts {
		if u.Admin {
			ownerID = u.ID
		}
	}
	adminToken, err := st.CreatePAT(ownerID, "owner-token", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	memberToken, err := st.CreatePAT(member.ID, "member-token", false, []string{"alpha"})
	if err != nil {
		t.Fatal(err)
	}
	code, userCode, err := st.CreateDeviceRequest("owner-device", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.ApproveDeviceRequest(ownerID, userCode, "owner-device", true, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.ClaimDeviceToken(code); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/tokens/owner-token", "/devices/owner-device"} {
		if rw := user.request(http.MethodGet, path, nil); rw.Code != http.StatusNotFound {
			t.Fatalf("foreign credential %s: status=%d", path, rw.Code)
		}
		for _, action := range []string{"access", "revoke", "delete"} {
			if rw := user.request(http.MethodPost, path+"/"+action, nil); rw.Code != http.StatusNotFound {
				t.Fatalf("foreign credential action %s: status=%d", action, rw.Code)
			}
		}
	}
	for _, path := range []string{"/tokens", "/devices"} {
		rw := user.request(http.MethodGet, path, nil)
		if rw.Code != http.StatusOK || strings.Contains(rw.Body.String(), "owner-token") || strings.Contains(rw.Body.String(), "owner-device") {
			t.Fatalf("credential list %s: status=%d", path, rw.Code)
		}
	}
	for _, path := range []string{"/tokens", "/tokens/member-token"} {
		rw := user.request(http.MethodGet, path, nil)
		if rw.Code != http.StatusOK || !strings.Contains(rw.Body.String(), `data-copy-token="/tokens/member-token/secret"`) || strings.Contains(rw.Body.String(), memberToken) {
			t.Fatalf("token copy button %s: status=%d", path, rw.Code)
		}
	}
	for _, b := range []*browser{user, admin} {
		rw := b.request(http.MethodGet, "/tokens/member-token/secret", nil)
		if rw.Code != http.StatusOK || rw.Body.String() != memberToken || rw.Header().Get("Cache-Control") != "no-store" || rw.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
			t.Fatalf("token copy: status=%d", rw.Code)
		}
	}
	for _, path := range []string{"/tokens/owner-token/secret", "/tokens/owner-device/secret"} {
		if rw := user.request(http.MethodGet, path, nil); rw.Code != http.StatusNotFound {
			t.Fatalf("foreign token copy: status=%d", rw.Code)
		}
	}
	if rw := (&browser{h: h}).request(http.MethodGet, "/tokens/member-token/secret", nil); rw.Code != http.StatusSeeOther || strings.Contains(rw.Body.String(), memberToken) {
		t.Fatalf("unauthenticated token copy: status=%d", rw.Code)
	}
	api := func(method, path, token, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/v1"+path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		rw := httptest.NewRecorder()
		h.ServeHTTP(rw, r)
		return rw
	}
	rw = api(http.MethodGet, "/projects", memberToken, "")
	var projects []model.Project
	if err := json.Unmarshal(rw.Body.Bytes(), &projects); err != nil || rw.Code != http.StatusOK || len(projects) != 1 || projects[0].Name != "alpha" {
		t.Fatalf("API project list: status=%d err=%v", rw.Code, err)
	}
	for _, action := range []struct{ method, path string }{{http.MethodPost, "/projects"}, {http.MethodPatch, "/projects/alpha"}, {http.MethodDelete, "/projects/alpha"}} {
		if rw := api(action.method, action.path, memberToken, "{}"); rw.Code != http.StatusForbidden {
			t.Fatalf("API project management %s: status=%d", action.method, rw.Code)
		}
	}
	if rw := api(http.MethodPost, "/projects", adminToken, `{"name":"gamma"}`); rw.Code != http.StatusCreated {
		t.Fatalf("admin API project creation: status=%d", rw.Code)
	}
	if rw := api(http.MethodGet, "/projects/beta", memberToken, ""); rw.Code != http.StatusNotFound {
		t.Fatalf("API foreign project: status=%d", rw.Code)
	}
	if rw := admin.request(http.MethodGet, "/users", nil); rw.Code != http.StatusOK {
		t.Fatalf("users page: status=%d", rw.Code)
	}
	userPath := "/users/" + strconv.FormatInt(member.ID, 10)
	if rw := admin.request(http.MethodGet, userPath, nil); rw.Code != http.StatusOK {
		t.Fatalf("user access page: status=%d", rw.Code)
	}
	if rw := admin.request(http.MethodPost, userPath+"/access", nil); rw.Code != http.StatusSeeOther || strings.Contains(rw.Header().Get("Location"), "err=") {
		t.Fatalf("revoke user access: status=%d", rw.Code)
	}
	if rw := user.request(http.MethodGet, "/p/alpha", nil); rw.Code != http.StatusNotFound {
		t.Fatalf("existing session retained revoked access: status=%d", rw.Code)
	}
	if rw := api(http.MethodGet, "/projects/alpha", memberToken, ""); rw.Code != http.StatusNotFound {
		t.Fatalf("existing token retained revoked access: status=%d", rw.Code)
	}
	user.csrf = "invalid"
	if rw := user.request(http.MethodPost, "/tokens", nil); rw.Code != http.StatusForbidden {
		t.Fatalf("invalid CSRF: status=%d", rw.Code)
	}
	if err := st.RevokePAT("member-token"); err != nil {
		t.Fatal(err)
	}
	if rw := user.request(http.MethodGet, "/tokens/member-token/secret", nil); rw.Code != http.StatusNotFound {
		t.Fatalf("revoked token copy: status=%d", rw.Code)
	}
	if rw := user.request(http.MethodGet, "/tokens", nil); strings.Contains(rw.Body.String(), `data-copy-token="/tokens/member-token/secret"`) {
		t.Fatal("revoked token has copy button")
	}
}

func TestAdminUsername(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "web.db"), crypto.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	password := crypto.RandomString(18)
	owner, err := st.RegisterAdmin("owner", password)
	if err != nil {
		t.Fatal(err)
	}
	memberPassword := crypto.RandomString(18)
	if err := st.CreateUser(owner.ID, "member", memberPassword, false, nil); err != nil {
		t.Fatal(err)
	}
	h := New(st, Options{MaxFileSize: 4096})
	admin := &browser{h: h}
	admin.signIn(t, "/login", "owner", password)
	to := "/users/" + strconv.FormatInt(owner.ID, 10)
	if rw := admin.request(http.MethodGet, to, nil); rw.Code != http.StatusOK || !strings.Contains(rw.Body.String(), "Save username") {
		t.Fatalf("username form: status=%d", rw.Code)
	}
	for _, name := range []string{"", "invalid name", "member"} {
		rw := admin.request(http.MethodPost, to+"/name", url.Values{"username": {name}})
		if rw.Code != http.StatusSeeOther || !strings.Contains(rw.Header().Get("Location"), "err=") {
			t.Fatalf("invalid or duplicate username: status=%d", rw.Code)
		}
	}
	rw := admin.request(http.MethodPost, to+"/name", url.Values{"username": {"new-owner"}})
	if rw.Code != http.StatusSeeOther || strings.Contains(rw.Header().Get("Location"), "err=") {
		t.Fatalf("rename administrator: status=%d", rw.Code)
	}
	if rw := admin.request(http.MethodGet, to, nil); rw.Code != http.StatusOK || !strings.Contains(rw.Body.String(), `value="new-owner"`) {
		t.Fatalf("existing session after rename: status=%d", rw.Code)
	}
	fresh := &browser{h: h}
	fresh.signIn(t, "/login", "new-owner", password)
	old := &browser{h: h}
	if rw := old.request(http.MethodPost, "/login", url.Values{"username": {"owner"}, "password": {password}}); len(rw.Result().Cookies()) != 0 || !strings.Contains(rw.Body.String(), "Wrong username or password") {
		t.Fatalf("old username login: status=%d", rw.Code)
	}
	member, err := st.AuthenticateUser("member", memberPassword)
	if err != nil {
		t.Fatal(err)
	}
	memberPath := "/users/" + strconv.FormatInt(member.ID, 10)
	if rw := admin.request(http.MethodPost, memberPath+"/name", url.Values{"username": {"other"}}); rw.Code != http.StatusForbidden {
		t.Fatalf("rename another account: status=%d", rw.Code)
	}
	user := &browser{h: h}
	user.signIn(t, "/login", "member", memberPassword)
	if rw := user.request(http.MethodPost, to+"/name", url.Values{"username": {"other"}}); rw.Code != http.StatusForbidden {
		t.Fatalf("non-admin rename: status=%d", rw.Code)
	}
	admin.csrf = "invalid"
	if rw := admin.request(http.MethodPost, to+"/name", url.Values{"username": {"other"}}); rw.Code != http.StatusForbidden {
		t.Fatalf("rename without valid CSRF: status=%d", rw.Code)
	}
}
