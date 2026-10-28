package web

import (
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jerrita/qcfg/internal/crypto"
	"github.com/jerrita/qcfg/internal/server"
	"github.com/jerrita/qcfg/internal/store"
)

func TestActivityVisibility(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "activity.db"), crypto.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	h := server.New(st, server.Options{MaxFileSize: 4096}, New(st, Options{MaxFileSize: 4096}))
	admin := &browser{h: h}
	admin.signIn(t, "/register", "owner", crypto.RandomString(18))
	password := crypto.RandomString(18)
	admin.request(http.MethodPost, "/users", url.Values{"username": {"member"}, "password": {password}})
	member := &browser{h: h}
	member.signIn(t, "/login", "member", password)
	member.request(http.MethodPost, "/projects?secret=hidden", nil)

	body := member.request(http.MethodGet, "/activity", nil).Body.String()
	if !strings.Contains(body, "/projects") || strings.Contains(body, "/users") || strings.Contains(body, "secret=hidden") {
		t.Fatalf("member activity: %s", body)
	}
	body = admin.request(http.MethodGet, "/activity", nil).Body.String()
	if !strings.Contains(body, "/projects") || !strings.Contains(body, "/users") || !strings.Contains(body, "member") {
		t.Fatalf("admin activity: %s", body)
	}
}
