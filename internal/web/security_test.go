package web

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jerrita/qcfg/internal/crypto"
	"github.com/jerrita/qcfg/internal/server"
	"github.com/jerrita/qcfg/internal/store"
)

func TestSelfServicePasswordChange(t *testing.T) {
	for _, name := range []string{"owner", "member"} {
		t.Run(name, func(t *testing.T) {
			st, _, ownerPassword := securityStore(t)
			owner, err := st.AuthenticateUser("owner", ownerPassword)
			if err != nil {
				t.Fatal(err)
			}
			password := ownerPassword
			if name == "member" {
				password = crypto.RandomString(18)
				if err := st.CreateUser(owner.ID, name, password, false, nil); err != nil {
					t.Fatal(err)
				}
			}
			h := New(st, Options{MaxFileSize: 4096})
			b, other := &browser{h: h}, &browser{h: h}
			b.signIn(t, "/login", name, password)
			other.signIn(t, "/login", name, password)
			if rw := b.request(http.MethodGet, "/account", nil); rw.Code != http.StatusOK || !strings.Contains(rw.Body.String(), `action="/account/password"`) || !strings.Contains(rw.Body.String(), `href="/account"`) {
				t.Fatalf("account page: status=%d", rw.Code)
			}
			newPassword := crypto.RandomString(18)
			form := url.Values{"current_password": {password}, "password": {newPassword}, "confirm_password": {newPassword}}
			csrf := b.csrf
			b.csrf = "invalid"
			if rw := b.request(http.MethodPost, "/account/password", form); rw.Code != http.StatusForbidden {
				t.Fatalf("invalid CSRF: status=%d", rw.Code)
			}
			b.csrf = csrf
			for _, invalid := range []struct{ field, value string }{
				{"current_password", crypto.RandomString(18)},
				{"confirm_password", crypto.RandomString(18)},
				{"password", "short"},
				{"password", strings.Repeat("x", 1025)},
			} {
				value := form.Get(invalid.field)
				form.Set(invalid.field, invalid.value)
				rw := b.request(http.MethodPost, "/account/password", form)
				if rw.Code != http.StatusSeeOther || !strings.HasPrefix(rw.Header().Get("Location"), "/account?err=") {
					t.Fatalf("invalid %s: status=%d", invalid.field, rw.Code)
				}
				form.Set(invalid.field, value)
			}
			if _, err := st.AuthenticateUser(name, password); err != nil {
				t.Fatalf("rejected change modified password: %v", err)
			}
			rw := b.request(http.MethodPost, "/account/password", form)
			if rw.Code != http.StatusSeeOther || rw.Header().Get("Location") != "/login" {
				t.Fatalf("change password: status=%d", rw.Code)
			}
			cookies := rw.Result().Cookies()
			if len(cookies) != 1 || cookies[0].MaxAge != -1 {
				t.Fatal("password change did not clear cookie")
			}
			for _, session := range []*browser{b, other} {
				if rw := session.request(http.MethodGet, "/account", nil); rw.Code != http.StatusSeeOther || !strings.HasPrefix(rw.Header().Get("Location"), "/login") {
					t.Fatalf("old session survived change: status=%d", rw.Code)
				}
			}
			if _, err := st.AuthenticateUser(name, password); !errors.Is(err, store.ErrDenied) {
				t.Fatalf("old password after change: %v", err)
			}
			fresh := &browser{h: h}
			fresh.signIn(t, "/login", name, newPassword)
			if name == "member" {
				if _, err := st.AuthenticateUser("owner", ownerPassword); err != nil {
					t.Fatalf("member change affected administrator: %v", err)
				}
			}
		})
	}
}

func securityStore(t *testing.T) (*store.Store, string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "security.db")
	st, err := store.Open(path, crypto.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	password := crypto.RandomString(18)
	if _, err := st.RegisterAdmin("owner", password); err != nil {
		t.Fatal(err)
	}
	return st, path, password
}

func loginRequest(h http.Handler, peer, forwarded, password string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "http://cfg.example/login", strings.NewReader(url.Values{
		"username": {"owner"}, "password": {password},
	}.Encode()))
	r.RemoteAddr = peer
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://cfg.example")
	r.Header.Set("X-Forwarded-For", forwarded)
	r.Header.Set("X-Forwarded-Proto", "https")
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, r)
	return rw
}

func TestProxyLoginIsolationAndSecureCookies(t *testing.T) {
	st, _, password := securityStore(t)
	h := server.New(st, server.Options{}, New(st, Options{MaxFileSize: 4096}))
	for range maxFailures {
		if rw := loginRequest(h, "192.0.2.10:8000", "198.51.100.1", crypto.RandomString(18)); rw.Code != http.StatusOK {
			t.Fatalf("password check returned %d", rw.Code)
		}
	}
	if rw := loginRequest(h, "192.0.2.10:8000", "198.51.100.1", password); rw.Code != http.StatusTooManyRequests {
		t.Fatalf("limited client returned %d", rw.Code)
	}
	rw := loginRequest(h, "192.0.2.10:8000", "198.51.100.2", password)
	cookies := rw.Result().Cookies()
	if rw.Code != http.StatusSeeOther || len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("other proxy client: status=%d, cookies=%d", rw.Code, len(cookies))
	}
	for range maxFailures {
		loginRequest(h, "192.0.2.10:8000", "203.0.113.1, 198.51.100.3", crypto.RandomString(18))
	}
	if rw := loginRequest(h, "192.0.2.10:8000", "203.0.113.2, 198.51.100.3", password); rw.Code != http.StatusTooManyRequests {
		t.Fatalf("spoofed IP bypassed limit: status=%d", rw.Code)
	}
}

func TestConcurrentLoginBudget(t *testing.T) {
	st, _, _ := securityStore(t)
	h := New(st, Options{MaxFileSize: 4096})
	checked := 0
	for range maxFailures {
		var wg sync.WaitGroup
		results := make(chan int, 12)
		for range cap(results) {
			wg.Go(func() {
				rw := loginRequest(h, "198.51.100.1:8000", "", crypto.RandomString(18))
				results <- rw.Code
			})
		}
		wg.Wait()
		close(results)
		for status := range results {
			switch status {
			case http.StatusOK:
				checked++
			case http.StatusTooManyRequests:
			default:
				t.Fatalf("unexpected login status=%d", status)
			}
		}
	}
	if checked != maxFailures {
		t.Fatalf("checked %d passwords, want %d", checked, maxFailures)
	}
}

func TestSuccessfulLoginDoesNotResetFailureBudget(t *testing.T) {
	st, _, password := securityStore(t)
	h := New(st, Options{MaxFileSize: 4096})
	for range maxFailures - 1 {
		loginRequest(h, "198.51.100.1:8000", "", crypto.RandomString(18))
	}
	if rw := loginRequest(h, "198.51.100.1:8000", "", password); rw.Code != http.StatusSeeOther {
		t.Fatalf("valid login: status=%d", rw.Code)
	}
	loginRequest(h, "198.51.100.1:8000", "", crypto.RandomString(18))
	if rw := loginRequest(h, "198.51.100.1:8000", "", password); rw.Code != http.StatusTooManyRequests {
		t.Fatalf("successful login cleared failure budget: status=%d", rw.Code)
	}
}

func TestPasswordResetInvalidatesExistingSessions(t *testing.T) {
	st, path, password := securityStore(t)
	h := New(st, Options{MaxFileSize: 4096})
	b := &browser{h: h}
	b.signIn(t, "/login", "owner", password)
	// A separate store connection exercises the running-server/CLI boundary.
	other, err := store.Open(path, crypto.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	newPassword := crypto.RandomString(18)
	if err := other.SetAdminPassword(newPassword); err != nil {
		t.Fatal(err)
	}
	if rw := b.request(http.MethodGet, "/users", nil); rw.Code != http.StatusSeeOther || !strings.HasPrefix(rw.Header().Get("Location"), "/login") {
		t.Fatalf("old session survived reset: status=%d", rw.Code)
	}
	fresh := &browser{h: h}
	fresh.signIn(t, "/login", "owner", newPassword)
	if rw := fresh.request(http.MethodGet, "/users", nil); rw.Code != http.StatusOK {
		t.Fatalf("new session after reset: status=%d", rw.Code)
	}
}

func TestBrowserCrossOriginProtection(t *testing.T) {
	st, _, password := securityStore(t)
	h := New(st, Options{MaxFileSize: 4096})
	for _, headers := range []map[string]string{
		{"Origin": "https://other.example"},
		{"Sec-Fetch-Site": "cross-site"},
		{"Origin": "https://other.cfg.example", "Sec-Fetch-Site": "same-site"},
	} {
		r := httptest.NewRequest(http.MethodPost, "http://cfg.example/login", strings.NewReader(url.Values{
			"username": {"owner"}, "password": {password},
		}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for name, value := range headers {
			r.Header.Set(name, value)
		}
		rw := httptest.NewRecorder()
		h.ServeHTTP(rw, r)
		if rw.Code != http.StatusForbidden || len(rw.Result().Cookies()) != 0 {
			t.Fatalf("cross-origin login: status=%d", rw.Code)
		}
	}
	empty, err := store.Open(filepath.Join(t.TempDir(), "empty.db"), crypto.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	defer empty.Close()
	r := httptest.NewRequest(http.MethodPost, "http://cfg.example/register", strings.NewReader(url.Values{
		"username": {"owner"}, "password": {password},
	}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://other.example")
	rw := httptest.NewRecorder()
	New(empty, Options{}).ServeHTTP(rw, r)
	if open, err := empty.RegistrationOpen(); rw.Code != http.StatusForbidden || err != nil || !open {
		t.Fatalf("cross-origin registration: status=%d open=%v err=%v", rw.Code, open, err)
	}
}

func TestSensitiveResponsesDisableCaching(t *testing.T) {
	st, _, password := securityStore(t)
	h := New(st, Options{MaxFileSize: 4096})
	b := &browser{h: h}
	b.signIn(t, "/login", "owner", password)
	for _, path := range []string{"/", "/tokens", "/users"} {
		rw := b.request(http.MethodGet, path, nil)
		if rw.Code != http.StatusOK || rw.Header().Get("Cache-Control") != "no-store" || !strings.Contains(rw.Body.String(), `hx-history="false"`) {
			t.Fatalf("sensitive page %s: status=%d cache=%q", path, rw.Code, rw.Header().Get("Cache-Control"))
		}
	}
}
