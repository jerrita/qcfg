package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jerrita/qcfg/internal/crypto"
)

func TestConcurrentPasswordChanges(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"), crypto.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	password := crypto.RandomString(18)
	u, err := s.RegisterAdmin("owner", password)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Go(func() {
			errs <- s.ChangeUserPassword(u.ID, u.AuthVersion, password, crypto.RandomString(18))
		})
	}
	wg.Wait()
	close(errs)
	var changed, denied int
	for err := range errs {
		switch {
		case err == nil:
			changed++
		case errors.Is(err, ErrDenied):
			denied++
		default:
			t.Fatal(err)
		}
	}
	if changed != 1 || denied != 1 {
		t.Fatalf("changed=%d denied=%d", changed, denied)
	}
	updated, err := s.GetUser(u.ID)
	if err != nil || updated.AuthVersion != u.AuthVersion+1 {
		t.Fatalf("password version: got=%d err=%v", updated.AuthVersion, err)
	}
}

func TestRegistrationClosesAtomically(t *testing.T) {
	path, key := filepath.Join(t.TempDir(), "test.db"), crypto.RandomBytes(32)
	s, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	other, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if open, err := s.RegistrationOpen(); err != nil || !open {
		t.Fatalf("initial registration: open=%v err=%v", open, err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i, st := range []*Store{s, other} {
		wg.Go(func() {
			_, err := st.RegisterAdmin([]string{"owner-a", "owner-b"}[i], crypto.RandomString(18))
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	var created, denied int
	for err := range errs {
		if err == nil {
			created++
		} else if errors.Is(err, ErrDenied) {
			denied++
		} else {
			t.Fatal(err)
		}
	}
	if created != 1 || denied != 1 {
		t.Fatalf("created=%d denied=%d", created, denied)
	}
	if open, err := s.RegistrationOpen(); err != nil || open {
		t.Fatalf("registration after signup: open=%v err=%v", open, err)
	}
	users, err := s.ListUsers()
	if err != nil || len(users) != 1 || !users[0].Admin {
		t.Fatalf("first user: %+v err=%v", users, err)
	}
}

func TestUserAccessCapsTokensAndDevices(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "test.db"), crypto.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	admin, err := s.RegisterAdmin("owner", crypto.RandomString(18))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alpha", "beta"} {
		if err := s.CreateProject(name, ""); err != nil {
			t.Fatal(err)
		}
	}
	password := crypto.RandomString(18)
	if err := s.CreateUser(admin.ID, "member", password, false, []string{"alpha"}); err != nil {
		t.Fatal(err)
	}
	u, err := s.AuthenticateUser("member", password)
	if err != nil || u.Admin || !u.CanAccess("alpha") || u.CanAccess("beta") {
		t.Fatalf("user access: %+v err=%v", u, err)
	}
	if _, err := s.AuthenticateUser("member", crypto.RandomString(18)); !errors.Is(err, ErrDenied) {
		t.Fatalf("wrong password: %v", err)
	}
	if err := s.CreateUser(u.ID, "intruder", password, true, nil); !errors.Is(err, ErrDenied) {
		t.Fatalf("non-admin creating user: %v", err)
	}
	if err := s.SetUserAccess(u.ID, u.ID, true, nil); !errors.Is(err, ErrDenied) {
		t.Fatalf("self escalation: %v", err)
	}
	if _, err := s.CreatePAT(u.ID, "wide", true, nil); !errors.Is(err, ErrDenied) {
		t.Fatalf("unrestricted token: %v", err)
	}
	if _, err := s.CreatePAT(u.ID, "foreign", false, []string{"beta"}); !errors.Is(err, ErrDenied) {
		t.Fatalf("foreign project token: %v", err)
	}
	token, err := s.CreatePAT(u.ID, "build", false, []string{"alpha"})
	if err != nil {
		t.Fatal(err)
	}
	code, userCode, err := s.CreateDeviceRequest("workstation", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ApproveDeviceRequest(u.ID, userCode, "workstation", false, []string{"beta"}); !errors.Is(err, ErrDenied) {
		t.Fatalf("foreign device grant: %v", err)
	}
	if err := s.ApproveDeviceRequest(u.ID, userCode, "workstation", false, []string{"alpha"}); err != nil {
		t.Fatal(err)
	}
	// Access revoked between approval and polling also caps the claimed token.
	if err := s.SetUserAccess(admin.ID, u.ID, false, nil); err != nil {
		t.Fatal(err)
	}
	deviceToken, _, err := s.ClaimDeviceToken(code)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{token, deviceToken} {
		p, err := s.Authenticate(secret, "127.0.0.1")
		if err != nil || p.User.ID != u.ID || p.CanAccess("alpha") || p.CanAccess("beta") {
			t.Fatalf("revoked user grant: %+v err=%v", p, err)
		}
	}
	if err := s.SetUserAccess(admin.ID, u.ID, true, nil); err != nil {
		t.Fatal(err)
	}
	allToken, err := s.CreatePAT(u.ID, "all", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserAccess(admin.ID, u.ID, false, []string{"beta"}); err != nil {
		t.Fatal(err)
	}
	p, err := s.Authenticate(allToken, "127.0.0.1")
	if err != nil || p.CanAccess("alpha") || !p.CanAccess("beta") {
		t.Fatalf("all token after narrowing: %+v err=%v", p, err)
	}
}

func TestMigrateAdmin(t *testing.T) {
	path, key := filepath.Join(t.TempDir(), "legacy.db"), crypto.RandomBytes(32)
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	legacySchema := schema[strings.Index(schema, "CREATE TABLE IF NOT EXISTS project ("):]
	if _, err := db.Exec(legacySchema); err != nil {
		t.Fatal(err)
	}
	password, token := crypto.RandomString(18), crypto.NewToken()
	if _, err := db.Exec(`INSERT INTO setting(key, value) VALUES('admin_password', ?)`, crypto.HashPassword(password)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO device(name, token_hash, created_at, all_projects)
		VALUES('legacy', ?, ?, 1)`, crypto.HashToken(token), now()); err != nil {
		t.Fatal(err)
	}
	pat := crypto.NewPAT()
	if _, err := db.Exec(`INSERT INTO device(name, token_hash, created_at, all_projects, kind)
		VALUES('legacy-pat', ?, ?, 1, 'pat')`, crypto.HashToken(pat), now()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO project(name, description, created_at, updated_at) VALUES('archive', 'preserved', ?, ?)`, now(), now()); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.AuthenticateUser("admin", password)
	if err != nil || !u.Admin {
		t.Fatalf("migrated admin: %+v err=%v", u, err)
	}
	p, err := s.Authenticate(token, "127.0.0.1")
	if err != nil || p.User.ID != u.ID || !p.CanAccess("archive") {
		t.Fatalf("migrated device: %+v err=%v", p, err)
	}
	if p, err := s.Authenticate(pat, "127.0.0.1"); err != nil || p.User.ID != u.ID || !p.CanAccess("archive") {
		t.Fatalf("migrated PAT: %+v err=%v", p, err)
	}
	if d, err := s.GetPAT("legacy-pat"); err != nil || d.UserID != u.ID {
		t.Fatalf("migrated PAT ownership: %+v err=%v", d, err)
	}
	if p, err := s.GetProject("archive"); err != nil || p.Description != "preserved" {
		t.Fatalf("migrated project: %+v err=%v", p, err)
	}
	if _, err := s.Setting("admin_password"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("legacy password setting: %v", err)
	}
	if err := s.SetAdminName(u.ID, "renamed-owner"); err != nil {
		t.Fatal(err)
	}
	password = crypto.RandomString(18)
	if err := s.SetAdminPassword(password); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	users, err := s.ListUsers()
	if err != nil || len(users) != 1 || users[0].Name != "renamed-owner" || users[0].ID != u.ID {
		t.Fatalf("repeated migration: %+v err=%v", users, err)
	}
	if _, err := s.AuthenticateUser("admin", password); !errors.Is(err, ErrNotFound) {
		t.Fatalf("previous username after restart: %v", err)
	}
	if renamed, err := s.AuthenticateUser("renamed-owner", password); err != nil || !renamed.Admin || renamed.ID != u.ID {
		t.Fatalf("renamed administrator after restart: %+v err=%v", renamed, err)
	}
	if p, err := s.Authenticate(pat, "127.0.0.1"); err != nil || p.User.Name != "renamed-owner" {
		t.Fatalf("PAT after username change: %+v err=%v", p, err)
	}
}

func TestMigrateUserAuthVersion(t *testing.T) {
	path, key := filepath.Join(t.TempDir(), "users.db"), crypto.RandomBytes(32)
	s, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	password := crypto.RandomString(18)
	owner, err := s.RegisterAdmin("owner", password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`ALTER TABLE user DROP COLUMN auth_version`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	u, err := s.AuthenticateUser("owner", password)
	if err != nil || u.ID != owner.ID || u.AuthVersion != 1 {
		t.Fatalf("migrated user: %+v err=%v", u, err)
	}
	newPassword := crypto.RandomString(18)
	if err := s.SetAdminPassword(newPassword); err != nil {
		t.Fatal(err)
	}
	u, err = s.AuthenticateUser("owner", newPassword)
	if err != nil || u.AuthVersion != 2 {
		t.Fatalf("password version: %+v err=%v", u, err)
	}
	if _, err := s.AuthenticateUser("owner", password); !errors.Is(err, ErrDenied) {
		t.Fatalf("old password after reset: %v", err)
	}
}
