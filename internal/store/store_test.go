package store

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/jerrita/qcfg/internal/crypto"
	"github.com/jerrita/qcfg/internal/model"
)

func TestPut(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "t.db"), crypto.RandomBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.KeepVersions = 2
	if err := s.CreateProject("p", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateFile("p", model.File{Name: "f", Path: "~/f"}); err != nil {
		t.Fatal(err)
	}

	for i, c := range []string{"a", "b", "c"} {
		v, created, err := s.Put("p", "f", int64(i), []byte(c), "d", "")
		if err != nil || !created || v.Rev != int64(i+1) {
			t.Fatalf("put %s: rev=%d created=%v err=%v", c, v.Rev, created, err)
		}
	}

	if _, created, err := s.Put("p", "f", 1, []byte("c"), "d", ""); err != nil || created {
		t.Fatalf("same content: created=%v err=%v", created, err)
	}

	var ce *ConflictError
	if _, _, err := s.Put("p", "f", 2, []byte("x"), "d", ""); !errors.As(err, &ce) || ce.HeadRev != 3 {
		t.Fatalf("stale base: err=%v", err)
	}

	vs, err := s.Versions("p", "f")
	if err != nil || len(vs) != 2 || vs[0].Rev != 3 {
		t.Fatalf("versions after prune: %+v err=%v", vs, err)
	}
	data, _, err := s.Content("p", "f", 0)
	if err != nil || string(data) != "c" {
		t.Fatalf("head content %q err=%v", data, err)
	}
	var blobs int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM blob`).Scan(&blobs); err != nil || blobs != 2 {
		t.Fatalf("blobs=%d err=%v", blobs, err)
	}
}
