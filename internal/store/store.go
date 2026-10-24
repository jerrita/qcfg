// Package store persists projects, files, versions and devices in SQLite.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jerrita/qcfg/internal/crypto"
	"github.com/jerrita/qcfg/internal/model"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound = errors.New("not found")
	ErrExists   = errors.New("already exists")
	ErrConflict = errors.New("conflict")
)

// ConflictError carries the current head revision.
type ConflictError struct{ HeadRev int64 }

func (e *ConflictError) Error() string { return fmt.Sprintf("conflict: head is rev %d", e.HeadRev) }
func (e *ConflictError) Unwrap() error { return ErrConflict }

type Store struct {
	db           *sql.DB
	key          []byte
	KeepVersions int // 0 keeps all versions
}

const schema = `
CREATE TABLE IF NOT EXISTS project (
	id          INTEGER PRIMARY KEY,
	name        TEXT NOT NULL UNIQUE,
	description TEXT NOT NULL DEFAULT '',
	created_at  INTEGER NOT NULL,
	updated_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS file (
	id             INTEGER PRIMARY KEY,
	project_id     INTEGER NOT NULL REFERENCES project(id) ON DELETE CASCADE,
	name           TEXT NOT NULL,
	path           TEXT NOT NULL,
	paths_json     TEXT NOT NULL DEFAULT '{}',
	platforms_json TEXT NOT NULL DEFAULT '[]',
	mode           TEXT NOT NULL DEFAULT '',
	head_rev       INTEGER NOT NULL DEFAULT 0,
	deleted        INTEGER NOT NULL DEFAULT 0,
	created_at     INTEGER NOT NULL,
	updated_at     INTEGER NOT NULL,
	UNIQUE(project_id, name)
);
CREATE TABLE IF NOT EXISTS blob (
	id         INTEGER PRIMARY KEY,
	sha256     TEXT NOT NULL UNIQUE,
	nonce      BLOB NOT NULL,
	ciphertext BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS version (
	id         INTEGER PRIMARY KEY,
	file_id    INTEGER NOT NULL REFERENCES file(id) ON DELETE CASCADE,
	rev        INTEGER NOT NULL,
	sha256     TEXT NOT NULL,
	size       INTEGER NOT NULL,
	blob_id    INTEGER NOT NULL REFERENCES blob(id),
	device     TEXT NOT NULL,
	message    TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	UNIQUE(file_id, rev)
);
CREATE TABLE IF NOT EXISTS device (
	id           INTEGER PRIMARY KEY,
	name         TEXT NOT NULL UNIQUE,
	token_hash   TEXT NOT NULL UNIQUE,
	created_at   INTEGER NOT NULL,
	last_seen_at INTEGER NOT NULL DEFAULT 0,
	last_ip      TEXT NOT NULL DEFAULT '',
	revoked      INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS setting (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
`

func Open(path string, key []byte) (*Store, error) {
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db, key: key}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func now() int64 { return time.Now().Unix() }

func unix(t int64) time.Time {
	if t == 0 {
		return time.Time{}
	}
	return time.Unix(t, 0)
}

func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// ---- settings ----

func (s *Store) Setting(key string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM setting WHERE key=?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return v, err
}

func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO setting(key,value) VALUES(?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

// ---- projects ----

func (s *Store) ListProjects() ([]model.Project, error) {
	rows, err := s.db.Query(`SELECT p.name, p.description, p.updated_at,
		(SELECT COUNT(*) FROM file f WHERE f.project_id=p.id AND f.deleted=0)
		FROM project p ORDER BY p.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Project{}
	for rows.Next() {
		var p model.Project
		var up int64
		if err := rows.Scan(&p.Name, &p.Description, &up, &p.FileCount); err != nil {
			return nil, err
		}
		p.UpdatedAt = unix(up)
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) projectID(name string) (int64, error) {
	var id int64
	err := s.db.QueryRow(`SELECT id FROM project WHERE name=?`, name).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return id, err
}

// GetProject returns the project with its live files.
func (s *Store) GetProject(name string) (model.Project, error) {
	var p model.Project
	var id, up int64
	err := s.db.QueryRow(`SELECT id, name, description, updated_at FROM project WHERE name=?`, name).
		Scan(&id, &p.Name, &p.Description, &up)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	if err != nil {
		return p, err
	}
	p.UpdatedAt = unix(up)
	rows, err := s.db.Query(fileSelect+` WHERE f.project_id=? AND f.deleted=0 ORDER BY f.name`, id)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	p.Files = []model.File{}
	for rows.Next() {
		f, err := scanFile(rows)
		if err != nil {
			return p, err
		}
		p.Files = append(p.Files, f)
	}
	p.FileCount = len(p.Files)
	return p, rows.Err()
}

func (s *Store) CreateProject(name, desc string) error {
	t := now()
	_, err := s.db.Exec(`INSERT INTO project(name, description, created_at, updated_at) VALUES(?,?,?,?)`,
		name, desc, t, t)
	if isUnique(err) {
		return ErrExists
	}
	return err
}

func (s *Store) UpdateProject(name, newName, desc string) error {
	res, err := s.db.Exec(`UPDATE project SET name=?, description=?, updated_at=? WHERE name=?`,
		newName, desc, now(), name)
	if isUnique(err) {
		return ErrExists
	}
	return affected(res, err)
}

func (s *Store) DeleteProject(name string) error {
	res, err := s.db.Exec(`DELETE FROM project WHERE name=?`, name)
	if err := affected(res, err); err != nil {
		return err
	}
	return s.gcBlobs()
}

func affected(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- files ----

const fileSelect = `SELECT f.id, f.name, f.path, f.paths_json, f.platforms_json, f.mode, f.head_rev,
	f.updated_at, COALESCE(v.sha256,''), COALESCE(v.size,0), COALESCE(v.device,'')
	FROM file f LEFT JOIN version v ON v.file_id=f.id AND v.rev=f.head_rev`

type scanner interface{ Scan(...any) error }

func scanFile(r scanner) (model.File, error) {
	var f model.File
	var id, up int64
	var paths, plats string
	err := r.Scan(&id, &f.Name, &f.Path, &paths, &plats, &f.Mode, &f.HeadRev, &up,
		&f.Sha256, &f.Size, &f.UpdatedBy)
	if err != nil {
		return f, err
	}
	f.UpdatedAt = unix(up)
	_ = json.Unmarshal([]byte(paths), &f.Paths)
	_ = json.Unmarshal([]byte(plats), &f.Platforms)
	if len(f.Paths) == 0 {
		f.Paths = nil
	}
	return f, nil
}

func (s *Store) fileID(project, name string) (int64, int64, error) {
	var id, head int64
	err := s.db.QueryRow(`SELECT f.id, f.head_rev FROM file f JOIN project p ON p.id=f.project_id
		WHERE p.name=? AND f.name=? AND f.deleted=0`, project, name).Scan(&id, &head)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, ErrNotFound
	}
	return id, head, err
}

func (s *Store) GetFile(project, name string) (model.File, error) {
	f, err := scanFile(s.db.QueryRow(fileSelect+` JOIN project p ON p.id=f.project_id
		WHERE p.name=? AND f.name=? AND f.deleted=0`, project, name))
	if errors.Is(err, sql.ErrNoRows) {
		return f, ErrNotFound
	}
	return f, err
}

func encodeDef(f model.File) (string, string) {
	paths, plats := f.Paths, f.Platforms
	if paths == nil {
		paths = map[string]string{}
	}
	if plats == nil {
		plats = []string{}
	}
	pj, _ := json.Marshal(paths)
	lj, _ := json.Marshal(plats)
	return string(pj), string(lj)
}

// CreateFile adds a file definition. A previously deleted file with the same
// name is revived with the new definition and keeps its history.
func (s *Store) CreateFile(project string, f model.File) error {
	pid, err := s.projectID(project)
	if err != nil {
		return err
	}
	pj, lj := encodeDef(f)
	t := now()
	res, err := s.db.Exec(`UPDATE file SET path=?, paths_json=?, platforms_json=?, mode=?, deleted=0, updated_at=?
		WHERE project_id=? AND name=? AND deleted=1`, f.Path, pj, lj, f.Mode, t, pid, f.Name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		_, err = s.db.Exec(`INSERT INTO file(project_id, name, path, paths_json, platforms_json, mode, created_at, updated_at)
			VALUES(?,?,?,?,?,?,?,?)`, pid, f.Name, f.Path, pj, lj, f.Mode, t, t)
		if isUnique(err) {
			return ErrExists
		}
		if err != nil {
			return err
		}
	}
	return s.touchProject(pid)
}

// UpdateFile replaces the definition (path, paths, platforms, mode) of a file.
func (s *Store) UpdateFile(project, name string, f model.File) error {
	id, _, err := s.fileID(project, name)
	if err != nil {
		return err
	}
	pj, lj := encodeDef(f)
	_, err = s.db.Exec(`UPDATE file SET path=?, paths_json=?, platforms_json=?, mode=?, updated_at=? WHERE id=?`,
		f.Path, pj, lj, f.Mode, now(), id)
	return err
}

func (s *Store) DeleteFile(project, name string) error {
	id, _, err := s.fileID(project, name)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`UPDATE file SET deleted=1, updated_at=? WHERE id=?`, now(), id)
	return err
}

func (s *Store) touchProject(pid int64) error {
	_, err := s.db.Exec(`UPDATE project SET updated_at=? WHERE id=?`, now(), pid)
	return err
}

// ---- versions ----

// Content returns the content of rev (0 means head).
func (s *Store) Content(project, name string, rev int64) ([]byte, model.Version, error) {
	var v model.Version
	id, head, err := s.fileID(project, name)
	if err != nil {
		return nil, v, err
	}
	if rev == 0 {
		rev = head
	}
	var nonce, ct []byte
	var created int64
	err = s.db.QueryRow(`SELECT v.rev, v.sha256, v.size, v.device, v.message, v.created_at, b.nonce, b.ciphertext
		FROM version v JOIN blob b ON b.id=v.blob_id WHERE v.file_id=? AND v.rev=?`, id, rev).
		Scan(&v.Rev, &v.Sha256, &v.Size, &v.Device, &v.Message, &created, &nonce, &ct)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, v, ErrNotFound
	}
	if err != nil {
		return nil, v, err
	}
	v.CreatedAt = unix(created)
	data, err := crypto.Open(s.key, nonce, ct)
	if err != nil {
		return nil, v, fmt.Errorf("decrypt blob: %w", err)
	}
	return data, v, nil
}

// Put stores content as a new head version if baseRev matches the current
// head. created is false when content equals the head and nothing changed.
func (s *Store) Put(project, name string, baseRev int64, content []byte, device, message string) (v model.Version, created bool, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return v, false, err
	}
	defer tx.Rollback()

	var id, pid, head int64
	err = tx.QueryRow(`SELECT f.id, f.project_id, f.head_rev FROM file f JOIN project p ON p.id=f.project_id
		WHERE p.name=? AND f.name=? AND f.deleted=0`, project, name).Scan(&id, &pid, &head)
	if errors.Is(err, sql.ErrNoRows) {
		return v, false, ErrNotFound
	}
	if err != nil {
		return v, false, err
	}

	sum := crypto.Sha256Hex(content)
	if head > 0 {
		var headSum string
		var created int64
		if err := tx.QueryRow(`SELECT sha256, size, device, message, created_at FROM version WHERE file_id=? AND rev=?`, id, head).
			Scan(&headSum, &v.Size, &v.Device, &v.Message, &created); err != nil {
			return v, false, err
		}
		if headSum == sum {
			v.Rev, v.Sha256, v.CreatedAt = head, headSum, unix(created)
			return v, false, nil
		}
	}
	if baseRev != head {
		return v, false, &ConflictError{HeadRev: head}
	}

	blobID, err := s.putBlob(tx, sum, content)
	if err != nil {
		return v, false, err
	}
	t := now()
	v = model.Version{Rev: head + 1, Sha256: sum, Size: int64(len(content)), Device: device, Message: message, CreatedAt: unix(t)}
	if _, err := tx.Exec(`INSERT INTO version(file_id, rev, sha256, size, blob_id, device, message, created_at)
		VALUES(?,?,?,?,?,?,?,?)`, id, v.Rev, sum, v.Size, blobID, device, message, t); err != nil {
		return v, false, err
	}
	if _, err := tx.Exec(`UPDATE file SET head_rev=?, updated_at=? WHERE id=?`, v.Rev, t, id); err != nil {
		return v, false, err
	}
	if _, err := tx.Exec(`UPDATE project SET updated_at=? WHERE id=?`, t, pid); err != nil {
		return v, false, err
	}
	pruned := false
	if s.KeepVersions > 0 {
		res, err := tx.Exec(`DELETE FROM version WHERE file_id=? AND rev<=?`, id, v.Rev-int64(s.KeepVersions))
		if err != nil {
			return v, false, err
		}
		n, _ := res.RowsAffected()
		pruned = n > 0
	}
	if err := tx.Commit(); err != nil {
		return v, false, err
	}
	if pruned {
		if err := s.gcBlobs(); err != nil {
			return v, true, err
		}
	}
	return v, true, nil
}

func (s *Store) putBlob(tx *sql.Tx, sum string, content []byte) (int64, error) {
	var id int64
	err := tx.QueryRow(`SELECT id FROM blob WHERE sha256=?`, sum).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	nonce, ct, err := crypto.Seal(s.key, content)
	if err != nil {
		return 0, err
	}
	res, err := tx.Exec(`INSERT INTO blob(sha256, nonce, ciphertext) VALUES(?,?,?)`, sum, nonce, ct)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) gcBlobs() error {
	_, err := s.db.Exec(`DELETE FROM blob WHERE id NOT IN (SELECT blob_id FROM version)`)
	return err
}

func (s *Store) Versions(project, name string) ([]model.Version, error) {
	id, _, err := s.fileID(project, name)
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT rev, sha256, size, device, message, created_at FROM version
		WHERE file_id=? ORDER BY rev DESC`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Version{}
	for rows.Next() {
		var v model.Version
		var created int64
		if err := rows.Scan(&v.Rev, &v.Sha256, &v.Size, &v.Device, &v.Message, &created); err != nil {
			return nil, err
		}
		v.CreatedAt = unix(created)
		out = append(out, v)
	}
	return out, rows.Err()
}

// Restore makes the content of rev the new head.
func (s *Store) Restore(project, name string, rev int64, device string) (model.Version, error) {
	data, _, err := s.Content(project, name, rev)
	if err != nil {
		return model.Version{}, err
	}
	_, head, err := s.fileID(project, name)
	if err != nil {
		return model.Version{}, err
	}
	v, _, err := s.Put(project, name, head, data, device, fmt.Sprintf("restore rev %d", rev))
	return v, err
}

// ---- devices ----

// CreateDevice registers a device and returns its token.
func (s *Store) CreateDevice(name string) (string, error) {
	token := crypto.NewToken()
	_, err := s.db.Exec(`INSERT INTO device(name, token_hash, created_at) VALUES(?,?,?)`,
		name, crypto.HashToken(token), now())
	if isUnique(err) {
		return "", ErrExists
	}
	return token, err
}

func (s *Store) ListDevices() ([]model.Device, error) {
	rows, err := s.db.Query(`SELECT name, created_at, last_seen_at, last_ip, revoked FROM device ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []model.Device{}
	for rows.Next() {
		var d model.Device
		var c, l int64
		if err := rows.Scan(&d.Name, &c, &l, &d.LastIP, &d.Revoked); err != nil {
			return nil, err
		}
		d.CreatedAt, d.LastSeenAt = unix(c), unix(l)
		out = append(out, d)
	}
	return out, rows.Err()
}

// Authenticate resolves a token to a device name and records the access.
func (s *Store) Authenticate(token, ip string) (string, error) {
	var id int64
	var name string
	err := s.db.QueryRow(`SELECT id, name FROM device WHERE token_hash=? AND revoked=0`, crypto.HashToken(token)).
		Scan(&id, &name)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	_, err = s.db.Exec(`UPDATE device SET last_seen_at=?, last_ip=? WHERE id=?`, now(), ip, id)
	return name, err
}

func (s *Store) RevokeDevice(name string) error {
	return affected(s.db.Exec(`UPDATE device SET revoked=1 WHERE name=?`, name))
}

func (s *Store) DeleteDevice(name string) error {
	return affected(s.db.Exec(`DELETE FROM device WHERE name=?`, name))
}
