// Package store persists projects, files, versions and devices in SQLite.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
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
	ErrLimit    = errors.New("too many requests")
	ErrPending  = errors.New("authorization pending")
	ErrDenied   = errors.New("access denied")
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
CREATE TABLE IF NOT EXISTS user (
	id INTEGER PRIMARY KEY,
	name TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	auth_version INTEGER NOT NULL DEFAULT 1,
	admin INTEGER NOT NULL DEFAULT 0,
	all_projects INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS user_project (
	user_id INTEGER NOT NULL REFERENCES user(id) ON DELETE CASCADE,
	project_id INTEGER NOT NULL REFERENCES project(id) ON DELETE CASCADE,
	PRIMARY KEY(user_id, project_id)
);
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
	revoked      INTEGER NOT NULL DEFAULT 0,
	all_projects INTEGER NOT NULL DEFAULT 0,
	kind         TEXT NOT NULL DEFAULT 'device'
);
CREATE TABLE IF NOT EXISTS pat_secret (
	device_id  INTEGER PRIMARY KEY REFERENCES device(id) ON DELETE CASCADE,
	nonce      BLOB NOT NULL,
	ciphertext BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS device_project (
	device_id  INTEGER NOT NULL REFERENCES device(id) ON DELETE CASCADE,
	project_id INTEGER NOT NULL REFERENCES project(id) ON DELETE CASCADE,
	PRIMARY KEY(device_id, project_id)
);
CREATE TABLE IF NOT EXISTS device_request (
	id            INTEGER PRIMARY KEY,
	code_hash     TEXT NOT NULL UNIQUE,
	user_code     TEXT NOT NULL UNIQUE,
	name          TEXT NOT NULL,
	ip            TEXT NOT NULL,
	status        TEXT NOT NULL DEFAULT 'pending',
	all_projects  INTEGER NOT NULL DEFAULT 0,
	projects_json TEXT NOT NULL DEFAULT '[]',
	created_at    INTEGER NOT NULL,
	expires_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS setting (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS activity (
	id INTEGER PRIMARY KEY,
	user_id INTEGER NOT NULL,
	user_name TEXT NOT NULL,
	source TEXT NOT NULL,
	method TEXT NOT NULL,
	path TEXT NOT NULL,
	status INTEGER NOT NULL,
	created_at INTEGER NOT NULL
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
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db, key: key}, nil
}

// migrate adds columns introduced after the initial schema to databases
// created by older versions; fresh databases get them from the schema.
func migrate(db *sql.DB) error {
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('user') WHERE name='auth_version'`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := db.Exec(`ALTER TABLE user ADD COLUMN auth_version INTEGER NOT NULL DEFAULT 1`); err != nil {
			return err
		}
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('device') WHERE name='kind'`).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		if _, err := db.Exec(`ALTER TABLE device ADD COLUMN kind TEXT NOT NULL DEFAULT 'device'`); err != nil {
			return err
		}
	}
	for _, table := range []string{"device", "device_request"} {
		if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name='user_id'`, table).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			if _, err := db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN user_id INTEGER REFERENCES user(id)`); err != nil {
				return err
			}
		}
	}
	return migrateAdmin(db)
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

type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

func grantProjects(db execer, deviceID int64, projects []string) error {
	for _, p := range projects {
		if _, err := db.Exec(`INSERT OR IGNORE INTO device_project(device_id, project_id)
			SELECT ?, id FROM project WHERE name=?`, deviceID, p); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) deviceProjects(id int64) ([]string, error) {
	rows, err := s.db.Query(`SELECT p.name FROM device_project dp JOIN project p ON p.id=dp.project_id
		WHERE dp.device_id=? ORDER BY p.name`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *Store) devices(where string, args ...any) ([]model.Device, error) {
	rows, err := s.db.Query(`SELECT id, name, created_at, last_seen_at, last_ip, revoked, all_projects, COALESCE(user_id, 0) FROM device `+
		where+` ORDER BY name`, args...)
	if err != nil {
		return nil, err
	}
	out := []model.Device{}
	var ids []int64
	for rows.Next() {
		var d model.Device
		var id, c, l int64
		if err := rows.Scan(&id, &d.Name, &c, &l, &d.LastIP, &d.Revoked, &d.AllProjects, &d.UserID); err != nil {
			rows.Close()
			return nil, err
		}
		d.CreatedAt, d.LastSeenAt = unix(c), unix(l)
		out = append(out, d)
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if !out[i].AllProjects {
			if out[i].Projects, err = s.deviceProjects(ids[i]); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// Kind distinguishes login devices from personal access tokens.
const (
	kindDevice = "device"
	kindPAT    = "pat"
)

func (s *Store) ListDevices() ([]model.Device, error) { return s.devices(`WHERE kind='device'`) }

func (s *Store) ListPATs() ([]model.Device, error) { return s.devices(`WHERE kind='pat'`) }

func (s *Store) getByKind(kind, name string) (model.Device, error) {
	ds, err := s.devices(`WHERE kind=? AND name=?`, kind, name)
	if err != nil {
		return model.Device{}, err
	}
	if len(ds) == 0 {
		return model.Device{}, ErrNotFound
	}
	return ds[0], nil
}

func (s *Store) GetDevice(name string) (model.Device, error) { return s.getByKind(kindDevice, name) }

func (s *Store) GetPAT(name string) (model.Device, error) { return s.getByKind(kindPAT, name) }

func (s *Store) PATSecret(name string) (string, error) {
	var nonce, ciphertext []byte
	err := s.db.QueryRow(`SELECT s.nonce, s.ciphertext FROM pat_secret s
		JOIN device d ON d.id=s.device_id WHERE d.name=? AND d.kind='pat' AND d.revoked=0`, name).
		Scan(&nonce, &ciphertext)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	plaintext, err := crypto.Open(s.key, nonce, ciphertext)
	return string(plaintext), err
}

// Principal is an authenticated device and the projects it may access.
type Principal struct {
	ID          int64
	User        model.User
	Name        string
	AllProjects bool
	Projects    []string
}

func (p *Principal) CanAccess(project string) bool {
	return p.AllProjects || slices.Contains(p.Projects, project)
}

// Authenticate resolves a token to a device and records the access.
func (s *Store) Authenticate(token, ip string) (*Principal, error) {
	p := &Principal{}
	var userID int64
	err := s.db.QueryRow(`SELECT id, name, all_projects, COALESCE(user_id, 0) FROM device WHERE token_hash=? AND revoked=0`, crypto.HashToken(token)).
		Scan(&p.ID, &p.Name, &p.AllProjects, &userID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.User, err = s.GetUser(userID)
	if err != nil {
		return nil, err
	}
	if _, err := s.db.Exec(`UPDATE device SET last_seen_at=?, last_ip=? WHERE id=?`, now(), ip, p.ID); err != nil {
		return nil, err
	}
	if !p.AllProjects {
		if p.Projects, err = s.deviceProjects(p.ID); err != nil {
			return nil, err
		}
	}
	if !p.User.Admin && !p.User.AllProjects {
		if p.AllProjects {
			p.Projects = p.User.Projects
		} else {
			p.Projects = slices.DeleteFunc(p.Projects, func(name string) bool { return !p.User.CanAccess(name) })
		}
		p.AllProjects = false
	}
	return p, nil
}

// GrantProject adds project to the projects a device may access.
func (s *Store) GrantProject(deviceID int64, project string) error {
	return grantProjects(s.db, deviceID, []string{project})
}

// CreatePAT creates a personal access token and stores its secret encrypted.
func (s *Store) CreatePAT(userID int64, name string, all bool, projects []string) (string, error) {
	if err := s.validateAccess(userID, all, projects); err != nil {
		return "", err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	token := crypto.NewPAT()
	nonce, ciphertext, err := crypto.Seal(s.key, []byte(token))
	if err != nil {
		return "", err
	}
	res, err := tx.Exec(`INSERT INTO device(name, token_hash, created_at, all_projects, kind, user_id)
		VALUES(?,?,?,?,?,?)`, name, crypto.HashToken(token), now(), all, kindPAT, userID)
	if isUnique(err) {
		return "", ErrExists
	}
	if err != nil {
		return "", err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return "", err
	}
	if _, err := tx.Exec(`INSERT INTO pat_secret(device_id, nonce, ciphertext) VALUES(?,?,?)`, id, nonce, ciphertext); err != nil {
		return "", err
	}
	if !all {
		if err := grantProjects(tx, id, projects); err != nil {
			return "", err
		}
	}
	return token, tx.Commit()
}

func (s *Store) setAccess(kind, name string, all bool, projects []string) error {
	d, err := s.getByKind(kind, name)
	if err != nil {
		return err
	}
	if err := s.validateAccess(d.UserID, all, projects); err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var id int64
	err = tx.QueryRow(`SELECT id FROM device WHERE name=? AND kind=?`, name, kind).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE device SET all_projects=? WHERE id=?`, all, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM device_project WHERE device_id=?`, id); err != nil {
		return err
	}
	if !all {
		if err := grantProjects(tx, id, projects); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SetDeviceAccess replaces the projects a device may access.
func (s *Store) SetDeviceAccess(name string, all bool, projects []string) error {
	return s.setAccess(kindDevice, name, all, projects)
}

// SetPATAccess replaces the projects a personal access token may access.
func (s *Store) SetPATAccess(name string, all bool, projects []string) error {
	return s.setAccess(kindPAT, name, all, projects)
}

func (s *Store) revokeByKind(kind, name string) error {
	return affected(s.db.Exec(`UPDATE device SET revoked=1 WHERE name=? AND kind=?`, name, kind))
}

func (s *Store) RevokeDevice(name string) error { return s.revokeByKind(kindDevice, name) }

func (s *Store) RevokePAT(name string) error { return s.revokeByKind(kindPAT, name) }

func (s *Store) deleteByKind(kind, name string) error {
	return affected(s.db.Exec(`DELETE FROM device WHERE name=? AND kind=?`, name, kind))
}

func (s *Store) DeleteDevice(name string) error { return s.deleteByKind(kindDevice, name) }

func (s *Store) DeletePAT(name string) error { return s.deleteByKind(kindPAT, name) }

// ---- device authorization ----

const (
	DeviceCodeTTL      = 10 * time.Minute
	maxPendingRequests = 3 // per client IP
)

// DeviceRequest is a pending device authorization.
type DeviceRequest struct {
	UserCode  string
	Name      string
	IP        string
	ExpiresAt time.Time
}

// CreateDeviceRequest starts a device authorization for a device named name
// and returns the secret device code and the user code entered in the WebUI.
func (s *Store) CreateDeviceRequest(name, ip string) (deviceCode, userCode string, err error) {
	t := now()
	if _, err := s.db.Exec(`DELETE FROM device_request WHERE expires_at<=?`, t); err != nil {
		return "", "", err
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM device_request WHERE ip=?`, ip).Scan(&n); err != nil {
		return "", "", err
	}
	if n >= maxPendingRequests {
		return "", "", ErrLimit
	}
	deviceCode = crypto.RandomString(32)
	for range 3 {
		userCode = crypto.NewUserCode()
		_, err = s.db.Exec(`INSERT INTO device_request(code_hash, user_code, name, ip, created_at, expires_at)
			VALUES(?,?,?,?,?,?)`, crypto.HashToken(deviceCode), userCode, name, ip, t, t+int64(DeviceCodeTTL.Seconds()))
		if !isUnique(err) {
			break
		}
	}
	return deviceCode, userCode, err
}

// PendingDeviceRequest returns the unexpired pending request for userCode.
func (s *Store) PendingDeviceRequest(userCode string) (DeviceRequest, error) {
	var r DeviceRequest
	var exp int64
	err := s.db.QueryRow(`SELECT user_code, name, ip, expires_at FROM device_request
		WHERE user_code=? AND status='pending' AND expires_at>?`, userCode, now()).
		Scan(&r.UserCode, &r.Name, &r.IP, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	r.ExpiresAt = unix(exp)
	return r, err
}

// ApproveDeviceRequest approves a pending request; the device is created
// with name and access when it next polls with its device code.
func (s *Store) ApproveDeviceRequest(userID int64, userCode, name string, all bool, projects []string) error {
	if err := s.validateAccess(userID, all, projects); err != nil {
		return err
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM device WHERE name=?`, name).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrExists
	}
	if all || projects == nil {
		projects = []string{}
	}
	pj, _ := json.Marshal(projects)
	return affected(s.db.Exec(`UPDATE device_request SET status='approved', name=?, all_projects=?, projects_json=?, user_id=?
		WHERE user_code=? AND status='pending' AND expires_at>?`, name, all, string(pj), userID, userCode, now()))
}

func (s *Store) DenyDeviceRequest(userCode string) error {
	return affected(s.db.Exec(`UPDATE device_request SET status='denied'
		WHERE user_code=? AND status='pending' AND expires_at>?`, userCode, now()))
}

// ClaimDeviceToken exchanges an approved device code for a new device token.
// It returns ErrPending before approval, ErrDenied after denial and
// ErrNotFound for unknown or expired codes.
func (s *Store) ClaimDeviceToken(deviceCode string) (token, name string, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback()
	var reqID, userID int64
	var status, pj string
	var all bool
	err = tx.QueryRow(`SELECT id, status, name, all_projects, projects_json, COALESCE(user_id, 0) FROM device_request
		WHERE code_hash=? AND expires_at>?`, crypto.HashToken(deviceCode), now()).
		Scan(&reqID, &status, &name, &all, &pj, &userID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", ErrNotFound
	}
	if err != nil {
		return "", "", err
	}
	switch status {
	case "pending":
		return "", "", ErrPending
	case "denied":
		if _, err := tx.Exec(`DELETE FROM device_request WHERE id=?`, reqID); err != nil {
			return "", "", err
		}
		if err := tx.Commit(); err != nil {
			return "", "", err
		}
		return "", "", ErrDenied
	}
	token = crypto.NewToken()
	res, err := tx.Exec(`INSERT INTO device(name, token_hash, created_at, all_projects, kind, user_id) VALUES(?,?,?,?,?,?)`,
		name, crypto.HashToken(token), now(), all, kindDevice, userID)
	if isUnique(err) {
		return "", "", ErrExists
	}
	if err != nil {
		return "", "", err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return "", "", err
	}
	var projects []string
	_ = json.Unmarshal([]byte(pj), &projects)
	if err := grantProjects(tx, id, projects); err != nil {
		return "", "", err
	}
	if _, err := tx.Exec(`DELETE FROM device_request WHERE id=?`, reqID); err != nil {
		return "", "", err
	}
	return token, name, tx.Commit()
}
