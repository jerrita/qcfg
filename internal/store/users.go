package store

import (
	"database/sql"
	"errors"

	"github.com/jerrita/qcfg/internal/crypto"
	"github.com/jerrita/qcfg/internal/model"
)

func migrateAdmin(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO user(name, password_hash, admin, created_at)
		SELECT 'admin', value, 1, ? FROM setting WHERE key='admin_password'
		AND NOT EXISTS (SELECT 1 FROM user)`, now()); err != nil {
		return err
	}
	for _, table := range []string{"device", "device_request"} {
		if _, err := tx.Exec(`UPDATE ` + table + ` SET user_id=(SELECT id FROM user WHERE admin=1 ORDER BY id LIMIT 1)
			WHERE user_id IS NULL`); err != nil {
			return err
		}
	}
	if _, err := tx.Exec(`DELETE FROM setting WHERE key='admin_password' AND EXISTS (SELECT 1 FROM user)`); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RegistrationOpen() (bool, error) {
	var open bool
	err := s.db.QueryRow(`SELECT NOT EXISTS (SELECT 1 FROM user)`).Scan(&open)
	return open, err
}

func validateUser(name, password string) error {
	if !model.ValidName(name) {
		return errors.New("invalid username")
	}
	if len(password) < 8 || len(password) > 1024 {
		return errors.New("password must be between 8 and 1024 characters")
	}
	return nil
}

// RegisterAdmin atomically creates the first user and closes registration.
func (s *Store) RegisterAdmin(name, password string) (model.User, error) {
	if err := validateUser(name, password); err != nil {
		return model.User{}, err
	}
	hash := crypto.HashPassword(password)
	res, err := s.db.Exec(`INSERT INTO user(name, password_hash, admin, created_at)
		SELECT ?, ?, 1, ? WHERE NOT EXISTS (SELECT 1 FROM user)`, name, hash, now())
	if err != nil {
		return model.User{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return model.User{}, err
	}
	if n == 0 {
		return model.User{}, ErrDenied
	}
	id, err := res.LastInsertId()
	if err != nil {
		return model.User{}, err
	}
	return s.GetUser(id)
}

func (s *Store) CreateUser(adminID int64, name, password string, all bool, projects []string) error {
	if err := validateUser(name, password); err != nil {
		return err
	}
	hash := crypto.HashPassword(password)
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var admin bool
	if err := tx.QueryRow(`SELECT admin FROM user WHERE id=?`, adminID).Scan(&admin); err != nil || !admin {
		return ErrDenied
	}
	res, err := tx.Exec(`INSERT INTO user(name, password_hash, all_projects, created_at) VALUES(?,?,?,?)`,
		name, hash, all, now())
	if isUnique(err) {
		return ErrExists
	}
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	if !all {
		if err := grantUserProjects(tx, id, projects); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func grantUserProjects(db execer, id int64, projects []string) error {
	for _, p := range projects {
		res, err := db.Exec(`INSERT OR IGNORE INTO user_project(user_id, project_id)
			SELECT ?, id FROM project WHERE name=?`, id, p)
		if err := affected(res, err); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) GetUser(id int64) (model.User, error) {
	var u model.User
	var created int64
	err := s.db.QueryRow(`SELECT id, name, admin, all_projects, created_at, auth_version FROM user WHERE id=?`, id).
		Scan(&u.ID, &u.Name, &u.Admin, &u.AllProjects, &created, &u.AuthVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	if err != nil {
		return u, err
	}
	u.CreatedAt = unix(created)
	rows, err := s.db.Query(`SELECT p.name FROM user_project up JOIN project p ON p.id=up.project_id
		WHERE up.user_id=? ORDER BY p.name`, id)
	if err != nil {
		return u, err
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return u, err
		}
		u.Projects = append(u.Projects, name)
	}
	return u, rows.Err()
}

func (s *Store) AuthenticateUser(name, password string) (model.User, error) {
	var id, authVersion int64
	var hash string
	err := s.db.QueryRow(`SELECT id, password_hash, auth_version FROM user WHERE name=?`, name).Scan(&id, &hash, &authVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return model.User{}, ErrNotFound
	}
	if err != nil {
		return model.User{}, err
	}
	if !crypto.VerifyPassword(hash, password) {
		return model.User{}, ErrDenied
	}
	u, err := s.GetUser(id)
	if err != nil {
		return u, err
	}
	if u.AuthVersion != authVersion {
		return model.User{}, ErrDenied
	}
	return u, nil
}

func (s *Store) ListUsers() ([]model.User, error) {
	rows, err := s.db.Query(`SELECT id FROM user ORDER BY name`)
	if err != nil {
		return nil, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	users := []model.User{}
	for _, id := range ids {
		u, err := s.GetUser(id)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

func (s *Store) SetUserAccess(adminID, userID int64, all bool, projects []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var admin bool
	if err := tx.QueryRow(`SELECT admin FROM user WHERE id=?`, adminID).Scan(&admin); err != nil || !admin {
		return ErrDenied
	}
	res, err := tx.Exec(`UPDATE user SET all_projects=? WHERE id=? AND admin=0`, all, userID)
	if err := affected(res, err); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM user_project WHERE user_id=?`, userID); err != nil {
		return err
	}
	if !all {
		if err := grantUserProjects(tx, userID, projects); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) SetAdminName(adminID int64, name string) error {
	if !model.ValidName(name) {
		return errors.New("invalid username")
	}
	res, err := s.db.Exec(`UPDATE user SET name=? WHERE id=? AND admin=1`, name, adminID)
	if isUnique(err) {
		return ErrExists
	}
	return affected(res, err)
}

func (s *Store) SetAdminPassword(password string) error {
	if err := validateUser("admin", password); err != nil {
		return err
	}
	return affected(s.db.Exec(`UPDATE user SET password_hash=?, auth_version=auth_version+1 WHERE admin=1`, crypto.HashPassword(password)))
}

func (s *Store) ChangeUserPassword(userID, authVersion int64, current, password string) error {
	if err := validateUser("admin", password); err != nil {
		return err
	}
	var hash string
	err := s.db.QueryRow(`SELECT password_hash FROM user WHERE id=? AND auth_version=?`, userID, authVersion).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrDenied
	}
	if err != nil {
		return err
	}
	if !crypto.VerifyPassword(hash, current) {
		return ErrDenied
	}
	res, err := s.db.Exec(`UPDATE user SET password_hash=?, auth_version=auth_version+1
		WHERE id=? AND auth_version=? AND password_hash=?`, crypto.HashPassword(password), userID, authVersion, hash)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrDenied
	}
	return nil
}

func (s *Store) validateAccess(userID int64, all bool, projects []string) error {
	u, err := s.GetUser(userID)
	if err != nil {
		return err
	}
	if all && !u.Admin && !u.AllProjects {
		return ErrDenied
	}
	for _, p := range projects {
		if !u.CanAccess(p) {
			return ErrDenied
		}
		if _, err := s.projectID(p); err != nil {
			return err
		}
	}
	return nil
}
