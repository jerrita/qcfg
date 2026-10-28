package store

import (
	"net/http"
	"time"
)

type Activity struct {
	UserID    int64
	UserName  string
	Source    string
	Method    string
	Path      string
	Status    int
	CreatedAt time.Time
}

// RecordActivity keeps a bounded history without request bodies or query strings.
func (s *Store) RecordActivity(a Activity) error {
	_, err := s.db.Exec(`INSERT INTO activity (user_id, user_name, source, method, path, status, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`, a.UserID, a.UserName, a.Source, a.Method, a.Path, a.Status, now())
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`DELETE FROM activity WHERE id <= (SELECT id FROM activity ORDER BY id DESC LIMIT 1 OFFSET 10000)`)
	return err
}

func (s *Store) ListActivity(userID int64, all bool) ([]Activity, error) {
	rows, err := s.db.Query(`SELECT user_id, user_name, source, method, path, status, created_at
		FROM activity WHERE ? OR user_id = ? ORDER BY id DESC LIMIT 100`, all, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var activities []Activity
	for rows.Next() {
		var a Activity
		var created int64
		if err := rows.Scan(&a.UserID, &a.UserName, &a.Source, &a.Method, &a.Path, &a.Status, &created); err != nil {
			return nil, err
		}
		a.CreatedAt = unix(created)
		activities = append(activities, a)
	}
	return activities, rows.Err()
}

// ActivityResponse captures the response status while preserving normal writes.
type ActivityResponse struct {
	http.ResponseWriter
	Status int
}

func (w *ActivityResponse) WriteHeader(status int) {
	if w.Status != 0 {
		return
	}
	w.Status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *ActivityResponse) Write(p []byte) (int, error) {
	if w.Status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}

func (w *ActivityResponse) Unwrap() http.ResponseWriter { return w.ResponseWriter }
