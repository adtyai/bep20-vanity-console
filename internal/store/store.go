package store

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"bep20-vanity-console/internal/secret"
	"bep20-vanity-console/internal/single"

	_ "modernc.org/sqlite"
)

type Settings struct {
	Running        bool
	CPU            int
	Rules          map[string]bool
	Attempts       uint64
	Accumulated    time.Duration
	SegmentStarted time.Time
}

type ResultMeta struct {
	ID        int64
	Rule      string
	Length    int
	Checksum  string
	Lower     string
	CreatedAt time.Time
}

type ResultSecret struct {
	ResultMeta
	Nonce      []byte
	Ciphertext []byte
}

type NewResult struct {
	Rule     string
	Length   int
	Checksum string
	Lower    string
	PrivHex  string
}

type Store struct {
	mu     sync.Mutex
	closed bool
	db     *sql.DB
	path   string
	lock   *single.Lock
}

func Open(path string) (*Store, error) {
	lk, err := single.Acquire(path + ".lock")
	if err != nil {
		if err.Error() == "lock" {
			return nil, errors.New("lock")
		}
		return nil, errors.New("lock_path")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		_ = lk.Release()
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, path: path, lock: lk}
	if err := s.init(); err != nil {
		_ = db.Close()
		_ = lk.Release()
		return nil, err
	}
	if err := chmodOwner(path); err != nil {
		_ = db.Close()
		_ = lk.Release()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	err := s.db.Close()
	if s.lock != nil {
		if rerr := s.lock.Release(); err == nil {
			err = rerr
		}
		s.lock = nil
	}
	return err
}

func (s *Store) guard() error {
	if s.closed {
		return errors.New("closed")
	}
	return nil
}

func (s *Store) Dir() string {
	return filepath.Dir(s.path)
}

func chmodOwner(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		err := os.Chmod(path+suffix, 0o600)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func (s *Store) init() error {
	if _, err := s.db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		return err
	}
	if _, err := s.db.Exec(`PRAGMA busy_timeout=5000`); err != nil {
		return err
	}
	if _, err := s.db.Exec(`PRAGMA foreign_keys=ON`); err != nil {
		return err
	}
	if _, err := s.db.Exec(`PRAGMA secure_delete=ON`); err != nil {
		return err
	}
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS admin (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  username TEXT NOT NULL UNIQUE,
  password_hash BLOB NOT NULL,
  salt BLOB NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  running INTEGER NOT NULL,
  cpu_percent INTEGER NOT NULL,
  rule_8a INTEGER NOT NULL,
  rule_9a INTEGER NOT NULL,
  rule_18 INTEGER NOT NULL,
  rule_19 INTEGER NOT NULL,
  attempts INTEGER NOT NULL,
  accumulated_ms INTEGER NOT NULL,
  segment_started_at TEXT,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS results (
  id INTEGER PRIMARY KEY,
  rule TEXT NOT NULL,
  length INTEGER NOT NULL,
  address_checksum TEXT NOT NULL,
  address_lower TEXT NOT NULL UNIQUE,
  nonce BLOB NOT NULL,
  ciphertext BLOB NOT NULL,
  created_at TEXT NOT NULL
);
`)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`
INSERT INTO settings (id, running, cpu_percent, rule_8a, rule_9a, rule_18, rule_19, attempts, accumulated_ms, segment_started_at, updated_at)
VALUES (1, 0, 50, 1, 1, 1, 1, 0, 0, NULL, ?)
ON CONFLICT(id) DO NOTHING`, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

type Admin struct {
	Username string
	Hash     []byte
	Salt     []byte
}

func (s *Store) CreateAdmin(username string, hash, salt []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(); err != nil {
		return err
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM admin`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return errors.New("admin_exists")
	}
	_, err := s.db.Exec(`INSERT INTO admin (id, username, password_hash, salt, created_at) VALUES (1, ?, ?, ?, ?)`,
		username, hash, salt, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

func (s *Store) Admin() (Admin, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(); err != nil {
		return Admin{}, false, err
	}
	var a Admin
	err := s.db.QueryRow(`SELECT username, password_hash, salt FROM admin WHERE id = 1`).Scan(&a.Username, &a.Hash, &a.Salt)
	if errors.Is(err, sql.ErrNoRows) {
		return Admin{}, false, nil
	}
	if err != nil {
		return Admin{}, false, err
	}
	return a, true, nil
}

func (s *Store) HasAdmin() (bool, error) {
	_, ok, err := s.Admin()
	return ok, err
}

func (s *Store) Settings() (Settings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(); err != nil {
		return Settings{}, err
	}
	return s.settingsLocked()
}

func (s *Store) settingsLocked() (Settings, error) {
	var running, cpu, r8, r9, r18, r19 int
	var attempts, accumulated int64
	var segment sql.NullString
	err := s.db.QueryRow(`SELECT running, cpu_percent, rule_8a, rule_9a, rule_18, rule_19, attempts, accumulated_ms, segment_started_at FROM settings WHERE id = 1`).
		Scan(&running, &cpu, &r8, &r9, &r18, &r19, &attempts, &accumulated, &segment)
	if err != nil {
		return Settings{}, err
	}
	out := Settings{
		Running:     running == 1,
		CPU:         cpu,
		Attempts:    uint64(attempts),
		Accumulated: time.Duration(accumulated) * time.Millisecond,
		Rules: map[string]bool{
			"8A":  r8 == 1,
			"9A":  r9 == 1,
			"1-8": r18 == 1,
			"1-9": r19 == 1,
		},
	}
	if segment.Valid && segment.String != "" {
		t, err := time.Parse(time.RFC3339Nano, segment.String)
		if err != nil {
			return Settings{}, err
		}
		out.SegmentStarted = t
	}
	return out, nil
}

func (s *Store) SetCPU(n int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(); err != nil {
		return err
	}
	_, err := s.db.Exec(`UPDATE settings SET cpu_percent = ?, updated_at = ? WHERE id = 1`, n, nowText())
	return err
}

func (s *Store) SetRules(rules map[string]bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(); err != nil {
		return err
	}
	_, err := s.db.Exec(`UPDATE settings SET rule_8a = ?, rule_9a = ?, rule_18 = ?, rule_19 = ?, updated_at = ? WHERE id = 1`,
		boolInt(rules["8A"]), boolInt(rules["9A"]), boolInt(rules["1-8"]), boolInt(rules["1-9"]), nowText())
	return err
}

func (s *Store) SetAttempts(n uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(); err != nil {
		return err
	}
	_, err := s.db.Exec(`UPDATE settings SET attempts = ?, updated_at = ? WHERE id = 1`, n, nowText())
	return err
}

func (s *Store) MarkRunning(at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(); err != nil {
		return err
	}
	_, err := s.db.Exec(`UPDATE settings SET running = 1, segment_started_at = ?, updated_at = ? WHERE id = 1`, at.UTC().Format(time.RFC3339Nano), nowText())
	return err
}

func (s *Store) TouchSegment(at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(); err != nil {
		return err
	}
	_, err := s.db.Exec(`UPDATE settings SET segment_started_at = ?, updated_at = ? WHERE id = 1`, at.UTC().Format(time.RFC3339Nano), nowText())
	return err
}

func (s *Store) CountResults() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(); err != nil {
		return 0, err
	}
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM results`).Scan(&n)
	return n, err
}

func (s *Store) SaveOpenSegment(accumulated time.Duration, segment time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(); err != nil {
		return err
	}
	if segment.IsZero() {
		_, err := s.db.Exec(`UPDATE settings SET accumulated_ms = ?, segment_started_at = NULL, updated_at = ? WHERE id = 1`, accumulated.Milliseconds(), nowText())
		return err
	}
	_, err := s.db.Exec(`UPDATE settings SET accumulated_ms = ?, segment_started_at = ?, updated_at = ? WHERE id = 1`, accumulated.Milliseconds(), segment.UTC().Format(time.RFC3339Nano), nowText())
	return err
}

func (s *Store) MarkStopped(now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(); err != nil {
		return err
	}
	st, err := s.settingsLocked()
	if err != nil {
		return err
	}
	acc := st.Accumulated
	if !st.SegmentStarted.IsZero() {
		d := now.Sub(st.SegmentStarted)
		if d > 0 {
			acc += d
		}
	}
	_, err = s.db.Exec(`UPDATE settings SET running = 0, accumulated_ms = ?, segment_started_at = NULL, updated_at = ? WHERE id = 1`,
		acc.Milliseconds(), nowText())
	return err
}

func (s *Store) SaveResult(key []byte, in NewResult) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(); err != nil {
		return 0, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`INSERT INTO results (rule, length, address_checksum, address_lower, nonce, ciphertext, created_at) VALUES (?, ?, ?, ?, x'', x'', ?)`,
		in.Rule, in.Length, in.Checksum, in.Lower, nowText())
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	nonce, ct, err := secret.Encrypt(key, []byte(in.PrivHex), []byte(strconv.FormatInt(id, 10)))
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`UPDATE results SET nonce = ?, ciphertext = ? WHERE id = ?`, nonce, ct, id); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return id, nil
}

func (s *Store) List(rule string) ([]ResultMeta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT id, rule, length, address_checksum, address_lower, created_at FROM results WHERE rule = ? ORDER BY id DESC`, rule)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ResultMeta
	for rows.Next() {
		var item ResultMeta
		var created string
		if err := rows.Scan(&item.ID, &item.Rule, &item.Length, &item.Checksum, &item.Lower, &created); err != nil {
			return nil, err
		}
		t, err := time.Parse(time.RFC3339Nano, created)
		if err != nil {
			return nil, err
		}
		item.CreatedAt = t
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Store) LastHit(rule string) (time.Time, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(); err != nil {
		return time.Time{}, false, err
	}
	var created sql.NullString
	err := s.db.QueryRow(`SELECT created_at FROM results WHERE rule = ? ORDER BY id DESC LIMIT 1`, rule).Scan(&created)
	if errors.Is(err, sql.ErrNoRows) || !created.Valid {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, err
	}
	t, err := time.Parse(time.RFC3339Nano, created.String)
	if err != nil {
		return time.Time{}, false, err
	}
	return t, true, nil
}

func (s *Store) Get(id int64) (ResultSecret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(); err != nil {
		return ResultSecret{}, err
	}
	var item ResultSecret
	var created string
	err := s.db.QueryRow(`SELECT id, rule, length, address_checksum, address_lower, nonce, ciphertext, created_at FROM results WHERE id = ?`, id).
		Scan(&item.ID, &item.Rule, &item.Length, &item.Checksum, &item.Lower, &item.Nonce, &item.Ciphertext, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return ResultSecret{}, errors.New("not_found")
	}
	if err != nil {
		return ResultSecret{}, err
	}
	t, err := time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return ResultSecret{}, err
	}
	item.CreatedAt = t
	return item, nil
}

func (s *Store) Delete(id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(); err != nil {
		return err
	}
	if _, err := s.db.Exec(`UPDATE results SET nonce = zeroblob(length(nonce)), ciphertext = zeroblob(length(ciphertext)) WHERE id = ?`, id); err != nil {
		return err
	}
	res, err := s.db.Exec(`DELETE FROM results WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("not_found")
	}
	if err := scrubAfterDelete(s.db, s.path); err != nil {
		return ErrScrub
	}
	return nil
}

var ErrScrub = errors.New("scrub")

func SetScrubHook(fn func(*sql.DB, string) error) func() {
	old := scrubAfterDelete
	if fn != nil {
		scrubAfterDelete = fn
	}
	return func() { scrubAfterDelete = old }
}

var scrubAfterDelete = func(db *sql.DB, path string) error {
	if _, err := db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return err
	}
	if _, err := db.Exec(`VACUUM`); err != nil {
		return err
	}
	if _, err := db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return err
	}
	return chmodOwner(path)
}

func (s *Store) RawCiphertext(id int64) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.guard(); err != nil {
		return nil, err
	}
	var ct []byte
	err := s.db.QueryRow(`SELECT ciphertext FROM results WHERE id = ?`, id).Scan(&ct)
	return ct, err
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func nowText() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}
