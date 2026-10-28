package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"sync"
	"time"
	"unicode/utf8"

	"bep20-vanity-console/internal/store"

	"golang.org/x/crypto/argon2"
)

const (
	sessionIdle = 7 * 24 * time.Hour
	lockFor     = 10 * time.Minute
	maxFails    = 5
)

type Params struct {
	Time    uint32
	Memory  uint32
	Threads uint8
	KeyLen  uint32
}

func ProductionParams() Params {
	return Params{Time: 3, Memory: 64 * 1024, Threads: 1, KeyLen: 32}
}

var (
	ErrLocked   = errors.New("locked")
	ErrBadLogin = errors.New("bad_login")
	ErrExists   = errors.New("admin_exists")
	ErrPassword = errors.New("password")
	ErrUsername = errors.New("username")
	deriveKey   = argon2.IDKey
)

type Session struct {
	ID       string
	Username string
	CSRF     string
	Expiry   time.Time
}

type Manager struct {
	store  *store.Store
	params Params
	now    func() time.Time

	mu          sync.Mutex
	sessions    map[string]*Session
	boot        map[string]bootToken
	fails       int
	lockedUntil time.Time
	dummySalt   []byte
}

type bootToken struct {
	token  string
	expiry time.Time
}

func New(st *store.Store, params Params, now func() time.Time) *Manager {
	if now == nil {
		now = time.Now
	}
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	return &Manager{
		store:     st,
		params:    params,
		now:       now,
		sessions:  map[string]*Session{},
		boot:      map[string]bootToken{},
		dummySalt: salt,
	}
}

func (m *Manager) CreateAdmin(username, password, again string) error {
	if err := ValidateUsername(username); err != nil {
		return err
	}
	if password != again {
		return ErrPassword
	}
	if err := ValidatePassword(password); err != nil {
		return err
	}
	ok, err := m.store.HasAdmin()
	if err != nil {
		return err
	}
	if ok {
		return ErrExists
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	hash := m.hash(password, salt)
	if err := m.store.CreateAdmin(username, hash, salt); err != nil {
		return err
	}
	return nil
}

func ValidateUsername(username string) error {
	n := utf8.RuneCountInString(username)
	if n < 1 || n > 64 {
		return ErrUsername
	}
	for _, r := range username {
		if r < 0x20 || r == 0x7f {
			return ErrUsername
		}
	}
	return nil
}

func ValidatePassword(password string) error {
	n := utf8.RuneCountInString(password)
	if n < 16 || n > 256 {
		return ErrPassword
	}
	return nil
}

func (m *Manager) Login(username, password string) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.now().Before(m.lockedUntil) {
		return Session{}, ErrLocked
	}
	admin, ok, err := m.store.Admin()
	if err != nil {
		return Session{}, err
	}
	var match bool
	if ok && subtle.ConstantTimeCompare([]byte(admin.Username), []byte(username)) == 1 {
		sum := m.hash(password, admin.Salt)
		match = subtle.ConstantTimeCompare(sum, admin.Hash) == 1
	} else {
		_ = m.hash(password, m.dummySalt)
	}
	if m.now().Before(m.lockedUntil) {
		return Session{}, ErrLocked
	}
	if !match {
		m.fails++
		if m.fails >= maxFails {
			m.lockedUntil = m.now().Add(lockFor)
			m.fails = 0
			return Session{}, ErrLocked
		}
		return Session{}, ErrBadLogin
	}
	m.fails = 0
	m.lockedUntil = time.Time{}
	sess := &Session{
		ID:       randomHex(32),
		Username: admin.Username,
		CSRF:     randomHex(32),
		Expiry:   m.now().Add(sessionIdle),
	}
	m.sessions[sess.ID] = sess
	return *sess, nil
}

func (m *Manager) Session(id string) (Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok || !m.now().Before(s.Expiry) {
		delete(m.sessions, id)
		return Session{}, false
	}
	s.Expiry = m.now().Add(sessionIdle)
	return *s, true
}

func (m *Manager) Logout(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
}

func (m *Manager) IssueBoot() (cookie, token string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.boot) > 100 {
		m.boot = map[string]bootToken{}
	}
	cookie = randomHex(16)
	token = randomHex(32)
	m.boot[cookie] = bootToken{token: token, expiry: m.now().Add(30 * time.Minute)}
	return cookie, token
}

func (m *Manager) CheckBoot(cookie, token string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	item, ok := m.boot[cookie]
	delete(m.boot, cookie)
	if !ok || !m.now().Before(item.expiry) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(item.token), []byte(token)) == 1
}

func (m *Manager) hash(password string, salt []byte) []byte {
	return deriveKey([]byte(password), salt, m.params.Time, m.params.Memory, m.params.Threads, m.params.KeyLen)
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
