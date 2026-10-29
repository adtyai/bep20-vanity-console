package httpapi

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"bep20-vanity-console/internal/auth"
	"bep20-vanity-console/internal/job"
	"bep20-vanity-console/internal/store"
	"bep20-vanity-console/internal/vanity"
)

const (
	testUser  = "owner"
	testPass  = "0123456789abcdef"
	testToken = "setup-token-16ch"
	knownKey  = "0000000000000000000000000000000000000000000000000000000000000001"
	knownAddr = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
)

type harness struct {
	t      *testing.T
	st     *store.Store
	runner *job.Runner
	key    []byte
	c      *client
	logs   []string
	logMu  sync.Mutex
}

type client struct {
	h      http.Handler
	jar    map[string]*http.Cookie
	header http.Header
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "vanity.db"))
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{9}, 32)
	harn := &harness{t: t, st: st, key: key}
	logf := func(event, rule string, id int64, count uint64, errorType string) {
		harn.logMu.Lock()
		harn.logs = append(harn.logs, event+" "+rule+" "+strconv.FormatInt(id, 10)+" "+errorType)
		harn.logMu.Unlock()
	}
	runner := job.New(st, key, func() (string, string, string, error) {
		return "", "", "", errors.New("idle")
	}, 1, logf)
	if err := runner.Boot(); err != nil {
		t.Fatal(err)
	}
	mgr := auth.New(st, auth.Params{Time: 1, Memory: 8 * 1024, Threads: 1, KeyLen: 32}, time.Now)
	handler, err := New(st, runner, mgr, testToken, logf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		runner.Shutdown()
		st.Close()
	})
	harn.runner = runner
	harn.c = &client{h: handler, jar: map[string]*http.Cookie{}, header: http.Header{}}
	return harn
}

func (c *client) do(method, path, body string) *http.Response {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, vs := range c.header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	for _, ck := range c.jar {
		req.AddCookie(ck)
	}
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	res := rec.Result()
	for _, ck := range res.Cookies() {
		if ck.MaxAge < 0 {
			delete(c.jar, ck.Name)
			continue
		}
		c.jar[ck.Name] = ck
	}
	return res
}

func readBody(t *testing.T, res *http.Response) string {
	t.Helper()
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mustCSRF(t *testing.T, body string) string {
	t.Helper()
	const key = `name="csrf" value="`
	i := strings.Index(body, key)
	if i < 0 {
		t.Fatalf("missing csrf: %s", body)
	}
	rest := body[i+len(key):]
	j := strings.Index(rest, `"`)
	if j <= 0 {
		t.Fatalf("bad csrf: %s", body)
	}
	return rest[:j]
}

func (h *harness) createAdmin() {
	h.t.Helper()
	res := h.c.do(http.MethodGet, "/setup", "")
	body := readBody(h.t, res)
	if res.StatusCode != http.StatusOK {
		h.t.Fatalf("setup %d %s", res.StatusCode, body)
	}
	res = h.c.do(http.MethodPost, "/setup", url.Values{
		"username":    {testUser},
		"password":    {testPass},
		"password2":   {testPass},
		"setup_token": {testToken},
		"csrf":        {mustCSRF(h.t, body)},
	}.Encode())
	if res.StatusCode != http.StatusSeeOther || res.Header.Get("Location") != "/login" {
		h.t.Fatalf("create %d %s", res.StatusCode, readBody(h.t, res))
	}
	res.Body.Close()
}

func (h *harness) login() {
	h.t.Helper()
	res := h.c.do(http.MethodGet, "/login", "")
	body := readBody(h.t, res)
	res = h.c.do(http.MethodPost, "/login", url.Values{
		"username": {testUser},
		"password": {testPass},
		"csrf":     {mustCSRF(h.t, body)},
	}.Encode())
	if res.StatusCode != http.StatusSeeOther {
		h.t.Fatalf("login %d %s", res.StatusCode, readBody(h.t, res))
	}
	res.Body.Close()
	ck := h.c.jar["vanity_session"]
	if ck == nil || !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode || ck.MaxAge != 7*24*3600 {
		h.t.Fatalf("session cookie %+v", ck)
	}
}

func (h *harness) home() (string, string) {
	h.t.Helper()
	res := h.c.do(http.MethodGet, "/", "")
	body := readBody(h.t, res)
	if res.StatusCode != http.StatusOK {
		h.t.Fatalf("home %d %s", res.StatusCode, body)
	}
	if res.Header.Get("Cache-Control") != "no-store" {
		h.t.Fatalf("cache %s", res.Header.Get("Cache-Control"))
	}
	return mustCSRF(h.t, body), body
}

func TestSetupDisappearsAndRejectsBadToken(t *testing.T) {
	h := newHarness(t)
	res := h.c.do(http.MethodGet, "/setup", "")
	body := readBody(t, res)
	res = h.c.do(http.MethodPost, "/setup", url.Values{
		"username":    {testUser},
		"password":    {testPass},
		"password2":   {"0123456789abcdef"},
		"setup_token": {"wrong-token-value"},
		"csrf":        {mustCSRF(t, body)},
	}.Encode())
	body = readBody(t, res)
	if res.StatusCode != http.StatusOK || !strings.Contains(body, "创建失败") || strings.Contains(body, testToken) {
		t.Fatalf("bad token %d %s", res.StatusCode, body)
	}
	ok, err := h.st.HasAdmin()
	if err != nil || ok {
		t.Fatalf("admin created on bad token ok=%v err=%v", ok, err)
	}
	h.createAdmin()
	res = h.c.do(http.MethodGet, "/setup", "")
	body = readBody(t, res)
	if res.StatusCode != http.StatusNotFound || !strings.Contains(body, "未找到") {
		t.Fatalf("setup still open %d %s", res.StatusCode, body)
	}
	res = h.c.do(http.MethodPost, "/setup", "username=other&password=0123456789abcdef&password2=0123456789abcdef&setup_token="+testToken)
	body = readBody(t, res)
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("second admin %d %s", res.StatusCode, body)
	}
}

func TestLoginLockCSRFAndResults(t *testing.T) {
	h := newHarness(t)
	h.createAdmin()
	res := h.c.do(http.MethodPost, "/login", "username="+testUser+"&password="+testPass)
	body := readBody(t, res)
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(body, "拒绝") {
		t.Fatalf("csrf %d %s", res.StatusCode, body)
	}
	if h.c.jar["vanity_session"] != nil {
		t.Fatal("session without csrf")
	}
	for i := 0; i < 4; i++ {
		res = h.c.do(http.MethodGet, "/login", "")
		page := readBody(t, res)
		res = h.c.do(http.MethodPost, "/login", url.Values{
			"username": {testUser},
			"password": {"wrong-password-1"},
			"csrf":     {mustCSRF(t, page)},
		}.Encode())
		page = readBody(t, res)
		if res.StatusCode != http.StatusOK || !strings.Contains(page, "用户名或密码错误") || strings.Contains(page, "锁定") {
			t.Fatalf("attempt %d: %d %s", i+1, res.StatusCode, page)
		}
	}
	res = h.c.do(http.MethodGet, "/login", "")
	page := readBody(t, res)
	res = h.c.do(http.MethodPost, "/login", url.Values{
		"username": {"nobody"},
		"password": {testPass},
		"csrf":     {mustCSRF(t, page)},
	}.Encode())
	page = readBody(t, res)
	if res.StatusCode != http.StatusTooManyRequests || !strings.Contains(page, "登录已锁定") {
		t.Fatalf("fifth %d %s", res.StatusCode, page)
	}
	res = h.c.do(http.MethodPost, "/login", url.Values{
		"username": {testUser},
		"password": {testPass},
		"csrf":     {mustCSRF(t, page)},
	}.Encode())
	page = readBody(t, res)
	if res.StatusCode != http.StatusTooManyRequests || !strings.Contains(page, "登录已锁定") || h.c.jar["vanity_session"] != nil {
		t.Fatalf("locked correct password %d %s", res.StatusCode, page)
	}
	res = h.c.do(http.MethodGet, "/results", "")
	page = readBody(t, res)
	if res.StatusCode != http.StatusUnauthorized || res.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("results %d %s", res.StatusCode, page)
	}
}

func TestCPUBoundsStopConfirmAndRules(t *testing.T) {
	h := newHarness(t)
	h.createAdmin()
	h.login()
	for _, n := range []string{"0", "96", "100"} {
		csrf, _ := h.home()
		res := h.c.do(http.MethodPost, "/cpu", url.Values{"csrf": {csrf}, "percent": {n}}.Encode())
		body := readBody(t, res)
		if res.StatusCode != http.StatusBadRequest || !strings.Contains(body, "拒绝") {
			t.Fatalf("cpu %s -> %d %s", n, res.StatusCode, body)
		}
	}
	for _, n := range []int{50, 95} {
		csrf, _ := h.home()
		res := h.c.do(http.MethodPost, "/cpu", url.Values{"csrf": {csrf}, "percent": {strconv.Itoa(n)}}.Encode())
		if res.StatusCode != http.StatusSeeOther {
			t.Fatalf("cpu %d -> %d %s", n, res.StatusCode, readBody(t, res))
		}
		res.Body.Close()
		settings, err := h.st.Settings()
		if err != nil || settings.CPU != n || h.runner.Snapshot().CPU != n {
			t.Fatalf("cpu %d stored %+v err=%v snap=%d", n, settings, err, h.runner.Snapshot().CPU)
		}
	}
	csrf, _ := h.home()
	res := h.c.do(http.MethodPost, "/start", url.Values{"csrf": {csrf}}.Encode())
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("start %d %s", res.StatusCode, readBody(t, res))
	}
	res.Body.Close()
	settings, err := h.st.Settings()
	if err != nil || !settings.Running {
		t.Fatal(err, settings.Running)
	}
	csrf, _ = h.home()
	res = h.c.do(http.MethodPost, "/stop", url.Values{"csrf": {csrf}}.Encode())
	body := readBody(t, res)
	if res.StatusCode != http.StatusOK || !strings.Contains(body, "确认停止") {
		t.Fatalf("confirm %d %s", res.StatusCode, body)
	}
	settings, err = h.st.Settings()
	if err != nil || !settings.Running {
		t.Fatal("first stop cleared running")
	}
	res = h.c.do(http.MethodPost, "/stop", url.Values{"csrf": {mustCSRF(t, body)}, "confirm": {"yes"}}.Encode())
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("stop %d %s", res.StatusCode, readBody(t, res))
	}
	res.Body.Close()
	settings, err = h.st.Settings()
	if err != nil || settings.Running {
		t.Fatal("confirmed stop did not clear running")
	}
	addr := "0x" + strings.Repeat("1", 30) + strings.Repeat("8", 10)
	priv := strings.Repeat("ab", 32)
	if _, err := h.st.SaveResult(h.key, store.NewResult{
		Rule: "9A", Length: 10, Checksum: addr, Lower: strings.TrimPrefix(addr, "0x"), PrivHex: priv,
	}); err != nil {
		t.Fatal(err)
	}
	csrf, _ = h.home()
	res = h.c.do(http.MethodPost, "/rules", url.Values{
		"csrf": {csrf}, "r8a": {"1"}, "r18": {"1"}, "r19": {"1"},
	}.Encode())
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("rules %d %s", res.StatusCode, readBody(t, res))
	}
	res.Body.Close()
	settings, err = h.st.Settings()
	if err != nil || settings.Rules["9A"] || !settings.Rules["8A"] {
		t.Fatalf("%+v %v", settings.Rules, err)
	}
	_, body = h.home()
	if !strings.Contains(body, addr) || strings.Contains(body, priv) {
		t.Fatal("existing 9A row missing or key leaked")
	}
}

func TestRevealMismatchDoesNotReturnKey(t *testing.T) {
	h := newHarness(t)
	h.createAdmin()
	h.login()
	privA, sumA, lowerA, err := vanity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	privB, _, _, err := vanity.Generate()
	if err != nil {
		t.Fatal(err)
	}
	id, err := h.st.SaveResult(h.key, store.NewResult{
		Rule: "8A", Length: 8, Checksum: sumA, Lower: lowerA, PrivHex: privB,
	})
	if err != nil {
		t.Fatal(err)
	}
	csrf, _ := h.home()
	res := h.c.do(http.MethodPost, "/results/"+itoa(id)+"/reveal", url.Values{"csrf": {csrf}}.Encode())
	body := readBody(t, res)
	if res.StatusCode != http.StatusConflict || !strings.Contains(body, "数据错误") {
		t.Fatalf("mismatch %d %s", res.StatusCode, body)
	}
	if strings.Contains(body, privA) || strings.Contains(body, privB) || strings.Contains(body, "0x"+privB) {
		t.Fatal("mismatch returned a private key")
	}
	other := bytes.Repeat([]byte{1}, 32)
	id, err = h.st.SaveResult(other, store.NewResult{
		Rule: "8A", Length: 8, Checksum: "0x" + strings.Repeat("2", 40), Lower: strings.Repeat("2", 40), PrivHex: privA,
	})
	if err != nil {
		t.Fatal(err)
	}
	csrf, _ = h.home()
	res = h.c.do(http.MethodPost, "/results/"+itoa(id)+"/reveal", url.Values{"csrf": {csrf}}.Encode())
	body = readBody(t, res)
	if res.StatusCode != http.StatusConflict || strings.Contains(body, privA) || strings.Contains(body, "0x"+privA) {
		t.Fatalf("wrong key reveal %d leaked=%v", res.StatusCode, strings.Contains(body, privA))
	}
}

func TestKnownVectorRevealAndHomeHidesKey(t *testing.T) {
	h := newHarness(t)
	h.createAdmin()
	h.login()
	sum, lower, err := vanity.AddressFromPrivateKeyHex(knownKey)
	if err != nil {
		t.Fatal(err)
	}
	if sum != knownAddr {
		t.Fatal(sum)
	}
	id, err := h.st.SaveResult(h.key, store.NewResult{
		Rule: "8A", Length: 8, Checksum: sum, Lower: lower, PrivHex: knownKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, body := h.home()
	if !strings.Contains(body, knownAddr) || strings.Contains(body, knownKey) || strings.Contains(body, "0x"+knownKey) {
		t.Fatal("home leaked key or hid address")
	}
	if !strings.Contains(body, "BEP20 自用靓号台") {
		t.Fatal("title missing")
	}
	csrf, _ := h.home()
	res := h.c.do(http.MethodPost, "/results/"+itoa(id)+"/reveal", url.Values{"csrf": {csrf}}.Encode())
	body = readBody(t, res)
	if res.StatusCode != http.StatusOK || res.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("reveal %d", res.StatusCode)
	}
	if !strings.Contains(body, knownAddr) || !strings.Contains(body, "0x"+knownKey) {
		t.Fatal("reveal missing address or key")
	}
	if !strings.Contains(body, "<title>BEP20 自用靓号台</title>") || !strings.Contains(body, "<h2>私钥</h2>") {
		t.Fatal(body)
	}
	h.logMu.Lock()
	joined := strings.Join(h.logs, "\n")
	h.logMu.Unlock()
	if !strings.Contains(joined, "reveal") || strings.Contains(joined, knownKey) {
		t.Fatalf("reveal audit missing or leaked key: %s", joined)
	}
}

func TestUnknownPathIsChinese(t *testing.T) {
	h := newHarness(t)
	res := h.c.do(http.MethodGet, "/no-such", "")
	body := readBody(t, res)
	if res.StatusCode != http.StatusNotFound || !strings.Contains(body, "未找到") || strings.Contains(body, "page not found") {
		t.Fatalf("%d %s", res.StatusCode, body)
	}
	res = h.c.do(http.MethodGet, "/assets/app.css", "")
	body = readBody(t, res)
	if res.StatusCode != http.StatusOK || !strings.Contains(res.Header.Get("Content-Type"), "text/css") || strings.Contains(body, "未找到") {
		t.Fatalf("asset %d %s", res.StatusCode, res.Header.Get("Content-Type"))
	}
}

func TestDeleteConfirmDoesNotOverclaim(t *testing.T) {
	h := newHarness(t)
	h.createAdmin()
	h.login()
	sum, lower, err := vanity.AddressFromPrivateKeyHex(knownKey)
	if err != nil {
		t.Fatal(err)
	}
	id, err := h.st.SaveResult(h.key, store.NewResult{
		Rule: "8A", Length: 8, Checksum: sum, Lower: lower, PrivHex: knownKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	csrf, _ := h.home()
	res := h.c.do(http.MethodPost, "/results/"+itoa(id)+"/delete", url.Values{"csrf": {csrf}}.Encode())
	body := readBody(t, res)
	if res.StatusCode != http.StatusOK || strings.Contains(body, "只删除服务器上的记录") || !strings.Contains(body, "覆盖库里的密文") || !strings.Contains(body, "待写文件") {
		t.Fatalf("%d %s", res.StatusCode, body)
	}
}

func TestStoreFailureDoesNotChangeLiveSettings(t *testing.T) {
	h := newHarness(t)
	h.createAdmin()
	h.login()
	csrf, _ := h.home()
	if err := h.runner.Start(); err != nil {
		t.Fatal(err)
	}
	if err := h.st.Close(); err != nil {
		t.Fatal(err)
	}
	res := h.c.do(http.MethodPost, "/cpu", url.Values{"csrf": {csrf}, "percent": {"80"}}.Encode())
	body := readBody(t, res)
	if res.StatusCode != http.StatusInternalServerError || !strings.Contains(body, "内部错误") || h.runner.Snapshot().CPU != 50 {
		t.Fatalf("cpu %d %s snap %d", res.StatusCode, body, h.runner.Snapshot().CPU)
	}
	res = h.c.do(http.MethodPost, "/rules", url.Values{"csrf": {csrf}, "r9a": {"1"}}.Encode())
	body = readBody(t, res)
	if res.StatusCode != http.StatusInternalServerError || !h.runner.Snapshot().Rules["8A"] {
		t.Fatalf("rules %d %v", res.StatusCode, h.runner.Snapshot().Rules)
	}
	res = h.c.do(http.MethodPost, "/stop", url.Values{"csrf": {csrf}, "confirm": {"yes"}}.Encode())
	body = readBody(t, res)
	if res.StatusCode != http.StatusInternalServerError || !h.runner.Snapshot().Running {
		t.Fatalf("stop %d running %v %s", res.StatusCode, h.runner.Snapshot().Running, body)
	}
}

func TestHomeWarnsWhenSavePending(t *testing.T) {
	h := newHarness(t)
	h.createAdmin()
	h.login()
	h.runner.HookSave(func([]byte, store.NewResult) (int64, error) {
		return 0, errors.New("busy")
	})
	sum, lower, err := vanity.AddressFromPrivateKeyHex(knownKey)
	if err != nil {
		t.Fatal(err)
	}
	h.runner.EnqueueHit("8A", 8, sum, lower, knownKey)
	_, body := h.home()
	if !strings.Contains(body, "有命中尚未写入") || strings.Contains(body, "无法重试") || strings.Contains(body, "进程退出前会继续重试") || strings.Contains(body, knownKey) || strings.Contains(body, "0x"+knownKey) {
		t.Fatalf("warning missing or key leaked: %s", body)
	}
}

func TestBrokenPendingWarningDoesNotPromiseRetry(t *testing.T) {
	dir := t.TempDir()
	pending := filepath.Join(dir, "pending")
	if err := os.MkdirAll(pending, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pending, "0123456789abcdef0123456789abcdef"), []byte("not-a-valid-box"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "vanity.db"))
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{9}, 32)
	runner := job.New(st, key, func() (string, string, string, error) {
		return "", "", "", errors.New("idle")
	}, 1, nil)
	if err := runner.Boot(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		runner.Shutdown()
		st.Close()
	})
	mgr := auth.New(st, auth.Params{Time: 1, Memory: 8 * 1024, Threads: 1, KeyLen: 32}, time.Now)
	handler, err := New(st, runner, mgr, testToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, st: st, runner: runner, key: key, c: &client{h: handler, jar: map[string]*http.Cookie{}, header: http.Header{}}}
	h.createAdmin()
	h.login()
	_, body := h.home()
	if strings.Contains(body, "会继续重试") {
		t.Fatalf("broken file claimed retry: %s", body)
	}
	if !strings.Contains(body, "无法重试") {
		t.Fatalf("missing broken warning: %s", body)
	}
	if strings.Contains(body, "not-a-valid-box") {
		t.Fatal("broken payload leaked")
	}
}

func TestSecureCookieBehindHTTPS(t *testing.T) {
	h := newHarness(t)
	h.c.header.Set("X-Forwarded-Proto", "https")
	h.createAdmin()
	h.login()
	if !h.c.jar["vanity_session"].Secure {
		t.Fatal("session cookie was not secure")
	}
}

func TestRunningRefreshDoesNotWipeEdits(t *testing.T) {
	h := newHarness(t)
	h.createAdmin()
	h.login()
	_, stopped := h.home()
	if strings.Contains(stopped, `http-equiv="refresh"`) || strings.Contains(stopped, `name="live-refresh"`) {
		t.Fatal("stopped page refreshes")
	}
	csrf, _ := h.home()
	res := h.c.do(http.MethodPost, "/start", url.Values{"csrf": {csrf}}.Encode())
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("start %d %s", res.StatusCode, readBody(t, res))
	}
	res.Body.Close()
	_, body := h.home()
	if strings.Contains(body, `http-equiv="refresh"`) {
		t.Fatal("meta refresh reloads over unsaved edits")
	}
	if !strings.Contains(body, `name="live-refresh"`) {
		t.Fatal("running page lost live update")
	}
	res = h.c.do(http.MethodGet, "/assets/app.js", "")
	js := readBody(t, res)
	if res.StatusCode != http.StatusOK || !strings.Contains(js, "live-refresh") || !strings.Contains(js, "defaultValue") {
		t.Fatal("script reloads without checking unsaved fields")
	}
}

func TestConfirmedDeleteRemovesPending(t *testing.T) {
	h := newHarness(t)
	h.createAdmin()
	h.login()
	sum, lower, err := vanity.AddressFromPrivateKeyHex(knownKey)
	if err != nil {
		t.Fatal(err)
	}
	id, err := h.st.SaveResult(h.key, store.NewResult{
		Rule: "8A", Length: 8, Checksum: sum, Lower: lower, PrivHex: knownKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(lower))
	pending := filepath.Join(h.st.Dir(), "pending")
	if err := os.MkdirAll(pending, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(pending, hex.EncodeToString(digest[:16]))
	if err := os.WriteFile(path, []byte("sealed"), 0o600); err != nil {
		t.Fatal(err)
	}
	csrf, _ := h.home()
	res := h.c.do(http.MethodPost, "/results/"+itoa(id)+"/delete", url.Values{"csrf": {csrf}, "confirm": {"yes"}}.Encode())
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete %d %s", res.StatusCode, readBody(t, res))
	}
	res.Body.Close()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("pending kept: %v", err)
	}
}

func TestClearBrokenPendingKeepsValidFile(t *testing.T) {
	dir := t.TempDir()
	pending := filepath.Join(dir, "pending")
	if err := os.MkdirAll(pending, 0o700); err != nil {
		t.Fatal(err)
	}
	broken := filepath.Join(pending, "0123456789abcdef0123456789abcdef")
	if err := os.WriteFile(broken, []byte("not-a-valid-box"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "vanity.db"))
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{9}, 32)
	runner := job.New(st, key, func() (string, string, string, error) {
		return "", "", "", errors.New("idle")
	}, 1, nil)
	if err := runner.Boot(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		runner.Shutdown()
		st.Close()
	})
	runner.HookSave(func([]byte, store.NewResult) (int64, error) {
		return 0, errors.New("busy")
	})
	sum, lower, err := vanity.AddressFromPrivateKeyHex(knownKey)
	if err != nil {
		t.Fatal(err)
	}
	runner.EnqueueHit("8A", 8, sum, lower, knownKey)
	mgr := auth.New(st, auth.Params{Time: 1, Memory: 8 * 1024, Threads: 1, KeyLen: 32}, time.Now)
	handler, err := New(st, runner, mgr, testToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, st: st, runner: runner, key: key, c: &client{h: handler, jar: map[string]*http.Cookie{}, header: http.Header{}}}
	h.createAdmin()
	h.login()
	_, body := h.home()
	if !strings.Contains(body, "清除损坏文件") || !strings.Contains(body, "无法重试") {
		t.Fatalf("missing clear entry: %s", body)
	}
	csrf, _ := h.home()
	res := h.c.do(http.MethodPost, "/pending/clear", url.Values{"csrf": {csrf}}.Encode())
	body = readBody(t, res)
	if res.StatusCode != http.StatusOK || !strings.Contains(body, "确认清除") {
		t.Fatalf("confirm %d %s", res.StatusCode, body)
	}
	res = h.c.do(http.MethodPost, "/pending/clear", url.Values{"csrf": {csrf}, "confirm": {"yes"}}.Encode())
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("clear %d %s", res.StatusCode, readBody(t, res))
	}
	res.Body.Close()
	if _, err := os.Stat(broken); !os.IsNotExist(err) {
		t.Fatalf("broken kept: %v", err)
	}
	left, err := os.ReadDir(pending)
	if err != nil || len(left) == 0 {
		t.Fatalf("valid pending removed: %v %v", left, err)
	}
	_, body = h.home()
	if strings.Contains(body, "无法重试") || strings.Contains(body, knownKey) {
		t.Fatalf("warning or key remained: %s", body)
	}
}

func TestDeleteScrubFailureIsNotHTTP500(t *testing.T) {
	h := newHarness(t)
	h.createAdmin()
	h.login()
	sum, lower, err := vanity.AddressFromPrivateKeyHex(knownKey)
	if err != nil {
		t.Fatal(err)
	}
	id, err := h.st.SaveResult(h.key, store.NewResult{
		Rule: "8A", Length: 8, Checksum: sum, Lower: lower, PrivHex: knownKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	restore := store.SetScrubHook(func(*sql.DB, string) error { return errors.New("vacuum") })
	defer restore()
	csrf, _ := h.home()
	res := h.c.do(http.MethodPost, "/results/"+itoa(id)+"/delete", url.Values{"csrf": {csrf}, "confirm": {"yes"}}.Encode())
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete %d %s", res.StatusCode, readBody(t, res))
	}
	res.Body.Close()
	if _, err := h.st.Get(id); err == nil || err.Error() != "not_found" {
		t.Fatalf("row kept: %v", err)
	}
	h.logMu.Lock()
	joined := strings.Join(h.logs, "\n")
	h.logMu.Unlock()
	if !strings.Contains(joined, "scrub") || strings.Contains(joined, knownKey) {
		t.Fatalf("scrub log missing or leaked: %s", joined)
	}
}

func TestHomeExplainsProbedCPUs(t *testing.T) {
	b, err := embedded.ReadFile("templates/home.html")
	if err != nil {
		t.Fatal(err)
	}
	page := string(b)
	for _, banned := range []string{"两颗物理", "面板上的 90%"} {
		if strings.Contains(page, banned) {
			t.Fatalf("home still says %q", banned)
		}
	}
	if !strings.Contains(page, "当前可用 {{.UsableCPUs}} 个逻辑核") {
		t.Fatal("home does not show probed usable CPUs")
	}
	for _, need := range []string{"容器配额不足 1 个逻辑核", "容器配额不到 1%", "没有读到容器 CPU 配额"} {
		if !strings.Contains(page, need) {
			t.Fatalf("home does not warn about quota cap %q", need)
		}
	}
}

func TestHomeRendersUnreadQuota(t *testing.T) {
	tmpl, err := template.ParseFS(embedded, "templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "home", view{QuotaUnknown: true, UsableCPUs: 40, HostCPUs: 40, CPU: 90}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "没有读到容器 CPU 配额") {
		t.Fatal("unread quota was not rendered")
	}
	buf.Reset()
	if err := tmpl.ExecuteTemplate(&buf, "home", view{UsableCPUs: 40, HostCPUs: 40, CPU: 90}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "没有读到容器 CPU 配额") {
		t.Fatal("warned without an unread quota")
	}
}

func itoa(n int64) string {
	return strconv.FormatInt(n, 10)
}
