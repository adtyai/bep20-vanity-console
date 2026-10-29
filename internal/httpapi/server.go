package httpapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"errors"
	"html/template"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"bep20-vanity-console/internal/auth"
	"bep20-vanity-console/internal/config"
	"bep20-vanity-console/internal/job"
	"bep20-vanity-console/internal/store"
	"bep20-vanity-console/internal/vanity"
)

//go:embed templates/*.html assets/app.js assets/app.css
var embedded embed.FS

type Server struct {
	store      *store.Store
	runner     *job.Runner
	auth       *auth.Manager
	setupToken string
	tmpl       *template.Template
	loc        *time.Location
	logf       job.Logger
}

type view struct {
	Title         string
	Refresh       bool
	CSRF          string
	Error         string
	Username      string
	Running       bool
	Exiting       bool
	Stoppable     bool
	CPU           int
	HostCPUs      int
	UsableCPUs    int
	DutyCap       int
	QuotaUnknown  bool
	Attempts      uint64
	Speed         string
	Runtime       string
	Rules         []ruleView
	Message       string
	Action        string
	AddressHead   string
	AddressTail   string
	Address       string
	Priv          string
	Found         string
	LengthLabel   string
	SaveWarning   string
	BrokenWarning string
}

type ruleView struct {
	ID      string
	Field   string
	Title   string
	Note    string
	Enabled bool
	Last    string
	ETA     string
	Rows    []rowView
}

type rowView struct {
	ID          int64
	Head        string
	Tail        string
	Checksum    string
	Found       string
	LengthLabel string
}

var ruleMeta = []struct {
	ID, Field, Title, Note string
}{
	{"8A", "r8a", "8A", "结尾恰好 8 位相同数字"},
	{"9A", "r9a", "9A", "结尾至少 9 位相同数字"},
	{"1-8", "r18", "1-8", "以 12345678 结束"},
	{"1-9", "r19", "1-9", "以 123456789 结束"},
}

func New(st *store.Store, runner *job.Runner, manager *auth.Manager, setupToken string, logf job.Logger) (http.Handler, error) {
	tmpl, err := template.ParseFS(embedded, "templates/*.html")
	if err != nil {
		return nil, err
	}
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		loc = time.FixedZone("Asia/Shanghai", 8*3600)
	}
	if logf == nil {
		logf = func(string, string, int64, uint64, string) {}
	}
	s := &Server{
		store:      st,
		runner:     runner,
		auth:       manager,
		setupToken: setupToken,
		tmpl:       tmpl,
		loc:        loc,
		logf:       logf,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /setup", s.setupGET)
	mux.HandleFunc("POST /setup", s.setupPOST)
	mux.HandleFunc("GET /login", s.loginGET)
	mux.HandleFunc("POST /login", s.loginPOST)
	mux.HandleFunc("POST /logout", s.logoutPOST)
	mux.HandleFunc("GET /{$}", s.homeGET)
	mux.HandleFunc("POST /start", s.startPOST)
	mux.HandleFunc("POST /stop", s.stopPOST)
	mux.HandleFunc("POST /cpu", s.cpuPOST)
	mux.HandleFunc("POST /rules", s.rulesPOST)
	mux.HandleFunc("GET /results", s.resultsGET)
	mux.HandleFunc("POST /results/{id}/reveal", s.revealPOST)
	mux.HandleFunc("POST /results/{id}/delete", s.deletePOST)
	mux.HandleFunc("POST /pending/clear", s.clearBrokenPOST)
	mux.HandleFunc("GET /assets/app.js", s.assetJS)
	mux.HandleFunc("GET /assets/app.css", s.assetCSS)
	mux.HandleFunc("/", s.notFound)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		defer func() {
			if recover() != nil {
				s.logf("error", "", 0, 0, "panic")
				http.Error(w, "内部错误", http.StatusInternalServerError)
			}
		}()
		mux.ServeHTTP(w, r)
	}), nil
}

func (s *Server) setupGET(w http.ResponseWriter, r *http.Request) {
	ok, err := s.store.HasAdmin()
	if err != nil {
		s.logf("error", "", 0, 0, "store")
		s.writeError(w, http.StatusInternalServerError, "内部错误")
		return
	}
	if ok {
		s.writeError(w, http.StatusNotFound, "未找到")
		return
	}
	s.render(w, http.StatusOK, "setup", view{Title: "创建管理员", CSRF: s.setBoot(w, r)})
}

func (s *Server) setupPOST(w http.ResponseWriter, r *http.Request) {
	ok, err := s.store.HasAdmin()
	if err != nil {
		s.logf("error", "", 0, 0, "store")
		s.writeError(w, http.StatusInternalServerError, "内部错误")
		return
	}
	if ok {
		s.writeError(w, http.StatusNotFound, "未找到")
		return
	}
	if !s.parse(w, r) || !s.checkBoot(w, r) {
		return
	}
	if !tokenEqual(r.FormValue("setup_token"), s.setupToken) {
		s.render(w, http.StatusOK, "setup", view{Title: "创建管理员", CSRF: s.setBoot(w, r), Error: "创建失败", Username: strings.TrimSpace(r.FormValue("username"))})
		return
	}
	err = s.auth.CreateAdmin(strings.TrimSpace(r.FormValue("username")), r.FormValue("password"), r.FormValue("password2"))
	if err != nil {
		msg := "创建失败"
		switch {
		case errors.Is(err, auth.ErrUsername):
			msg = "请填写用户名"
		case errors.Is(err, auth.ErrPassword):
			if r.FormValue("password") != r.FormValue("password2") {
				msg = "两次密码不一致"
			} else {
				msg = "密码至少 16 位"
			}
		}
		s.render(w, http.StatusOK, "setup", view{Title: "创建管理员", CSRF: s.setBoot(w, r), Error: msg, Username: strings.TrimSpace(r.FormValue("username"))})
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) loginGET(w http.ResponseWriter, r *http.Request) {
	ok, err := s.store.HasAdmin()
	if err != nil {
		s.logf("error", "", 0, 0, "store")
		s.writeError(w, http.StatusInternalServerError, "内部错误")
		return
	}
	if !ok {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if _, ok := s.session(w, r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, http.StatusOK, "login", view{Title: "登录", CSRF: s.setBoot(w, r)})
}

func (s *Server) loginPOST(w http.ResponseWriter, r *http.Request) {
	if !s.parse(w, r) || !s.checkBoot(w, r) {
		return
	}
	sess, err := s.auth.Login(strings.TrimSpace(r.FormValue("username")), r.FormValue("password"))
	if err != nil {
		msg := "用户名或密码错误"
		status := http.StatusOK
		if errors.Is(err, auth.ErrLocked) {
			msg = "登录已锁定"
			status = http.StatusTooManyRequests
		}
		s.render(w, status, "login", view{Title: "登录", CSRF: s.setBoot(w, r), Error: msg, Username: strings.TrimSpace(r.FormValue("username"))})
		return
	}
	s.setSession(w, r, sess.ID)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logoutPOST(w http.ResponseWriter, r *http.Request) {
	if !s.parse(w, r) {
		return
	}
	sess, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	s.auth.Logout(sess.ID)
	s.setCookie(w, r, "vanity_session", "", -1)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) homeGET(w http.ResponseWriter, r *http.Request) {
	ok, err := s.store.HasAdmin()
	if err != nil {
		s.logf("error", "", 0, 0, "store")
		s.writeError(w, http.StatusInternalServerError, "内部错误")
		return
	}
	if !ok {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	sess, ok := s.session(w, r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.renderHome(w, sess)
}

func (s *Server) startPOST(w http.ResponseWriter, r *http.Request) {
	if !s.parse(w, r) {
		return
	}
	if _, ok := s.requireSession(w, r); !ok {
		return
	}
	if err := s.runner.Start(); err != nil {
		s.logf("error", "", 0, 0, "save")
		s.writeError(w, http.StatusInternalServerError, "内部错误")
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) stopPOST(w http.ResponseWriter, r *http.Request) {
	if !s.parse(w, r) {
		return
	}
	sess, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	if r.FormValue("confirm") != "yes" {
		s.render(w, http.StatusOK, "confirm", view{
			Title:   "确认停止",
			CSRF:    sess.CSRF,
			Message: "确认停止生成？已找到的结果会保留。",
			Action:  "/stop",
		})
		return
	}
	if err := s.runner.Stop(); err != nil {
		s.logf("error", "", 0, 0, "save")
		s.writeError(w, http.StatusInternalServerError, "内部错误")
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) cpuPOST(w http.ResponseWriter, r *http.Request) {
	if !s.parse(w, r) {
		return
	}
	if _, ok := s.requireSession(w, r); !ok {
		return
	}
	n, err := strconv.Atoi(r.FormValue("percent"))
	if err != nil || errors.Is(config.ValidateCPU(n), config.ErrCPU) {
		s.writeError(w, http.StatusBadRequest, "拒绝")
		return
	}
	if err := s.runner.SetCPU(n); err != nil {
		s.logf("error", "", 0, 0, "save")
		s.writeError(w, http.StatusInternalServerError, "内部错误")
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) rulesPOST(w http.ResponseWriter, r *http.Request) {
	if !s.parse(w, r) {
		return
	}
	if _, ok := s.requireSession(w, r); !ok {
		return
	}
	rules := map[string]bool{
		"8A":  r.FormValue("r8a") == "1",
		"9A":  r.FormValue("r9a") == "1",
		"1-8": r.FormValue("r18") == "1",
		"1-9": r.FormValue("r19") == "1",
	}
	if err := s.runner.SetRules(rules); err != nil {
		s.logf("error", "", 0, 0, "save")
		s.writeError(w, http.StatusInternalServerError, "内部错误")
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) resultsGET(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.session(w, r); !ok {
		s.writeError(w, http.StatusUnauthorized, "没有权限")
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) revealPOST(w http.ResponseWriter, r *http.Request) {
	if !s.parse(w, r) {
		return
	}
	if _, ok := s.requireSession(w, r); !ok {
		return
	}
	id, ok := s.resultID(w, r)
	if !ok {
		return
	}
	rec, err := s.store.Get(id)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "未找到")
		return
	}
	plain, err := decryptResult(s.runnerKey(), rec)
	if err != nil {
		s.logf("error", rec.Rule, id, 0, "decrypt")
		s.writeError(w, http.StatusConflict, "数据错误")
		return
	}
	sum, lower, err := vanity.AddressFromPrivateKeyHex(plain)
	if err != nil || !strings.EqualFold(sum, rec.Checksum) || lower != rec.Lower {
		s.logf("error", rec.Rule, id, 0, "address_mismatch")
		s.writeError(w, http.StatusConflict, "数据错误")
		return
	}
	head, tail, err := vanity.SplitChecksum(sum, rec.Length)
	if err != nil {
		s.logf("error", rec.Rule, id, 0, "address_mismatch")
		s.writeError(w, http.StatusConflict, "数据错误")
		return
	}
	raw := strings.TrimPrefix(strings.ToLower(plain), "0x")
	s.logf("reveal", rec.Rule, id, 1, "")
	s.render(w, http.StatusOK, "reveal", view{
		Title:       "BEP20 自用靓号台",
		AddressHead: head,
		AddressTail: tail,
		Address:     sum,
		Priv:        "0x" + raw,
		Found:       formatShanghai(rec.CreatedAt, s.loc),
		LengthLabel: lengthLabel(rec.Rule, rec.Length),
	})
}

func (s *Server) deletePOST(w http.ResponseWriter, r *http.Request) {
	if !s.parse(w, r) {
		return
	}
	sess, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	id, ok := s.resultID(w, r)
	if !ok {
		return
	}
	if r.FormValue("confirm") != "yes" {
		s.render(w, http.StatusOK, "confirm", view{
			Title:   "确认删除",
			CSRF:    sess.CSRF,
			Message: "确认删除这条结果？列表会去掉这一行，并覆盖库里的密文，同时覆盖待写文件中的密文。已经复制走的私钥仍然有效。",
			Action:  "/results/" + strconv.FormatInt(id, 10) + "/delete",
		})
		return
	}
	if err := s.runner.DeleteResult(id); err != nil {
		if err.Error() == "not_found" {
			s.writeError(w, http.StatusNotFound, "未找到")
			return
		}
		s.logf("error", "", id, 0, "save")
		s.writeError(w, http.StatusInternalServerError, "内部错误")
		return
	}
	s.logf("delete", "", id, 0, "")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) renderHome(w http.ResponseWriter, sess auth.Session) {
	snap := s.runner.Snapshot()
	page := view{
		Title:         "BEP20 自用靓号台",
		Refresh:       snap.Running || snap.Exiting,
		CSRF:          sess.CSRF,
		Running:       snap.Running,
		Exiting:       snap.Exiting,
		Stoppable:     snap.Stoppable,
		CPU:           snap.CPU,
		HostCPUs:      snap.HostCPUs,
		UsableCPUs:    snap.UsableCPUs,
		DutyCap:       snap.DutyCap,
		QuotaUnknown:  snap.QuotaUnknown,
		Attempts:      snap.Attempts,
		Speed:         speedText(snap),
		Runtime:       runtimeText(snap.Runtime),
		SaveWarning:   saveWarning(snap.Unsaved),
		BrokenWarning: brokenWarning(snap.Broken),
	}
	for _, meta := range ruleMeta {
		lastText := "尚无"
		if t, ok, err := s.store.LastHit(meta.ID); err != nil {
			s.logf("error", meta.ID, 0, 0, "store")
			s.writeError(w, http.StatusInternalServerError, "内部错误")
			return
		} else if ok {
			lastText = formatShanghai(t, s.loc)
		}
		rows, err := s.store.List(meta.ID)
		if err != nil {
			s.logf("error", meta.ID, 0, 0, "store")
			s.writeError(w, http.StatusInternalServerError, "内部错误")
			return
		}
		item := ruleView{
			ID:      meta.ID,
			Field:   meta.Field,
			Title:   meta.Title,
			Note:    meta.Note,
			Enabled: snap.Rules[meta.ID],
			Last:    lastText,
			ETA:     etaText(meta.ID, snap),
		}
		for _, row := range rows {
			head, tail, err := vanity.SplitChecksum(row.Checksum, row.Length)
			if err != nil {
				continue
			}
			item.Rows = append(item.Rows, rowView{
				ID:          row.ID,
				Head:        head,
				Tail:        tail,
				Checksum:    row.Checksum,
				Found:       formatShanghai(row.CreatedAt, s.loc),
				LengthLabel: lengthLabel(row.Rule, row.Length),
			})
		}
		page.Rules = append(page.Rules, item)
	}
	s.render(w, http.StatusOK, "home", page)
}

func (s *Server) resultID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		s.writeError(w, http.StatusNotFound, "未找到")
		return 0, false
	}
	return id, true
}

func (s *Server) parse(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		s.writeError(w, http.StatusBadRequest, "拒绝")
		return false
	}
	return true
}

func (s *Server) checkBoot(w http.ResponseWriter, r *http.Request) bool {
	c, err := r.Cookie("vanity_boot")
	if err != nil || !s.auth.CheckBoot(c.Value, r.FormValue("csrf")) {
		s.writeError(w, http.StatusBadRequest, "拒绝")
		return false
	}
	return true
}

func (s *Server) requireSession(w http.ResponseWriter, r *http.Request) (auth.Session, bool) {
	sess, ok := s.session(w, r)
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "没有权限")
		return auth.Session{}, false
	}
	if subtle.ConstantTimeCompare([]byte(sess.CSRF), []byte(r.FormValue("csrf"))) != 1 {
		s.writeError(w, http.StatusBadRequest, "拒绝")
		return auth.Session{}, false
	}
	return sess, true
}

func (s *Server) session(w http.ResponseWriter, r *http.Request) (auth.Session, bool) {
	c, err := r.Cookie("vanity_session")
	if err != nil {
		return auth.Session{}, false
	}
	sess, ok := s.auth.Session(c.Value)
	if !ok {
		return auth.Session{}, false
	}
	s.setSession(w, r, sess.ID)
	return sess, true
}

func (s *Server) setBoot(w http.ResponseWriter, r *http.Request) string {
	id, token := s.auth.IssueBoot()
	s.setCookie(w, r, "vanity_boot", id, 1800)
	return token
}

func (s *Server) setSession(w http.ResponseWriter, r *http.Request, id string) {
	s.setCookie(w, r, "vanity_session", id, int((7 * 24 * time.Hour).Seconds()))
}

func (s *Server) setCookie(w http.ResponseWriter, r *http.Request, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   cookieSecure(r),
		MaxAge:   maxAge,
	})
}

func cookieSecure(r *http.Request) bool {
	if r != nil && r.TLS != nil {
		return true
	}
	if r == nil {
		return false
	}
	proto := r.Header.Get("X-Forwarded-Proto")
	if i := strings.Index(proto, ","); i >= 0 {
		proto = proto[:i]
	}
	return strings.EqualFold(strings.TrimSpace(proto), "https")
}

func (s *Server) render(w http.ResponseWriter, status int, name string, page view) {
	if status == 0 {
		status = http.StatusOK
	}
	if page.Title == "" {
		page.Title = "BEP20 自用靓号台"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.tmpl.ExecuteTemplate(w, name, page); err != nil {
		s.logf("error", "", 0, 0, "template")
	}
}

func (s *Server) notFound(w http.ResponseWriter, r *http.Request) {
	s.writeError(w, http.StatusNotFound, "未找到")
}

func (s *Server) clearBrokenPOST(w http.ResponseWriter, r *http.Request) {
	if !s.parse(w, r) {
		return
	}
	sess, ok := s.requireSession(w, r)
	if !ok {
		return
	}
	if r.FormValue("confirm") != "yes" {
		s.render(w, http.StatusOK, "confirm", view{
			Title:   "确认清除",
			CSRF:    sess.CSRF,
			Message: "确认清除损坏的待写文件？能导入的文件会保留。损坏文件里的密文会被覆盖后删除。",
			Action:  "/pending/clear",
		})
		return
	}
	n, err := s.runner.ClearBroken()
	if err != nil {
		s.logf("error", "", 0, 0, "pending")
		s.writeError(w, http.StatusInternalServerError, "内部错误")
		return
	}
	s.logf("clear", "", 0, uint64(n), "pending")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func saveWarning(n int) string {
	if n <= 0 {
		return ""
	}
	return "有命中尚未写入数据库。已落到待写文件的会在下次启动导入。请勿强制结束进程。"
}

func brokenWarning(n int) string {
	if n <= 0 {
		return ""
	}
	return "有待写文件已损坏，无法重试。可以清除这些损坏文件。"
}

func (s *Server) writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.tmpl.ExecuteTemplate(w, "error", view{Title: "BEP20 自用靓号台", Error: msg}); err != nil {
		s.logf("error", "", 0, 0, "template")
		_, _ = io.WriteString(w, "内部错误")
	}
}

func (s *Server) assetJS(w http.ResponseWriter, r *http.Request) {
	s.asset(w, "assets/app.js", "text/javascript; charset=utf-8")
}

func (s *Server) assetCSS(w http.ResponseWriter, r *http.Request) {
	s.asset(w, "assets/app.css", "text/css; charset=utf-8")
}

func (s *Server) asset(w http.ResponseWriter, name, contentType string) {
	b, err := embedded.ReadFile(name)
	if err != nil {
		s.writeError(w, http.StatusNotFound, "未找到")
		return
	}
	w.Header().Set("Content-Type", contentType)
	_, _ = w.Write(b)
}

func (s *Server) runnerKey() []byte {
	return s.runner.Key()
}

func decryptResult(key []byte, rec store.ResultSecret) (string, error) {
	plain, err := decrypt(key, rec)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func lengthLabel(rule string, n int) string {
	if rule == "9A" {
		return strconv.Itoa(n) + " 位"
	}
	return rule
}

func tokenEqual(a, b string) bool {
	ah := sha256.Sum256([]byte(a))
	bh := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(ah[:], bh[:]) == 1
}
