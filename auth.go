package main

// auth.go — 管理员认证：Argon2id 密码哈希、可撤销的服务端会话、登录/退出/改密码。
//
//   会话：token 只在服务端保存其哈希；空闲超时 + 绝对过期；退出删除服务端记录；
//         改密码撤销全部会话；会话名下登记的终端连接在撤销/过期时一并关闭。
//   Cookie：__Host-sshweb_admin（Secure、Path=/、无 Domain、HttpOnly、SameSite=Strict）

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// ---------------- Argon2id ----------------

type argonParams struct {
	mem     uint32 // KiB
	time    uint32
	threads uint8
	keyLen  uint32
}

var (
	adminArgon = argonParams{mem: 64 * 1024, time: 2, threads: 1, keyLen: 32}
	// 探针查看密码：OWASP 最低推荐参数，解锁接口需要逐个比对
	viewArgon = argonParams{mem: 19 * 1024, time: 2, threads: 1, keyLen: 32}
)

var errHashBusy = errors.New("服务器繁忙，请稍后再试")

// hashSem 限制同时进行的 Argon2 计算，防止被借来耗尽内存和 CPU
var hashSem = make(chan struct{}, 2)

func withHashSlot(fn func()) error {
	select {
	case hashSem <- struct{}{}:
	case <-time.After(5 * time.Second):
		return errHashBusy
	}
	defer func() { <-hashSem }()
	fn()
	return nil
}

var b64 = base64.RawStdEncoding

func hashPassword(pw string, p argonParams) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	var key []byte
	if err := withHashSlot(func() { key = argon2.IDKey([]byte(pw), salt, p.time, p.mem, p.threads, p.keyLen) }); err != nil {
		return "", err
	}
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.mem, p.time, p.threads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// verifyPassword 校验 PHC 格式的 Argon2id 哈希；参数越界的记录一律视为不匹配
func verifyPassword(pw, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, nil
	}
	var ver int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &ver); err != nil || ver != argon2.Version {
		return false, nil
	}
	var p argonParams
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.mem, &p.time, &p.threads); err != nil {
		return false, nil
	}
	if p.mem < 8*1024 || p.mem > 256*1024 || p.time < 1 || p.time > 10 || p.threads < 1 || p.threads > 4 {
		return false, nil
	}
	salt, err1 := b64.DecodeString(parts[4])
	want, err2 := b64.DecodeString(parts[5])
	if err1 != nil || err2 != nil || len(salt) < 8 || len(want) < 16 || len(want) > 64 {
		return false, nil
	}
	var got []byte
	if err := withHashSlot(func() { got = argon2.IDKey([]byte(pw), salt, p.time, p.mem, p.threads, uint32(len(want))) }); err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// ---------------- 会话 ----------------

type adminSession struct {
	created  time.Time
	lastSeen time.Time
	conns    map[uint64]func() // 名下的长连接（终端），撤销时调用关闭
}

type Sessions struct {
	mu       sync.Mutex
	m        map[string]*adminSession // key = 会话 token 的哈希
	idle     time.Duration
	absolute time.Duration
	nextConn uint64
	now      func() time.Time
}

func newSessions(idle, absolute time.Duration) *Sessions {
	return &Sessions{m: map[string]*adminSession{}, idle: idle, absolute: absolute, now: time.Now}
}

func sessionKey(tok string) string {
	h := sha256.Sum256([]byte("sshweb/admin-session/v1|" + tok))
	return hex.EncodeToString(h[:])
}

func (ss *Sessions) newToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	tok := base64.RawURLEncoding.EncodeToString(b)
	now := ss.now()
	ss.mu.Lock()
	ss.m[sessionKey(tok)] = &adminSession{created: now, lastSeen: now, conns: map[uint64]func(){}}
	ss.mu.Unlock()
	return tok
}

func (ss *Sessions) expiredLocked(s *adminSession, now time.Time) bool {
	return now.Sub(s.lastSeen) > ss.idle || now.Sub(s.created) > ss.absolute
}

// valid 校验并刷新空闲计时；已过期的会话会被移除并关闭其连接
func (ss *Sessions) valid(tok string) bool {
	if tok == "" {
		return false
	}
	k := sessionKey(tok)
	ss.mu.Lock()
	s, ok := ss.m[k]
	if !ok {
		ss.mu.Unlock()
		return false
	}
	now := ss.now()
	if ss.expiredLocked(s, now) {
		delete(ss.m, k)
		closers := collectClosers(s)
		ss.mu.Unlock()
		runClosers(closers)
		return false
	}
	s.lastSeen = now
	ss.mu.Unlock()
	return true
}

func collectClosers(s *adminSession) []func() {
	out := make([]func(), 0, len(s.conns))
	for _, fn := range s.conns {
		out = append(out, fn)
	}
	return out
}

func runClosers(fns []func()) {
	for _, fn := range fns {
		fn()
	}
}

func (ss *Sessions) revoke(tok string) {
	ss.mu.Lock()
	s, ok := ss.m[sessionKey(tok)]
	var closers []func()
	if ok {
		delete(ss.m, sessionKey(tok))
		closers = collectClosers(s)
	}
	ss.mu.Unlock()
	runClosers(closers)
}

func (ss *Sessions) revokeAll() {
	ss.mu.Lock()
	var closers []func()
	for k, s := range ss.m {
		closers = append(closers, collectClosers(s)...)
		delete(ss.m, k)
	}
	ss.mu.Unlock()
	runClosers(closers)
}

// attach 在会话名下登记一个长连接。检查会话有效与登记在同一把锁内完成：
// 与退出并发时，要么登记失败（调用方关闭连接），要么登记成功后被退出流程关闭。
func (ss *Sessions) attach(tok string, closeFn func()) (detach func(), ok bool) {
	k := sessionKey(tok)
	ss.mu.Lock()
	defer ss.mu.Unlock()
	s, found := ss.m[k]
	if !found || ss.expiredLocked(s, ss.now()) {
		return nil, false
	}
	ss.nextConn++
	id := ss.nextConn
	s.conns[id] = closeFn
	return func() {
		ss.mu.Lock()
		if cur, ok := ss.m[k]; ok {
			delete(cur.conns, id)
		}
		ss.mu.Unlock()
	}, true
}

// sweep 清理过期会话并关闭其名下连接（由 janitor 定期调用）
func (ss *Sessions) sweep() {
	now := ss.now()
	ss.mu.Lock()
	var closers []func()
	for k, s := range ss.m {
		if ss.expiredLocked(s, now) {
			closers = append(closers, collectClosers(s)...)
			delete(ss.m, k)
		}
	}
	ss.mu.Unlock()
	runClosers(closers)
}

func (ss *Sessions) janitor(every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for range t.C {
		ss.sweep()
	}
}

// ---------------- Cookie ----------------

func (a *App) sessionCookieName() string {
	if a.cfg.secureCookies() {
		return "__Host-sshweb_admin"
	}
	return "sshweb_admin"
}

func (a *App) sessionToken(r *http.Request) string {
	c, err := r.Cookie(a.sessionCookieName())
	if err != nil {
		return ""
	}
	return c.Value
}

func (a *App) setSessionCookie(w http.ResponseWriter, tok string) {
	http.SetCookie(w, &http.Cookie{
		Name: a.sessionCookieName(), Value: tok, Path: "/", HttpOnly: true,
		Secure: a.cfg.secureCookies(), SameSite: http.SameSiteStrictMode,
		MaxAge: int(a.sessions.absolute / time.Second),
	})
}

func (a *App) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: a.sessionCookieName(), Value: "", Path: "/", HttpOnly: true,
		Secure: a.cfg.secureCookies(), SameSite: http.SameSiteStrictMode, MaxAge: -1,
	})
}

// ---------------- 处理函数 ----------------

func tooMany(w http.ResponseWriter, d time.Duration) {
	mins := int(d.Minutes()) + 1
	w.Header().Set("Retry-After", fmt.Sprint(int(d.Seconds())+1))
	writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": fmt.Sprintf("尝试次数过多，请 %d 分钟后再试", mins)})
}

// checkAdminPassword 统一的管理密码校验（含失败计数与锁定）。返回 false 时已写好响应。
func (a *App) checkAdminPassword(w http.ResponseWriter, r *http.Request, pw string, badMsg string) bool {
	ip := a.clientIP(r)
	if b, d := a.loginFails.blocked(ip); b {
		tooMany(w, d)
		return false
	}
	if b, d := a.loginFailsGlobal.blocked("*"); b {
		tooMany(w, d)
		return false
	}
	ok, err := verifyPassword(pw, a.store.AdminHash())
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return false
	}
	if !ok {
		a.loginFails.fail(ip)
		a.loginFailsGlobal.fail("*")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": badMsg})
		return false
	}
	a.loginFails.success(ip)
	return true
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "请求格式错误"})
		return
	}
	if !a.checkAdminPassword(w, r, body.Password, "密码错误") {
		return
	}
	a.setSessionCookie(w, a.sessions.newToken())
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var in struct {
		Old string `json:"old"`
		New string `json:"new"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "请求格式错误"})
		return
	}
	if utf8.RuneCountInString(in.New) < minAdminPasswordLen {
		writeJSON(w, 400, map[string]string{"error": fmt.Sprintf("新密码至少 %d 位", minAdminPasswordLen)})
		return
	}
	if in.New == in.Old {
		writeJSON(w, 400, map[string]string{"error": "新密码不能与原密码相同"})
		return
	}
	if !a.checkAdminPassword(w, r, in.Old, "原密码错误") {
		return
	}
	h, err := hashPassword(in.New, adminArgon)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if err := a.store.SetAdminHash(h); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	// 撤销包括当前在内的全部会话，再给当前用户签发新会话
	a.sessions.revokeAll()
	a.setSessionCookie(w, a.sessions.newToken())
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	a.sessions.revoke(a.sessionToken(r))
	a.clearSessionCookie(w)
	writeJSON(w, 200, map[string]any{"ok": true})
}
