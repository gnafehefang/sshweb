package main

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/baiduxc/sshweb/internal/sshx"

	"github.com/gorilla/websocket"
)

//go:embed all:web
var embeddedWeb embed.FS

var version = "0.5.9"

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ---------------- 会话 ----------------

type Sessions struct {
	mu sync.Mutex
	m  map[string]time.Time
}

func (ss *Sessions) valid(tok string) bool {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	exp, ok := ss.m[tok]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(ss.m, tok)
		return false
	}
	ss.m[tok] = time.Now().Add(24 * time.Hour)
	return true
}

func (ss *Sessions) newToken() string {
	b := make([]byte, 24)
	rand.Read(b)
	tok := hex.EncodeToString(b)
	ss.mu.Lock()
	ss.m[tok] = time.Now().Add(24 * time.Hour)
	ss.mu.Unlock()
	return tok
}

// ---------------- HTTP ----------------

type App struct {
	cfg      *Config
	store    *Store
	sessions *Sessions
	pool     *sshx.Pool
	upgrader websocket.Upgrader
	game     *gameHub
	probes   *probeRuntime
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// authOK 只在管理口上可能为 true；公开口一律视为游客
func (a *App) authOK(r *http.Request) bool {
	if !onAdminSite(r) {
		return false
	}
	c, err := r.Cookie("sshweb_session")
	return err == nil && a.sessions.valid(c.Value)
}

// POST /api/admin/clearblocks — 清除全部方块（需管理员登录），并广播给所有在线客户端
func (a *App) handleClearBlocks(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		writeJSON(w, 405, map[string]string{"error": "method not allowed"})
		return
	}
	if err := a.store.ClearBlocks(); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if a.game != nil {
		a.game.broadcast(map[string]any{"t": "clearblocks"}, nil)
		a.game.event("🧹 管理员清除了地图上所有方块")
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) require(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.authOK(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "未登录"})
			return
		}
		next(w, r)
	}
}

func requestIsTLS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "请求格式错误"})
		return
	}
	if subtle.ConstantTimeCompare([]byte(body.Password), []byte(a.store.Password)) != 1 {
		time.Sleep(500 * time.Millisecond)
		writeJSON(w, 401, map[string]string{"error": "密码错误"})
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "sshweb_session", Value: a.sessions.newToken(), Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: 86400, Secure: requestIsTLS(r),
	})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
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
	if len(in.New) < 6 {
		writeJSON(w, 400, map[string]string{"error": "新密码至少 6 位"})
		return
	}
	if subtle.ConstantTimeCompare([]byte(in.Old), []byte(a.store.Password)) != 1 {
		writeJSON(w, 401, map[string]string{"error": "原密码错误"})
		return
	}
	if err := a.store.SetPassword(in.New); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{Name: "sshweb_session", Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (a *App) handleSession(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{
		"loggedIn":  a.authOK(r),
		"version":   version,
		"adminSite": onAdminSite(r),
		"ssh":       a.cfg.EnableSSH && onAdminSite(r),
	})
}

func sanitize(s *Server) map[string]any {
	return map[string]any{
		"id": s.ID, "name": s.Name, "host": s.Host, "port": s.Port,
		"user": s.User, "authKind": s.AuthKind, "note": s.Note, "region": s.Region,
		"hasSecret": s.Password != "" || s.PrivateKey != "",
		"lastUsed":  s.LastUsed, "createdAt": s.CreatedAt,
	}
}

func (a *App) handleServers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		out := []map[string]any{}
		for _, s := range a.store.List() {
			out = append(out, sanitize(s))
		}
		writeJSON(w, 200, out)
	case http.MethodPost:
		var in struct {
			ID, Name, Host, User, AuthKind, Password, PrivateKey, KeyPass, Note, Region string
			Port                                                                        int
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeJSON(w, 400, map[string]string{"error": "请求格式错误"})
			return
		}
		if in.Name == "" || in.Host == "" || in.User == "" {
			writeJSON(w, 400, map[string]string{"error": "名称、主机、用户名必填"})
			return
		}
		if in.Port <= 0 || in.Port > 65535 {
			in.Port = 22
		}
		if in.AuthKind != "key" {
			in.AuthKind = "password"
		}
		sv := a.store.Get(in.ID)
		if sv == nil {
			sv = &Server{ID: newID(), CreatedAt: time.Now()}
		}
		sv.Name, sv.Host, sv.Port, sv.User, sv.AuthKind, sv.Note, sv.Region = in.Name, in.Host, in.Port, in.User, in.AuthKind, in.Note, strings.TrimSpace(in.Region)
		if in.Password != "" {
			sv.Password = in.Password
		}
		if in.PrivateKey != "" {
			sv.PrivateKey, sv.KeyPass = in.PrivateKey, in.KeyPass
		}
		if sv.AuthKind == "password" && sv.Password == "" {
			writeJSON(w, 400, map[string]string{"error": "请填写登录密码"})
			return
		}
		if sv.AuthKind == "key" && sv.PrivateKey == "" {
			writeJSON(w, 400, map[string]string{"error": "请粘贴 SSH 私钥"})
			return
		}
		if err := a.store.Put(sv); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, sanitize(sv))
	default:
		http.Error(w, "method not allowed", 405)
	}
}

func (a *App) handleServerOne(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/servers/")
	if strings.HasSuffix(path, "/test") {
		id := strings.TrimSuffix(path, "/test")
		sv := a.store.Get(id)
		if sv == nil {
			writeJSON(w, 404, map[string]string{"error": "服务器不存在"})
			return
		}
		si := sv.ServerInfo()
		res := sshx.TestConn(&si, 8*time.Second)
		if res.Err != "" {
			writeJSON(w, 200, map[string]any{"ok": false, "error": res.Err})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "hostname": res.Hostname, "uptime": res.Uptime, "uname": res.Uname})
		return
	}
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", 405)
		return
	}
	if path == "" {
		http.Error(w, "need id", 400)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": a.store.Delete(path) == nil})
}

// ---------------- WebSocket 终端 ----------------

func (a *App) handleTerminal(w http.ResponseWriter, r *http.Request) {
	if !a.authOK(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	id := r.URL.Query().Get("server")
	sv := a.store.Get(id)
	if sv == nil {
		http.Error(w, "server not found", 404)
		return
	}
	ws, err := a.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()
	si := sv.ServerInfo()
	if err := a.pool.Attach(ws, &si); err != nil {
		log.Printf("terminal %s@%s: %v", sv.User, sv.Host, err)
	}
	a.store.Touch(id)
}

func (s *Server) ServerInfo() sshx.ServerInfo {
	return sshx.ServerInfo{
		Host: s.Host, Port: s.Port, User: s.User, AuthKind: s.AuthKind,
		Password: s.Password, PrivateKey: s.PrivateKey, KeyPass: s.KeyPass,
	}
}

// 两个监听口共用的路由：静态页、会话状态、农场/探针的公开视图、游戏 WS
func (a *App) registerCommon(m *http.ServeMux) {
	m.HandleFunc("/api/session", a.handleSession)
	m.HandleFunc("/ws/game", a.handleGameWS)
	m.HandleFunc("/api/farm/public", a.handleFarmPublic)
	m.HandleFunc("/api/probes/public", a.handleProbesPublic)

	webFS, _ := fs.Sub(embeddedWeb, "web")
	fileServer := http.FileServer(http.FS(webFS))
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// 静态资源一律协商缓存：浏览器/CDN 每次回源验证（304 无流量），
		// 避免升级后用户拿到旧 JS（曾导致生产环境缓存 4 小时旧版）
		w.Header().Set("Cache-Control", "no-cache, must-revalidate")
		fileServer.ServeHTTP(w, r)
	})
}

// publicHandler 公开口：只有农场展示、探针上报/解锁、安装脚本与 Skill 接口，没有任何管理路由
func (a *App) publicHandler() http.Handler {
	m := http.NewServeMux()
	a.registerCommon(m)
	m.HandleFunc("/api/probe/report", a.handleProbeReport)
	m.HandleFunc("/api/probe/goodbye", a.handleProbeGoodbye)
	m.HandleFunc("/api/probe/unlock", a.handleProbeUnlock)
	m.HandleFunc("/api/probe/unlockpass", a.handleProbeUnlockPass)
	m.HandleFunc("/probe/agent.sh", a.handleProbeAgentScript)
	m.HandleFunc("/probe/uninstall.sh", a.handleProbeUninstallScript)
	m.HandleFunc("/api/skill/blocks", a.handleSkillBlocks)
	m.HandleFunc("/api/skill/player", a.handleSkillPlayer)
	m.HandleFunc("/api/skill/state", a.handleSkillState)
	st := &site{admin: false, origin: a.cfg.PublicOrigin}
	return withSite(st, m)
}

// adminHandler 管理口：全部管理路由；/api/* 统一经过 Origin/CSRF 校验
func (a *App) adminHandler() http.Handler {
	m := http.NewServeMux()
	a.registerCommon(m)
	m.HandleFunc("/api/login", a.handleLogin)
	m.HandleFunc("/api/logout", a.require(a.handleLogout))
	m.HandleFunc("/api/password", a.require(a.handleChangePassword))
	m.HandleFunc("/api/probe/join", a.require(a.handleProbeJoin))
	m.HandleFunc("/api/probes", a.require(a.handleProbes))
	m.HandleFunc("/api/keys", a.require(a.handleAPIKeys))
	m.HandleFunc("/api/admin/clearblocks", a.require(a.handleClearBlocks))
	if a.cfg.EnableSSH {
		m.HandleFunc("/api/servers", a.require(a.handleServers))
		m.HandleFunc("/api/servers/", a.require(a.handleServerOne))
		m.HandleFunc("/ws/terminal", a.handleTerminal)
	}
	st := &site{admin: true, origin: a.cfg.AdminOrigin}
	return withSite(st, adminAPIGuard(st, m))
}

func newApp(cfg *Config, store *Store) *App {
	app := &App{
		cfg:      cfg,
		store:    store,
		sessions: &Sessions{m: map[string]time.Time{}},
		pool:     sshx.NewPool(),
		upgrader: websocket.Upgrader{CheckOrigin: wsOriginOK},
	}
	app.probes = newProbeRuntime()
	app.game = newGameHub(store)
	app.game.probeRT = app.probes
	return app
}

func newHTTPServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
}

func main() {
	cfg, err := loadConfig(os.Args[1:], os.Getenv, os.Stderr)
	if err != nil {
		log.Fatalf("配置错误: %v", err)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		log.Fatal(err)
	}
	store, err := loadStore(cfg.DataDir, cfg.EnableSSH)
	if err != nil {
		log.Fatalf("加载数据失败: %v", err)
	}
	app := newApp(cfg, store)

	mode := "探针版（SSH 关闭）"
	if cfg.EnableSSH {
		mode = "SSH 已开启"
	}
	fmt.Printf("SSHWeb v%s · %s · 数据 %s\n", version, mode, cfg.DataDir)
	fmt.Printf("  公开口 %s → %s\n", cfg.Listen, cfg.PublicOrigin)

	errc := make(chan error, 2)
	go func() { errc <- newHTTPServer(cfg.Listen, app.publicHandler()).ListenAndServe() }()
	if cfg.AdminListen != "" {
		fmt.Printf("  管理口 %s → %s\n", cfg.AdminListen, cfg.AdminOrigin)
		go func() { errc <- newHTTPServer(cfg.AdminListen, app.adminHandler()).ListenAndServe() }()
	} else {
		fmt.Println("  管理口未启用")
	}
	log.Fatal(<-errc)
}
