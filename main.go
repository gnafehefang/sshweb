package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"strings"
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

// ---------------- HTTP ----------------

type App struct {
	cfg      *Config
	store    *Store
	sessions *Sessions
	// 管理密码失败计数：按来源 IP，以及全局兜底
	loginFails       *failTracker
	loginFailsGlobal *failTracker
	unlockFails      *failTracker // 探针查看密码失败计数（按来源）
	probeSigner      *probeSigner // 探针解锁 Cookie 签名
	pool             *sshx.Pool
	upgrader         websocket.Upgrader
	game             *gameHub
	probes           *probeRuntime
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
	return a.sessions.valid(a.sessionToken(r))
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
		var in serverInput
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeJSON(w, 400, map[string]string{"error": "请求格式错误"})
			return
		}
		next, code, msg := buildServer(a.store.Get(in.ID), in, time.Now())
		if code != 0 {
			writeJSON(w, code, map[string]string{"error": msg})
			return
		}
		if err := a.store.Put(next); err != nil {
			writeJSON(w, 500, map[string]string{"error": "保存失败"})
			return
		}
		writeJSON(w, 200, sanitize(next))
	default:
		http.Error(w, "method not allowed", 405)
	}
}

type serverInput struct {
	ID, Name, Host, User, AuthKind, Password, PrivateKey, KeyPass, Note, Region string
	Port                                                                        int
}

// buildServer 在副本上应用编辑并完成全部校验；返回非 0 的 code 表示拒绝，此时原记录未被改动。
//   - 修改 Host/Port/User 或切换认证方式时，必须提供当前认证方式的新凭据
//   - 切换认证方式时清空旧方式的凭据字段
//   - 连接目标变化时清除已确认的主机密钥
func buildServer(old *Server, in serverInput, now time.Time) (*Server, int, string) {
	in.Name, in.Host, in.User = strings.TrimSpace(in.Name), strings.TrimSpace(in.Host), strings.TrimSpace(in.User)
	in.Region, in.Note = strings.TrimSpace(in.Region), strings.TrimSpace(in.Note)
	if in.Name == "" || in.Host == "" || in.User == "" {
		return nil, 400, "名称、主机、用户名必填"
	}
	if len([]rune(in.Name)) > 64 || len(in.Host) > 253 || len(in.User) > 64 || len([]rune(in.Region)) > 32 || len([]rune(in.Note)) > 200 {
		return nil, 400, "字段过长"
	}
	if strings.ContainsAny(in.Host, " \t\r\n/@") || strings.ContainsAny(in.User, " \t\r\n") {
		return nil, 400, "主机或用户名包含非法字符"
	}
	if in.Port == 0 {
		in.Port = 22
	}
	if in.Port < 1 || in.Port > 65535 {
		return nil, 400, "端口范围 1-65535"
	}
	if in.AuthKind != "key" {
		in.AuthKind = "password"
	}
	if in.ID != "" && old == nil {
		return nil, 404, "服务器不存在"
	}

	var next Server
	if old != nil {
		next = *old
	} else {
		next = Server{ID: newID(), CreatedAt: now}
	}
	isNew := old == nil
	targetChanged := !isNew && (old.Host != in.Host || old.Port != in.Port || old.User != in.User)
	authChanged := !isNew && old.AuthKind != in.AuthKind
	needSecret := isNew || targetChanged || authChanged

	switch in.AuthKind {
	case "password":
		if needSecret && in.Password == "" {
			if isNew {
				return nil, 400, "请填写登录密码"
			}
			return nil, 400, "修改主机/端口/用户或认证方式时，必须重新填写登录密码"
		}
		next.PrivateKey, next.KeyPass = "", ""
		if in.Password != "" {
			next.Password = in.Password
		}
	case "key":
		if needSecret && in.PrivateKey == "" {
			if isNew {
				return nil, 400, "请粘贴 SSH 私钥"
			}
			return nil, 400, "修改主机/端口/用户或认证方式时，必须重新粘贴 SSH 私钥"
		}
		next.Password = ""
		if in.PrivateKey != "" {
			next.PrivateKey, next.KeyPass = in.PrivateKey, in.KeyPass
		}
	}
	if targetChanged {
		next.HostKey = ""
	}
	next.Name, next.Host, next.Port, next.User, next.AuthKind = in.Name, in.Host, in.Port, in.User, in.AuthKind
	next.Note, next.Region = in.Note, in.Region
	return &next, 0, ""
}

func (a *App) handleServerOne(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/servers/")
	if strings.HasSuffix(path, "/test") {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
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
	// 终端登记到会话名下：退出、改密码、会话过期时连接会被关闭
	detach, ok := a.sessions.attach(a.sessionToken(r), func() { ws.Close() })
	if !ok {
		return
	}
	defer detach()
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
	m.HandleFunc("/api/probe/unlock", publicBrowserWrite(a.handleProbeUnlock))
	m.HandleFunc("/api/probe/unlockpass", publicBrowserWrite(a.handleProbeUnlockPass))
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
	m.HandleFunc("/api/probes/revoke", a.require(a.handleProbeRevoke))
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

func newApp(cfg *Config, store *Store) (*App, error) {
	signer, err := store.loadProbeSigner()
	if err != nil {
		return nil, err
	}
	app := &App{
		cfg:      cfg,
		store:    store,
		sessions: newSessions(2*time.Hour, 12*time.Hour),
		// 每个来源 5 次失败锁 15 分钟（之后翻倍，最长 24 小时）；全局 10 分钟内 50 次失败锁 5 分钟
		loginFails:       newFailTracker(5, 15*time.Minute, 15*time.Minute, 24*time.Hour),
		loginFailsGlobal: newFailTracker(50, 10*time.Minute, 5*time.Minute, time.Hour),
		// 每个来源 1 分钟内 5 次失败锁 1 分钟，之后翻倍，最长 1 小时
		unlockFails: newFailTracker(5, time.Minute, time.Minute, time.Hour),
		probeSigner: signer,
		pool:        sshx.NewPool(),
		upgrader:    websocket.Upgrader{CheckOrigin: wsOriginOK},
	}
	app.probes = newProbeRuntime()
	app.game = newGameHub(store)
	app.game.probeRT = app.probes
	return app, nil
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
	store, err := loadStore(cfg.DataDir, storeOptions{EnableSSH: cfg.EnableSSH, InitialPassword: cfg.InitialPassword})
	if err != nil {
		log.Fatalf("加载数据失败: %v", err)
	}
	app, err := newApp(cfg, store)
	if err != nil {
		log.Fatalf("初始化失败: %v", err)
	}
	go app.sessions.janitor(time.Minute)

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
