package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/websocket"
)

const (
	testPublic = "https://farm.example.com"
	testAdmin  = "https://admin.example.net"
)

type testEnv struct {
	app    *App
	public http.Handler
	admin  http.Handler
}

func newTestEnv(t *testing.T, ssh bool) *testEnv {
	t.Helper()
	env := map[string]string{
		"SSHWEB_PUBLIC_URL": testPublic, "SSHWEB_ADMIN_ORIGIN": testAdmin,
		"SSHWEB_PASSWORD": "correct-horse-battery",
	}
	if ssh {
		env["SSHWEB_ENABLE_SSH"] = "1"
	}
	cfg, err := loadConfig(nil, envMap(env), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	store, err := loadStore(t.TempDir(), storeOptions{EnableSSH: cfg.EnableSSH, InitialPassword: cfg.InitialPassword})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	app, err := newApp(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	return &testEnv{app: app, public: app.publicHandler(), admin: app.adminHandler()}
}

type reqOpt func(*http.Request)

func hdr(k, v string) reqOpt { return func(r *http.Request) { r.Header.Set(k, v) } }
func cookie(c *http.Cookie) reqOpt {
	return func(r *http.Request) { r.AddCookie(c) }
}
func remote(addr string) reqOpt { return func(r *http.Request) { r.RemoteAddr = addr } }

// adminWrite 带齐管理站写请求所需的头
func adminWrite() reqOpt {
	return func(r *http.Request) {
		r.Header.Set("Origin", testAdmin)
		r.Header.Set("X-SSHWeb", "1")
		r.Header.Set("Content-Type", "application/json")
	}
}

func do(h http.Handler, method, path, body string, opts ...reqOpt) *httptest.ResponseRecorder {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	r := httptest.NewRequest(method, path, rd)
	r.RemoteAddr = "192.0.2.10:5555"
	for _, o := range opts {
		o(r)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestPublicSiteHasNoAdminRoutes(t *testing.T) {
	e := newTestEnv(t, true)
	for _, p := range []string{"/api/login", "/api/logout", "/api/password", "/api/servers", "/api/servers/x/test",
		"/ws/terminal", "/api/probe/join", "/api/probes", "/api/keys", "/api/admin/clearblocks"} {
		w := do(e.public, http.MethodPost, p, `{}`, hdr("Origin", testPublic), hdr("X-SSHWeb", "1"), hdr("Content-Type", "application/json"))
		if w.Code != http.StatusNotFound {
			t.Errorf("公开口 %s 应返回 404, got %d", p, w.Code)
		}
	}
}

func TestSSHRoutesAbsentWhenDisabled(t *testing.T) {
	e := newTestEnv(t, false)
	for _, p := range []string{"/api/servers", "/ws/terminal"} {
		if w := do(e.admin, http.MethodGet, p, ""); w.Code != http.StatusNotFound {
			t.Errorf("SSH 关闭时管理口 %s 应 404, got %d", p, w.Code)
		}
	}
}

func TestAdminWriteRequiresOriginHeaderAndJSON(t *testing.T) {
	e := newTestEnv(t, false)
	body := `{"password":"wrong"}`
	cases := []struct {
		name string
		opts []reqOpt
		want int
	}{
		{"跨站 Origin", []reqOpt{hdr("Origin", "https://evil.example"), hdr("X-SSHWeb", "1"), hdr("Content-Type", "application/json")}, 403},
		{"公开站 Origin", []reqOpt{hdr("Origin", testPublic), hdr("X-SSHWeb", "1"), hdr("Content-Type", "application/json")}, 403},
		{"无 Origin 也无 Sec-Fetch-Site", []reqOpt{hdr("X-SSHWeb", "1"), hdr("Content-Type", "application/json")}, 403},
		{"缺 X-SSHWeb", []reqOpt{hdr("Origin", testAdmin), hdr("Content-Type", "application/json")}, 403},
		{"text/plain", []reqOpt{hdr("Origin", testAdmin), hdr("X-SSHWeb", "1"), hdr("Content-Type", "text/plain")}, 403},
		{"齐全（密码错误）", []reqOpt{adminWrite()}, 401},
		{"无 Origin 但 same-origin", []reqOpt{hdr("Sec-Fetch-Site", "same-origin"), hdr("X-SSHWeb", "1"), hdr("Content-Type", "application/json")}, 401},
	}
	for _, c := range cases {
		if w := do(e.admin, http.MethodPost, "/api/login", body, c.opts...); w.Code != c.want {
			t.Errorf("%s: want %d got %d (%s)", c.name, c.want, w.Code, w.Body.String())
		}
	}
}

func TestAdminReadOriginOnlyCheckedWhenPresent(t *testing.T) {
	e := newTestEnv(t, false)
	if w := do(e.admin, http.MethodGet, "/api/session", ""); w.Code != 200 {
		t.Fatalf("同源 GET 不带 Origin 应正常, got %d", w.Code)
	}
	if w := do(e.admin, http.MethodGet, "/api/session", "", hdr("Origin", "https://evil.example")); w.Code != 403 {
		t.Fatalf("GET 带错误 Origin 应 403, got %d", w.Code)
	}
	if w := do(e.admin, http.MethodGet, "/api/session", "", hdr("Origin", testAdmin)); w.Code != 200 {
		t.Fatalf("GET 带正确 Origin 应正常, got %d", w.Code)
	}
}

func loginCookie(t *testing.T, e *testEnv, pw string) *http.Cookie {
	t.Helper()
	w := do(e.admin, http.MethodPost, "/api/login", `{"password":"`+pw+`"}`, adminWrite())
	if w.Code != 200 {
		t.Fatalf("登录失败: %d %s", w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Value != "" {
			return c
		}
	}
	t.Fatal("没有拿到会话 Cookie")
	return nil
}

func sessionLoggedIn(t *testing.T, h http.Handler, c *http.Cookie) bool {
	t.Helper()
	w := do(h, http.MethodGet, "/api/session", "", cookie(c))
	var v struct{ LoggedIn bool }
	json.Unmarshal(w.Body.Bytes(), &v)
	return v.LoggedIn
}

func TestAdminCookieIgnoredOnPublicSite(t *testing.T) {
	e := newTestEnv(t, false)
	c := loginCookie(t, e, "correct-horse-battery")
	if !sessionLoggedIn(t, e.admin, c) {
		t.Fatal("管理口应识别会话")
	}
	if sessionLoggedIn(t, e.public, c) {
		t.Fatal("公开口不应识别管理会话")
	}
}

func TestSecurityHeaders(t *testing.T) {
	e := newTestEnv(t, false)
	w := do(e.public, http.MethodGet, "/", "")
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") ||
		!strings.Contains(csp, "wss://farm.example.com") {
		t.Fatalf("CSP 不正确: %q", csp)
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("缺少 nosniff")
	}
	w = do(e.admin, http.MethodGet, "/api/session", "")
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "wss://admin.example.net") {
		t.Fatal("管理口 CSP 应放行管理站 wss")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("API 响应应 no-store")
	}
}

func TestWebSocketOriginStrict(t *testing.T) {
	e := newTestEnv(t, false)
	srv := httptest.NewServer(e.public)
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws/game"
	for _, o := range []string{"", "https://evil.example", testAdmin} {
		h := http.Header{}
		if o != "" {
			h.Set("Origin", o)
		}
		c, resp, err := websocket.DefaultDialer.Dial(url, h)
		if err == nil {
			c.Close()
			t.Fatalf("Origin=%q 不应握手成功", o)
		}
		if resp == nil || resp.StatusCode != http.StatusForbidden {
			t.Fatalf("Origin=%q 应 403, got %v", o, resp)
		}
	}
	h := http.Header{}
	h.Set("Origin", testPublic)
	c, _, err := websocket.DefaultDialer.Dial(url, h)
	if err != nil {
		t.Fatalf("正确 Origin 应握手成功: %v", err)
	}
	c.Close()
}
