package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestProbeSignerVerify(t *testing.T) {
	ps := &probeSigner{active: "k1", keys: map[string][]byte{"k1": randomBytes(32), "k0": randomBytes(32)}}
	now := time.Unix(2_000_000, 0)
	v := ps.sign("abc", 3, now.Add(time.Hour))
	if !ps.verify("abc", v, 3, now) {
		t.Fatal("有效 Cookie 应通过")
	}
	parts := strings.Split(v, ".")
	bad := map[string]string{
		"伪造值 1":     "1",
		"签名被改":      strings.Join(append(parts[:4:4], "AAAA"+parts[4][4:]), "."),
		"未知 kid":    strings.Join([]string{"v1", "kx", parts[2], parts[3], parts[4]}, "."),
		"改过期时间":     strings.Join([]string{"v1", parts[1], parts[2], "9999999999", parts[4]}, "."),
		"改版本号":      strings.Join([]string{"v1", parts[1], "4", parts[3], parts[4]}, "."),
		"段数不对":      "v1.k1.3",
		"其他 kid 签名": ps.signWith("k0", "abc", 3, now.Add(time.Hour), "k1"),
	}
	for name, val := range bad {
		if ps.verify("abc", val, 3, now) {
			t.Errorf("%s 不应通过", name)
		}
	}
	if ps.verify("other", v, 3, now) {
		t.Fatal("换探针 ID 不应通过")
	}
	if ps.verify("abc", v, 4, now) {
		t.Fatal("权限版本号变化后不应通过")
	}
	if ps.verify("abc", v, 3, now.Add(2*time.Hour)) {
		t.Fatal("过期后不应通过")
	}
	// 轮换后旧 kid 签发的 Cookie 仍可验证
	old := ps.sign("abc", 3, now.Add(time.Hour))
	ps.active = "k0"
	if !ps.verify("abc", old, 3, now) {
		t.Fatal("轮换后旧密钥签发的 Cookie 应仍有效")
	}
}

// signWith 用 key 签名但在值里声称是 claimKid（测试“kid 与密钥不符”）
func (ps *probeSigner) signWith(keyKid, id string, ver int, exp time.Time, claimKid string) string {
	e := exp.Unix()
	return strings.Join([]string{"v1", claimKid, itoa(ver), itoa64(e), ps.mac(ps.keys[keyKid], id, claimKid, ver, e)}, ".")
}

func itoa(i int) string     { return itoa64(int64(i)) }
func itoa64(i int64) string { b, _ := json.Marshal(i); return string(b) }

func TestMaskIP(t *testing.T) {
	cases := map[string]string{
		"203.0.113.77":          "203.0.*.*",
		"::ffff:203.0.113.77":   "203.0.*.*",
		"2001:db8:1234:5678::1": "2001:db8:*",
		"2400:cb00::1":          "2400:cb00:*",
		"garbage":               "",
	}
	for in, want := range cases {
		if got := maskIP(in); got != want {
			t.Errorf("maskIP(%q) = %q, want %q", in, got, want)
		}
	}
}

func publicWrite() reqOpt {
	return func(r *http.Request) {
		r.Header.Set("Origin", testPublic)
		r.Header.Set("X-SSHWeb", "1")
		r.Header.Set("Content-Type", "application/json")
	}
}

func addLockedProbe(t *testing.T, e *testEnv, id, pass string) {
	t.Helper()
	h, err := hashPassword(pass, viewArgon)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.app.store.AddProbe(&Probe{ID: id, Token: "tok-" + id, ViewPassHash: h}); err != nil {
		t.Fatal(err)
	}
	e.app.probes.report(id, &probeStats{Hostname: "secret-host-" + id, IP: "203.0.113.77", LastSeen: time.Now()})
}

func publicProbes(t *testing.T, e *testEnv, opts ...reqOpt) []map[string]any {
	t.Helper()
	w := do(e.public, http.MethodGet, "/api/probes/public", "", opts...)
	var out []map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestForgedUnlockCookieStaysLocked(t *testing.T) {
	e := newTestEnv(t, false)
	addLockedProbe(t, e, "p1", "view-password-1")
	for _, name := range []string{"__Host-pv_p1", "pv_p1", "probe_unlock_p1"} {
		ps := publicProbes(t, e, cookie(&http.Cookie{Name: name, Value: "1"}))
		if ps[0]["locked"] != true {
			t.Fatalf("伪造 Cookie %s 不应解锁", name)
		}
		if _, ok := ps[0]["hostname"]; ok || strings.Contains(ps[0]["name"].(string), "secret-host") {
			t.Fatalf("锁定探针不应暴露主机名: %v", ps[0])
		}
	}
	if n := e.app.game.probeName("p1"); strings.Contains(n, "secret-host") {
		t.Fatalf("游戏事件不应暴露锁定探针的主机名: %s", n)
	}
}

func TestUnlockFlowAndRevoke(t *testing.T) {
	e := newTestEnv(t, false)
	addLockedProbe(t, e, "p1", "view-password-1")

	if w := do(e.public, http.MethodGet, "/api/probe/unlock?id=p1&pass=view-password-1", ""); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET 解锁应 405, got %d", w.Code)
	}
	if w := do(e.public, http.MethodPost, "/api/probe/unlock", `{"id":"p1","pass":"view-password-1"}`,
		hdr("Origin", "https://evil.example"), hdr("X-SSHWeb", "1"), hdr("Content-Type", "application/json")); w.Code != 403 {
		t.Fatalf("跨站解锁应 403, got %d", w.Code)
	}
	w := do(e.public, http.MethodPost, "/api/probe/unlock", `{"id":"p1","pass":"view-password-1"}`, publicWrite())
	if w.Code != 200 {
		t.Fatalf("正确密码应解锁: %d %s", w.Code, w.Body.String())
	}
	var c *http.Cookie
	for _, ck := range w.Result().Cookies() {
		if ck.Name == "__Host-pv_p1" {
			c = ck
		}
	}
	if c == nil || !c.Secure || !c.HttpOnly || c.Domain != "" || c.Path != "/" {
		t.Fatalf("解锁 Cookie 属性不正确: %+v", c)
	}
	ps := publicProbes(t, e, cookie(c))
	if ps[0]["locked"] == true || ps[0]["hostname"] != "secret-host-p1" || ps[0]["ip"] != "203.0.*.*" && ps[0]["ip"] != "203.0.113.77" {
		t.Fatalf("解锁后应可见: %v", ps[0])
	}

	// 管理员撤销 → 旧 Cookie 失效
	admin := loginCookie(t, e, "correct-horse-battery")
	if w := do(e.admin, http.MethodPost, "/api/probes/revoke", `{"id":"p1"}`, adminWrite(), cookie(admin)); w.Code != 200 {
		t.Fatalf("撤销失败: %d %s", w.Code, w.Body.String())
	}
	if ps := publicProbes(t, e, cookie(c)); ps[0]["locked"] != true {
		t.Fatal("撤销后旧 Cookie 不应再解锁")
	}
}

func TestUnlockBruteForceLockout(t *testing.T) {
	e := newTestEnv(t, false)
	addLockedProbe(t, e, "p1", "view-password-1")
	for i := 0; i < 5; i++ {
		if w := do(e.public, http.MethodPost, "/api/probe/unlock", `{"id":"p1","pass":"wrong-pass"}`, publicWrite()); w.Code != 403 {
			t.Fatalf("错误密码应 403, got %d", w.Code)
		}
	}
	if w := do(e.public, http.MethodPost, "/api/probe/unlock", `{"id":"p1","pass":"view-password-1"}`, publicWrite()); w.Code != 429 {
		t.Fatalf("锁定期内应 429, got %d", w.Code)
	}
	// 不存在的探针同样计数
	for i := 0; i < 5; i++ {
		do(e.public, http.MethodPost, "/api/probe/unlock", `{"id":"nope","pass":"x"}`, publicWrite(), remote("198.51.100.9:1"))
	}
	if w := do(e.public, http.MethodPost, "/api/probe/unlockpass", `{"pass":"view-password-1"}`, publicWrite(), remote("198.51.100.9:1")); w.Code != 429 {
		t.Fatalf("对不存在探针的尝试也应计入锁定, got %d", w.Code)
	}
}

func TestUnlockPass(t *testing.T) {
	e := newTestEnv(t, false)
	addLockedProbe(t, e, "p1", "shared-password")
	addLockedProbe(t, e, "p2", "shared-password")
	addLockedProbe(t, e, "p3", "different-password")
	w := do(e.public, http.MethodPost, "/api/probe/unlockpass", `{"pass":"shared-password"}`, publicWrite())
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"unlocked":2`) {
		t.Fatalf("应解锁 2 只: %d %s", w.Code, w.Body.String())
	}
	var opts []reqOpt
	for _, c := range w.Result().Cookies() {
		opts = append(opts, cookie(c))
	}
	locked := 0
	for _, p := range publicProbes(t, e, opts...) {
		if p["locked"] == true {
			locked++
		}
	}
	if locked != 1 {
		t.Fatalf("应只剩 1 只锁定, got %d", locked)
	}
}

func TestJoinRequiresAdminAndHashesViewPass(t *testing.T) {
	e := newTestEnv(t, false)
	if w := do(e.admin, http.MethodPost, "/api/probe/join", `{"public":false,"viewPass":"view-password-1"}`, adminWrite()); w.Code != 401 {
		t.Fatalf("未登录创建探针应 401, got %d", w.Code)
	}
	admin := loginCookie(t, e, "correct-horse-battery")
	if w := do(e.admin, http.MethodPost, "/api/probe/join", `{"public":false,"viewPass":"short"}`, adminWrite(), cookie(admin)); w.Code != 400 {
		t.Fatalf("过短查看密码应 400, got %d", w.Code)
	}
	if w := do(e.admin, http.MethodPost, "/api/probe/join", `{"public":false,"viewPass":"view-password-1"}`, adminWrite(), cookie(admin)); w.Code != 200 {
		t.Fatalf("创建探针失败: %d %s", w.Code, w.Body.String())
	}
	ps := e.app.store.Probes()
	if len(ps) != 1 || ps[0].ViewPass != "" || !strings.HasPrefix(ps[0].ViewPassHash, "$argon2id$") {
		t.Fatalf("查看密码应只存哈希: %+v", ps)
	}
}

func TestGeoIPOffByDefault(t *testing.T) {
	e := newTestEnv(t, false)
	if cc := e.app.countryCode("8.8.8.8"); cc != "" {
		t.Fatalf("默认不应进行国家识别, got %q", cc)
	}
}

func TestChangeViewPassRevokesOldUnlocks(t *testing.T) {
	e := newTestEnv(t, false)
	addLockedProbe(t, e, "p1", "view-password-1")
	w := do(e.public, http.MethodPost, "/api/probe/unlock", `{"id":"p1","pass":"view-password-1"}`, publicWrite())
	if w.Code != 200 {
		t.Fatalf("旧密码应能解锁: %d", w.Code)
	}
	var old *http.Cookie
	for _, c := range w.Result().Cookies() {
		old = c
	}
	admin := loginCookie(t, e, "correct-horse-battery")

	if w := do(e.admin, http.MethodPost, "/api/probes/viewpass", `{"id":"p1","viewPass":"view-password-2"}`, adminWrite()); w.Code != 401 {
		t.Fatalf("未登录修改查看密码应 401, got %d", w.Code)
	}
	if w := do(e.admin, http.MethodPost, "/api/probes/viewpass", `{"id":"p1","viewPass":"short"}`, adminWrite(), cookie(admin)); w.Code != 400 {
		t.Fatalf("过短的查看密码应 400, got %d", w.Code)
	}
	if w := do(e.admin, http.MethodPost, "/api/probes/viewpass", `{"id":"nope","viewPass":"view-password-2"}`, adminWrite(), cookie(admin)); w.Code != 404 {
		t.Fatalf("不存在的探针应 404, got %d", w.Code)
	}
	if w := do(e.admin, http.MethodPost, "/api/probes/viewpass", `{"id":"p1","viewPass":"view-password-2"}`, adminWrite(), cookie(admin)); w.Code != 200 {
		t.Fatalf("修改查看密码失败: %d %s", w.Code, w.Body.String())
	}

	if ps := publicProbes(t, e, cookie(old)); ps[0]["locked"] != true {
		t.Fatal("改密码后，旧的解锁 Cookie 应失效")
	}
	if w := do(e.public, http.MethodPost, "/api/probe/unlock", `{"id":"p1","pass":"view-password-1"}`, publicWrite()); w.Code != 403 {
		t.Fatalf("旧密码不应再能解锁, got %d", w.Code)
	}
	if w := do(e.public, http.MethodPost, "/api/probe/unlockpass", `{"pass":"view-password-1"}`, publicWrite(), remote("198.51.100.20:1")); w.Code != 403 {
		t.Fatalf("旧密码不应再能通过 unlockpass 解锁, got %d", w.Code)
	}
	if w := do(e.public, http.MethodPost, "/api/probe/unlock", `{"id":"p1","pass":"view-password-2"}`, publicWrite()); w.Code != 200 {
		t.Fatalf("新密码应能解锁, got %d", w.Code)
	}
}

func TestSetViewPassMakesPublicProbeLocked(t *testing.T) {
	e := newTestEnv(t, false)
	if err := e.app.store.AddProbe(&Probe{ID: "pub1", Public: true}); err != nil {
		t.Fatal(err)
	}
	e.app.probes.report("pub1", &probeStats{Hostname: "open-host", LastSeen: time.Now()})
	if ps := publicProbes(t, e); ps[0]["locked"] == true || ps[0]["hostname"] != "open-host" {
		t.Fatalf("公开探针初始应可见: %v", ps[0])
	}
	admin := loginCookie(t, e, "correct-horse-battery")
	if w := do(e.admin, http.MethodPost, "/api/probes/viewpass", `{"id":"pub1","viewPass":"view-password-9"}`, adminWrite(), cookie(admin)); w.Code != 200 {
		t.Fatalf("设置查看密码失败: %d", w.Code)
	}
	ps := publicProbes(t, e)
	if ps[0]["locked"] != true {
		t.Fatal("设置查看密码后应改为密码查看")
	}
	if _, ok := ps[0]["hostname"]; ok {
		t.Fatal("改为密码查看后不应再下发主机名")
	}
	pr := e.app.store.ProbeByID("pub1")
	if pr.Public || !strings.HasPrefix(pr.ViewPassHash, "$argon2id$") || pr.GrantVersion != 1 {
		t.Fatalf("探针记录不正确: %+v", pr)
	}
}
