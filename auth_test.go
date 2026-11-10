package main

import (
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestArgon2RoundTrip(t *testing.T) {
	h, err := hashPassword("s3cret-password!", viewArgon)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("PHC 格式不对: %s", h)
	}
	if ok, _ := verifyPassword("s3cret-password!", h); !ok {
		t.Fatal("正确密码应通过")
	}
	if ok, _ := verifyPassword("s3cret-password?", h); ok {
		t.Fatal("错误密码不应通过")
	}
	for _, bad := range []string{"", "plaintext", strings.Replace(h, "m=19456", "m=999999", 1), strings.Replace(h, "argon2id", "argon2i", 1)} {
		if ok, _ := verifyPassword("s3cret-password!", bad); ok {
			t.Fatalf("异常记录不应通过: %q", bad)
		}
	}
}

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func TestSessionExpiryAndRevoke(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	ss := newSessions(30*time.Minute, 2*time.Hour)
	ss.now = clk.now

	a := ss.newToken()
	if !ss.valid(a) {
		t.Fatal("新会话应有效")
	}
	clk.t = clk.t.Add(29 * time.Minute)
	if !ss.valid(a) {
		t.Fatal("空闲未超时应有效")
	}
	clk.t = clk.t.Add(31 * time.Minute)
	if ss.valid(a) {
		t.Fatal("空闲超时应失效")
	}

	b := ss.newToken()
	for i := 0; i < 9; i++ { // 一直活跃，但超过绝对期限
		clk.t = clk.t.Add(15 * time.Minute)
		ss.valid(b)
	}
	if ss.valid(b) {
		t.Fatal("超过绝对期限应失效")
	}

	c, d := ss.newToken(), ss.newToken()
	ss.revoke(c)
	if ss.valid(c) || !ss.valid(d) {
		t.Fatal("revoke 只应撤销指定会话")
	}
	ss.revokeAll()
	if ss.valid(d) {
		t.Fatal("revokeAll 应撤销全部")
	}
}

func TestSessionAttachedConnsClosed(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	ss := newSessions(30*time.Minute, 2*time.Hour)
	ss.now = clk.now

	var closed atomic.Int32
	tok := ss.newToken()
	detach, ok := ss.attach(tok, func() { closed.Add(1) })
	if !ok {
		t.Fatal("有效会话应能登记连接")
	}
	detach()
	ss.revoke(tok)
	if closed.Load() != 0 {
		t.Fatal("已注销的连接不应被关闭回调")
	}

	tok = ss.newToken()
	ss.attach(tok, func() { closed.Add(1) })
	ss.revoke(tok)
	if closed.Load() != 1 {
		t.Fatal("退出时应关闭会话名下的连接")
	}
	if _, ok := ss.attach(tok, func() {}); ok {
		t.Fatal("已撤销的会话不应能登记连接")
	}

	tok = ss.newToken()
	ss.attach(tok, func() { closed.Add(1) })
	clk.t = clk.t.Add(31 * time.Minute)
	ss.sweep()
	if closed.Load() != 2 {
		t.Fatal("会话自然过期后应关闭其连接")
	}
}

// 退出与建连并发：结束后不能留下“已撤销会话持有的连接”
func TestSessionLogoutAttachRace(t *testing.T) {
	ss := newSessions(time.Hour, time.Hour)
	for i := 0; i < 300; i++ {
		tok := ss.newToken()
		var closed, attached atomic.Bool
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, ok := ss.attach(tok, func() { closed.Store(true) }); ok {
				attached.Store(true)
			}
		}()
		go func() { defer wg.Done(); ss.revoke(tok) }()
		wg.Wait()
		if attached.Load() && !closed.Load() {
			t.Fatalf("第 %d 轮：连接登记成功但退出后未被关闭", i)
		}
	}
}

func TestLogoutInvalidatesCookie(t *testing.T) {
	e := newTestEnv(t, false)
	c := loginCookie(t, e, "correct-horse-battery")
	if c.Name != "__Host-sshweb_admin" || !c.Secure || !c.HttpOnly || c.Path != "/" || c.SameSite != http.SameSiteStrictMode || c.Domain != "" {
		t.Fatalf("会话 Cookie 属性不正确: %+v", c)
	}
	if w := do(e.admin, http.MethodPost, "/api/logout", "", adminWrite(), cookie(c)); w.Code != 200 {
		t.Fatalf("退出失败: %d", w.Code)
	}
	if sessionLoggedIn(t, e.admin, c) {
		t.Fatal("退出后旧 Cookie 不应再有效")
	}
	if w := do(e.admin, http.MethodGet, "/api/keys", "", cookie(c)); w.Code != 401 {
		t.Fatalf("退出后访问管理接口应 401, got %d", w.Code)
	}
}

func TestChangePasswordRevokesOtherSessions(t *testing.T) {
	e := newTestEnv(t, false)
	c1 := loginCookie(t, e, "correct-horse-battery")
	c2 := loginCookie(t, e, "correct-horse-battery")
	if w := do(e.admin, http.MethodPost, "/api/password", `{"old":"correct-horse-battery","new":"short"}`, adminWrite(), cookie(c1)); w.Code != 400 {
		t.Fatalf("过短的新密码应被拒绝, got %d", w.Code)
	}
	w := do(e.admin, http.MethodPost, "/api/password", `{"old":"correct-horse-battery","new":"another-long-password"}`, adminWrite(), cookie(c1))
	if w.Code != 200 {
		t.Fatalf("改密码失败: %d %s", w.Code, w.Body.String())
	}
	var fresh *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Value != "" {
			fresh = c
		}
	}
	if sessionLoggedIn(t, e.admin, c1) || sessionLoggedIn(t, e.admin, c2) {
		t.Fatal("改密码后旧会话都应失效")
	}
	if fresh == nil || !sessionLoggedIn(t, e.admin, fresh) {
		t.Fatal("改密码后当前用户应拿到新会话")
	}
	loginCookie(t, e, "another-long-password")
	if w := do(e.admin, http.MethodPost, "/api/login", `{"password":"correct-horse-battery"}`, adminWrite()); w.Code != 401 {
		t.Fatalf("旧密码不应再能登录, got %d", w.Code)
	}
}

func TestLoginLockout(t *testing.T) {
	e := newTestEnv(t, false)
	for i := 0; i < 5; i++ {
		if w := do(e.admin, http.MethodPost, "/api/login", `{"password":"nope"}`, adminWrite()); w.Code != 401 {
			t.Fatalf("第 %d 次错误密码应 401, got %d", i+1, w.Code)
		}
	}
	if w := do(e.admin, http.MethodPost, "/api/login", `{"password":"correct-horse-battery"}`, adminWrite()); w.Code != 429 {
		t.Fatalf("锁定期内即使密码正确也应 429, got %d", w.Code)
	}
	// 其他来源不受影响
	if w := do(e.admin, http.MethodPost, "/api/login", `{"password":"correct-horse-battery"}`, adminWrite(), remote("198.51.100.7:1")); w.Code != 200 {
		t.Fatalf("其他来源应能登录, got %d", w.Code)
	}
}

func TestFailTrackerBackoff(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_000_000, 0)}
	f := newFailTracker(3, time.Minute, time.Minute, 10*time.Minute)
	f.now = clk.now
	for i := 0; i < 3; i++ {
		f.fail("k")
	}
	if b, d := f.blocked("k"); !b || d != time.Minute {
		t.Fatalf("首次锁定 1 分钟, got %v %v", b, d)
	}
	clk.t = clk.t.Add(61 * time.Second)
	for i := 0; i < 3; i++ {
		f.fail("k")
	}
	if _, d := f.blocked("k"); d != 2*time.Minute {
		t.Fatalf("第二次锁定应翻倍, got %v", d)
	}
	f.success("k")
	if b, _ := f.blocked("k"); b {
		t.Fatal("成功后应清除")
	}
}

func TestStoreAdminPasswordRules(t *testing.T) {
	if _, err := loadStore(t.TempDir(), storeOptions{}); err == nil || !strings.Contains(err.Error(), "SSHWEB_PASSWORD") {
		t.Fatalf("首次启动无密码应拒绝, got %v", err)
	}
	if _, err := loadStore(t.TempDir(), storeOptions{InitialPassword: "short"}); err == nil {
		t.Fatal("初始密码过短应拒绝")
	}
	dir := t.TempDir()
	s, err := loadStore(dir, storeOptions{InitialPassword: testPW})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(s.AdminHash(), testPW) || !strings.HasPrefix(s.AdminHash(), "$argon2id$") {
		t.Fatal("只应保存哈希")
	}
	// 模拟旧版数据卷：meta 里有明文密码
	if err := s.metaSet("password", "old-plaintext-password"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := loadStore(dir, storeOptions{}); err == nil || !strings.Contains(err.Error(), "旧版明文管理密码") {
		t.Fatalf("探针模式遇到明文密码应拒绝, got %v", err)
	}
	s2, err := loadStore(dir, storeOptions{EnableSSH: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if v, _ := s2.metaGet("password"); v != "" {
		t.Fatal("SSH 模式应删除明文密码")
	}
	if ok, _ := verifyPassword(testPW, s2.AdminHash()); !ok {
		t.Fatal("已有哈希时应保留原哈希")
	}
}
