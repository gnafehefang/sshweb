package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func createServer(t *testing.T, e *testEnv, c *http.Cookie, body string) string {
	t.Helper()
	w := do(e.admin, http.MethodPost, "/api/servers", body, adminWrite(), cookie(c))
	if w.Code != 200 {
		t.Fatalf("创建服务器失败: %d %s", w.Code, w.Body.String())
	}
	var v struct{ ID string }
	json.Unmarshal(w.Body.Bytes(), &v)
	return v.ID
}

func TestRejectedEditLeavesRecordUnchanged(t *testing.T) {
	e := newTestEnv(t, true)
	c := loginCookie(t, e, "correct-horse-battery")
	id := createServer(t, e, c, `{"name":"web","host":"10.0.0.5","port":22,"user":"deploy","authKind":"password","password":"pw-1"}`)
	before := e.app.store.Get(id)

	rejects := []string{
		`{"id":"` + id + `","name":"web","host":"evil.example","port":22,"user":"deploy","authKind":"password"}`,             // 改 Host 不填密码
		`{"id":"` + id + `","name":"web","host":"10.0.0.5","port":2222,"user":"deploy","authKind":"password"}`,               // 改端口
		`{"id":"` + id + `","name":"web","host":"10.0.0.5","port":22,"user":"root","authKind":"password"}`,                   // 改用户
		`{"id":"` + id + `","name":"web","host":"10.0.0.5","port":22,"user":"deploy","authKind":"key"}`,                      // 切换认证方式不给私钥
		`{"id":"` + id + `","name":"","host":"evil.example","port":22,"user":"deploy","authKind":"password","password":"x"}`, // 其他校验失败
	}
	for _, body := range rejects {
		if w := do(e.admin, http.MethodPost, "/api/servers", body, adminWrite(), cookie(c)); w.Code != 400 {
			t.Fatalf("应被拒绝: %s → %d %s", body, w.Code, w.Body.String())
		}
		after := e.app.store.Get(id)
		if *after != *before {
			t.Fatalf("被拒绝的编辑改动了内存记录:\nbefore %+v\nafter  %+v", before, after)
		}
	}
	// 重新加载数据库，确认库里也没变
	e.app.store.Close()
	s2, err := loadStore(e.app.store.dir, storeOptions{EnableSSH: true})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if got := s2.Get(id); got.Host != "10.0.0.5" || got.Password != "pw-1" {
		t.Fatalf("数据库记录被改动: %+v", got)
	}
}

func TestEditRulesForSecretsAndHostKey(t *testing.T) {
	e := newTestEnv(t, true)
	c := loginCookie(t, e, "correct-horse-battery")
	id := createServer(t, e, c, `{"name":"web","host":"10.0.0.5","port":22,"user":"deploy","authKind":"password","password":"pw-1"}`)

	// 不改连接目标：允许留空密码（保留原密码）
	if w := do(e.admin, http.MethodPost, "/api/servers", `{"id":"`+id+`","name":"web-renamed","host":"10.0.0.5","port":22,"user":"deploy","authKind":"password"}`, adminWrite(), cookie(c)); w.Code != 200 {
		t.Fatalf("仅改名应允许: %d %s", w.Code, w.Body.String())
	}
	if got := e.app.store.Get(id); got.Password != "pw-1" || got.Name != "web-renamed" {
		t.Fatalf("仅改名时应保留原密码: %+v", got)
	}

	// 模拟已确认主机密钥；改 Host 并提供新密码 → 主机密钥被清除
	sv := e.app.store.Get(id)
	sv.HostKey = "SHA256:abc"
	if err := e.app.store.Put(sv); err != nil {
		t.Fatal(err)
	}
	if w := do(e.admin, http.MethodPost, "/api/servers", `{"id":"`+id+`","name":"web","host":"10.0.0.6","port":22,"user":"deploy","authKind":"password","password":"pw-2"}`, adminWrite(), cookie(c)); w.Code != 200 {
		t.Fatalf("改 Host 并重填密码应允许: %d", w.Code)
	}
	if got := e.app.store.Get(id); got.HostKey != "" || got.Password != "pw-2" {
		t.Fatalf("改连接目标后应清除主机密钥: %+v", got)
	}

	// 切换为私钥：清空密码
	if w := do(e.admin, http.MethodPost, "/api/servers", `{"id":"`+id+`","name":"web","host":"10.0.0.6","port":22,"user":"deploy","authKind":"key","privateKey":"KEY","keyPass":"kp"}`, adminWrite(), cookie(c)); w.Code != 200 {
		t.Fatalf("切换私钥失败: %d", w.Code)
	}
	if got := e.app.store.Get(id); got.Password != "" || got.PrivateKey != "KEY" || got.KeyPass != "kp" {
		t.Fatalf("切换为私钥后应清空密码: %+v", got)
	}
	// 再切回密码：清空私钥和口令
	if w := do(e.admin, http.MethodPost, "/api/servers", `{"id":"`+id+`","name":"web","host":"10.0.0.6","port":22,"user":"deploy","authKind":"password","password":"pw-3"}`, adminWrite(), cookie(c)); w.Code != 200 {
		t.Fatalf("切回密码失败: %d", w.Code)
	}
	if got := e.app.store.Get(id); got.PrivateKey != "" || got.KeyPass != "" || got.Password != "pw-3" {
		t.Fatalf("切回密码后应清空私钥: %+v", got)
	}

	if w := do(e.admin, http.MethodPost, "/api/servers", `{"id":"nope","name":"x","host":"h","user":"u","authKind":"password","password":"p"}`, adminWrite(), cookie(c)); w.Code != 404 {
		t.Fatalf("编辑不存在的服务器应 404, got %d", w.Code)
	}
	// 列表接口不下发凭据
	w := do(e.admin, http.MethodGet, "/api/servers", "", cookie(c))
	if strings.Contains(w.Body.String(), "pw-3") || strings.Contains(w.Body.String(), "KEY") {
		t.Fatal("列表接口不应包含凭据")
	}
}

func TestStoreGetReturnsCopyAndPutIsAtomic(t *testing.T) {
	s, err := loadStore(t.TempDir(), storeOptions{EnableSSH: true, InitialPassword: testPW})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(&Server{ID: "s1", Name: "n", Host: "h", Port: 22, User: "u", AuthKind: "password", Password: "p"}); err != nil {
		t.Fatal(err)
	}
	g := s.Get("s1")
	g.Host = "changed"
	s.List()[0].Password = "changed"
	if cur := s.Get("s1"); cur.Host != "h" || cur.Password != "p" {
		t.Fatal("修改返回值不应影响内存记录")
	}
	s.db.Close() // 让写库失败
	g2 := s.Get("s1")
	g2.Host = "new-host"
	if err := s.Put(g2); err == nil {
		t.Fatal("写库失败应返回错误")
	}
	if s.Get("s1").Host != "h" {
		t.Fatal("写库失败时内存不应改变")
	}
}

func TestServerTestEndpointPostOnly(t *testing.T) {
	e := newTestEnv(t, true)
	c := loginCookie(t, e, "correct-horse-battery")
	if w := do(e.admin, http.MethodGet, "/api/servers/x/test", "", cookie(c)); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /test 应 405, got %d", w.Code)
	}
}

func TestAPIKeysHashed(t *testing.T) {
	e := newTestEnv(t, false)
	c := loginCookie(t, e, "correct-horse-battery")
	w := do(e.admin, http.MethodPost, "/api/keys", `{"name":"bot"}`, adminWrite(), cookie(c))
	var created struct{ ID, Key string }
	json.Unmarshal(w.Body.Bytes(), &created)
	if !strings.HasPrefix(created.Key, "sw_") {
		t.Fatalf("创建时应返回完整 key: %s", w.Body.String())
	}
	list := do(e.admin, http.MethodGet, "/api/keys", "", cookie(c)).Body.String()
	if strings.Contains(list, created.Key) || !strings.Contains(list, created.Key[:10]) {
		t.Fatalf("列表只应包含前缀: %s", list)
	}
	var n int
	e.app.store.db.QueryRow("SELECT COUNT(*) FROM apikeys_v2 WHERE hash=?", created.Key).Scan(&n)
	if n != 0 {
		t.Fatal("库里不应保存明文 key")
	}
	if w := do(e.public, http.MethodGet, "/api/skill/state", "", hdr("X-API-Key", created.Key)); w.Code != 200 {
		t.Fatalf("完整 key 应能调用 Skill 接口, got %d", w.Code)
	}
	if w := do(e.public, http.MethodGet, "/api/skill/state", "", hdr("X-API-Key", created.Key[:10])); w.Code != 401 {
		t.Fatalf("前缀不应能调用, got %d", w.Code)
	}
	do(e.admin, http.MethodDelete, "/api/keys?id="+created.ID, "", adminWrite(), cookie(c))
	if w := do(e.public, http.MethodGet, "/api/skill/state", "", hdr("X-API-Key", created.Key)); w.Code != 401 {
		t.Fatalf("删除后 key 应失效, got %d", w.Code)
	}
}

func TestLegacyPlaintextAPIKeysMigrated(t *testing.T) {
	dir := t.TempDir()
	s, err := loadStore(dir, storeOptions{InitialPassword: testPW})
	if err != nil {
		t.Fatal(err)
	}
	s.db.Exec("INSERT INTO apikeys(key,name,created_at) VALUES('sw_legacykey0123456789','old','2026-01-01')")
	s.Close()
	s2, err := loadStore(dir, storeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	var n int
	s2.db.QueryRow("SELECT COUNT(*) FROM apikeys").Scan(&n)
	if n != 0 {
		t.Fatal("旧表中的明文 key 应被删除")
	}
	if _, ok := s2.APIKeyID("sw_legacykey0123456789"); !ok {
		t.Fatal("迁移后旧 key 应仍可用")
	}
}
