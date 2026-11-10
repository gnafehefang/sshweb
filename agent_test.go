package main

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestEnrollConcurrentRedeemOnlyOnce(t *testing.T) {
	s, err := loadStore(t.TempDir(), storeOptions{InitialPassword: testPW})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	code, _, err := s.AddProbeWithEnroll(&Probe{ID: "p1", Public: true}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var ok atomic.Int32
	var wg sync.WaitGroup
	tokens := make(chan string, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, tok, err := s.RedeemEnrollCode(code, time.Now()); err == nil {
				ok.Add(1)
				tokens <- tok
			}
		}()
	}
	wg.Wait()
	close(tokens)
	if ok.Load() != 1 {
		t.Fatalf("50 个并发兑换应只有 1 个成功, got %d", ok.Load())
	}
	tok := <-tokens
	if !validToken(tok, "swp_", 64) {
		t.Fatalf("token 格式不对: %s", tok)
	}
	if pr := s.ProbeByTokenHash(probeTokenHash(tok)); pr == nil || pr.ID != "p1" {
		t.Fatal("兑换后应能用 token 找到探针")
	}
	// 库里不存明文 token / 注册码
	var raw string
	s.db.QueryRow("SELECT data FROM probes WHERE id='p1'").Scan(&raw)
	if strings.Contains(raw, tok) {
		t.Fatal("数据库不应保存明文 token")
	}
	var n int
	s.db.QueryRow("SELECT COUNT(*) FROM enroll_codes WHERE code_hash=?", code).Scan(&n)
	if n != 0 {
		t.Fatal("数据库不应保存明文注册码")
	}
}

func TestEnrollCodeExpiryAndFormat(t *testing.T) {
	s, err := loadStore(t.TempDir(), storeOptions{InitialPassword: testPW})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	code, _, _ := s.AddProbeWithEnroll(&Probe{ID: "p1", Public: true}, now)
	if _, _, err := s.RedeemEnrollCode(code, now.Add(enrollTTL+time.Second)); err != errEnrollInvalid {
		t.Fatalf("过期注册码应被拒绝, got %v", err)
	}
	for _, bad := range []string{"", "swe_xyz", "swp_" + strings.Repeat("a", 32), code + "0"} {
		if _, _, err := s.RedeemEnrollCode(bad, now); err != errEnrollInvalid {
			t.Fatalf("无效注册码 %q 应被拒绝, got %v", bad, err)
		}
	}
	// 重新生成后旧码作废
	code2, _, err := s.RotateProbe("p1", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.RedeemEnrollCode(code, now); err != errEnrollInvalid {
		t.Fatal("轮换后旧注册码应作废")
	}
	if _, _, err := s.RedeemEnrollCode(code2, now); err != nil {
		t.Fatalf("新注册码应可用: %v", err)
	}
}

func enrollViaHTTP(t *testing.T, e *testEnv, code string) string {
	t.Helper()
	w := do(e.public, http.MethodPost, "/api/probe/enroll", `{"code":"`+code+`"}`, hdr("Content-Type", "application/json"))
	if w.Code != 200 {
		t.Fatalf("注册失败: %d %s", w.Code, w.Body.String())
	}
	var v struct{ Token string }
	json.Unmarshal(w.Body.Bytes(), &v)
	return v.Token
}

var codeRe = regexp.MustCompile(`swe_[0-9a-f]{32}`)

func TestAgentLifecycleOverHTTP(t *testing.T) {
	e := newTestEnv(t, false)
	admin := loginCookie(t, e, "correct-horse-battery")
	w := do(e.admin, http.MethodPost, "/api/probe/join", `{"public":true,"name":"jp"}`, adminWrite(), cookie(admin))
	if w.Code != 200 {
		t.Fatalf("创建探针失败: %d %s", w.Code, w.Body.String())
	}
	var j struct{ ID, Install, Uninstall string }
	json.Unmarshal(w.Body.Bytes(), &j)
	code := codeRe.FindString(j.Install)
	if code == "" || !strings.HasPrefix(j.Install, "curl -fsSL 'https://farm.example.com/probe/agent.sh' | sudo bash -s -- ") {
		t.Fatalf("安装命令格式不对: %s", j.Install)
	}
	if w := do(e.public, http.MethodPost, "/api/probe/enroll", `{"code":"`+code+`"}`, hdr("Content-Type", "application/json")); w.Code != 200 {
		t.Fatalf("注册失败: %d", w.Code)
	}
	if w := do(e.public, http.MethodPost, "/api/probe/enroll", `{"code":"`+code+`"}`, hdr("Content-Type", "application/json")); w.Code != 403 {
		t.Fatalf("注册码重复使用应 403, got %d", w.Code)
	}

	// 轮换：旧 token 立即失效，新注册码可用
	w = do(e.admin, http.MethodPost, "/api/probes/rotate", `{"id":"`+j.ID+`"}`, adminWrite(), cookie(admin))
	code2 := codeRe.FindString(w.Body.String())
	tok := enrollViaHTTP(t, e, code2)
	if w := do(e.public, http.MethodPost, "/api/probe/report", `{"hostname":"h"}`, hdr("Authorization", "Bearer "+tok)); w.Code != 200 {
		t.Fatalf("新 token 上报应成功: %d %s", w.Code, w.Body.String())
	}
	if w := do(e.public, http.MethodPost, "/api/probe/report", `{}`, hdr("Authorization", "Bearer swp_"+strings.Repeat("0", 64))); w.Code != 401 {
		t.Fatalf("错误 token 应 401, got %d", w.Code)
	}
	if w := do(e.public, http.MethodPost, "/api/probe/goodbye", "", hdr("Authorization", "Bearer "+tok)); w.Code != 200 {
		t.Fatalf("goodbye 应成功（无请求体）: %d", w.Code)
	}
	if len(e.app.store.Probes()) != 0 {
		t.Fatal("goodbye 后探针应被删除")
	}
}

func TestLegacyAgentQueryToken(t *testing.T) {
	e := newTestEnv(t, false)
	legacyTok := "0123456789abcdef0123456789abcdef"
	if err := e.app.store.AddProbe(&Probe{ID: "old", TokenHash: probeTokenHash(legacyTok), Public: true}); err != nil {
		t.Fatal(err)
	}
	w := do(e.public, http.MethodPost, "/api/probe/report?t="+legacyTok, `{"hostname":"h"}`)
	if w.Code != 401 || !strings.Contains(w.Body.String(), "旧版 agent 已停用") {
		t.Fatalf("默认应拒绝旧版 ?t=, got %d %s", w.Code, w.Body.String())
	}
	e.app.cfg.LegacyAgentUntil = time.Now().Add(24 * time.Hour)
	if w := do(e.public, http.MethodPost, "/api/probe/report?t="+legacyTok, `{"hostname":"h"}`); w.Code != 200 {
		t.Fatalf("兼容期内应接受旧版 ?t=, got %d", w.Code)
	}
	if pr := e.app.store.ProbeByID("old"); !pr.LegacyAgent {
		t.Fatal("应标记为旧版 agent")
	}
	e.app.cfg.LegacyAgentUntil = time.Now().Add(-time.Second)
	if w := do(e.public, http.MethodPost, "/api/probe/report?t="+legacyTok, `{"hostname":"h"}`); w.Code != 401 {
		t.Fatalf("过了截止日期应拒绝, got %d", w.Code)
	}
}

func TestLegacyPlaintextTokenMigrated(t *testing.T) {
	dir := t.TempDir()
	s, err := loadStore(dir, storeOptions{InitialPassword: testPW})
	if err != nil {
		t.Fatal(err)
	}
	s.AddProbe(&Probe{ID: "p", Token: "legacy-plain-token", Public: true})
	s.Close()
	s2, err := loadStore(dir, storeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	var raw string
	s2.db.QueryRow("SELECT data FROM probes WHERE id='p'").Scan(&raw)
	if strings.Contains(raw, "legacy-plain-token") {
		t.Fatal("旧版明文 token 应在加载时转成哈希")
	}
	if s2.ProbeByTokenHash(probeTokenHash("legacy-plain-token")) == nil {
		t.Fatal("迁移后应能按哈希找到")
	}
}

func TestInstallScriptsHaveNoSecretsAndParse(t *testing.T) {
	e := newTestEnv(t, false)
	inst := e.app.installScript()
	un := e.app.uninstallScript()
	for name, sc := range map[string]string{"install": inst, "uninstall": un, "agent": strings.ReplaceAll(agentBody, "__PANEL__", "https://farm.example.com")} {
		if strings.Contains(sc, "__PANEL__") || strings.Contains(sc, "__AGENT_BODY__") {
			t.Fatalf("%s 中有未替换的占位符", name)
		}
		if strings.Contains(sc, "?t=") || strings.Contains(sc, "swp_") && name == "agent" {
			t.Fatalf("%s 不应包含 token", name)
		}
		if _, err := exec.LookPath("bash"); err == nil {
			f := filepath.Join(t.TempDir(), name+".sh")
			os.WriteFile(f, []byte(sc), 0o600)
			if out, err := exec.Command("bash", "-n", f).CombinedOutput(); err != nil {
				t.Fatalf("%s 语法错误: %v\n%s", name, err, out)
			}
		}
	}
	for _, want := range []string{"LoadCredential=auth-header:", "DynamicUser=yes", "--data-binary @-", "-H @\"$HDR\""} {
		if !strings.Contains(inst, want) {
			t.Fatalf("安装脚本缺少 %q", want)
		}
	}
	if !strings.Contains(inst, "PANEL='https://farm.example.com'") {
		t.Fatal("面板地址应取自 SSHWEB_PUBLIC_URL")
	}
}

func TestEnrollRateLimited(t *testing.T) {
	e := newTestEnv(t, false)
	got429 := false
	for i := 0; i < 15; i++ {
		w := do(e.public, http.MethodPost, "/api/probe/enroll", `{"code":"swe_`+strings.Repeat("0", 32)+`"}`, hdr("Content-Type", "application/json"))
		if w.Code == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatal("注册接口应按来源限流")
	}
}
