package main

import (
	"io"
	"strings"
	"testing"
	"time"
)

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestConfigRequiresHTTPSPublicURL(t *testing.T) {
	_, err := loadConfig(nil, envMap(map[string]string{
		"SSHWEB_PUBLIC_URL": "http://farm.example.com", "SSHWEB_ADMIN_ORIGIN": "https://admin.example.net",
	}), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("http 公开地址应被拒绝, got %v", err)
	}
	if _, err := loadConfig(nil, envMap(map[string]string{"SSHWEB_ADMIN_ORIGIN": "https://a.example.net"}), io.Discard); err == nil {
		t.Fatal("缺少 SSHWEB_PUBLIC_URL 应被拒绝")
	}
}

func TestConfigAdminOriginRules(t *testing.T) {
	base := map[string]string{"SSHWEB_PUBLIC_URL": "https://farm.example.com"}
	if _, err := loadConfig(nil, envMap(base), io.Discard); err == nil {
		t.Fatal("启用管理口但未设置 SSHWEB_ADMIN_ORIGIN 应被拒绝")
	}
	same := map[string]string{"SSHWEB_PUBLIC_URL": "https://farm.example.com", "SSHWEB_ADMIN_ORIGIN": "https://farm.example.com:8443"}
	if _, err := loadConfig(nil, envMap(same), io.Discard); err == nil {
		t.Fatal("管理站与公开站同主机名应被拒绝")
	}
	withPath := map[string]string{"SSHWEB_PUBLIC_URL": "https://farm.example.com", "SSHWEB_ADMIN_ORIGIN": "https://admin.example.net/x"}
	if _, err := loadConfig(nil, envMap(withPath), io.Discard); err == nil {
		t.Fatal("管理 Origin 带路径应被拒绝")
	}
	// 关闭管理口时不要求管理 Origin
	cfg, err := loadConfig([]string{"-admin-listen", ""}, envMap(base), io.Discard)
	if err != nil || cfg.AdminOrigin != "" {
		t.Fatalf("关闭管理口: cfg=%+v err=%v", cfg, err)
	}
}

func TestConfigNormalizesAndParses(t *testing.T) {
	cfg, err := loadConfig(nil, envMap(map[string]string{
		"SSHWEB_PUBLIC_URL":         "HTTPS://Farm.Example.com/",
		"SSHWEB_ADMIN_ORIGIN":       "https://vps.tail1234.ts.net",
		"SSHWEB_TRUSTED_PROXIES":    "172.30.10.1, 10.0.0.0/8",
		"SSHWEB_LEGACY_AGENT_UNTIL": "2027-01-31",
		"SSHWEB_ENABLE_SSH":         "0",
	}), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PublicURL != "https://farm.example.com" || cfg.PublicOrigin != "https://farm.example.com" {
		t.Fatalf("PublicURL 规范化错误: %q", cfg.PublicURL)
	}
	if len(cfg.TrustedProxies) != 2 || cfg.TrustedProxies[0].Bits() != 32 {
		t.Fatalf("TrustedProxies 解析错误: %v", cfg.TrustedProxies)
	}
	if cfg.EnableSSH || cfg.GeoIP {
		t.Fatal("SSH 与 GeoIP 默认应关闭")
	}
	if !cfg.legacyAgentAllowed(time.Date(2027, 1, 31, 23, 0, 0, 0, time.UTC)) ||
		cfg.legacyAgentAllowed(time.Date(2027, 2, 1, 0, 0, 1, 0, time.UTC)) {
		t.Fatal("旧版 agent 截止日期计算错误")
	}
	if _, err := loadConfig(nil, envMap(map[string]string{
		"SSHWEB_PUBLIC_URL": "https://farm.example.com", "SSHWEB_ADMIN_ORIGIN": "https://a.example.net",
		"SSHWEB_TRUSTED_PROXIES": "not-an-ip",
	}), io.Discard); err == nil {
		t.Fatal("非法可信代理应被拒绝")
	}
}

func TestConfigDevDefaults(t *testing.T) {
	cfg, err := loadConfig(nil, envMap(map[string]string{"SSHWEB_DEV": "1"}), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.secureCookies() || !strings.HasPrefix(cfg.PublicURL, "http://") {
		t.Fatalf("开发模式默认值错误: %+v", cfg)
	}
}
