package main

// config.go — 启动配置：命令行参数 + 环境变量，启动时一次性校验，不合格直接拒绝启动。
//
//   SSHWEB_ENABLE_SSH         1 = 开启网页 SSH（默认 0：探针版，不加载任何 SSH 凭据）
//   SSHWEB_PUBLIC_URL         公开站地址，必须是 https（安装脚本里的面板地址只取这里）
//   SSHWEB_ADMIN_ORIGIN       管理站 Origin（scheme://host[:port]），必须是 https 且与公开站主机名不同
//   SSHWEB_TRUSTED_PROXIES    可信反代地址（逗号分隔的 IP 或 CIDR），只有来自这些地址的请求才读取 X-Forwarded-For
//   SSHWEB_GEOIP              1 = 开启国家识别（会把访客 IP 发给 ip-api.com，默认 0）
//   SSHWEB_LEGACY_AGENT_UNTIL 旧版 agent（?t= 方式）兼容截止日期 YYYY-MM-DD，留空 = 不兼容
//   SSHWEB_PASSWORD           仅首次启动时用于设置管理密码（至少 12 位）
//   SSHWEB_DEV                1 = 本地开发模式：允许 http 地址、非 Secure Cookie

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

type Config struct {
	Listen      string
	AdminListen string
	DataDir     string

	EnableSSH bool
	Dev       bool

	PublicURL    string // 规范化后的公开站地址，不带结尾斜杠
	PublicOrigin string // scheme://host[:port]
	AdminOrigin  string // 为空表示不启用管理口

	TrustedProxies []netip.Prefix
	GeoIP          bool

	LegacyAgentUntil time.Time // 零值 = 不接受旧版 agent

	InitialPassword string
}

const minAdminPasswordLen = 12

func envBool(getenv func(string) string, k string) (bool, error) {
	switch strings.TrimSpace(strings.ToLower(getenv(k))) {
	case "", "0", "false", "no", "off":
		return false, nil
	case "1", "true", "yes", "on":
		return true, nil
	default:
		return false, fmt.Errorf("%s 只能是 0 或 1", k)
	}
}

// parseOrigin 规范化为 scheme://host[:port]；不允许路径、查询、用户信息。
func parseOrigin(raw string, allowHTTP bool) (string, *url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", nil, err
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", nil, errors.New("格式应为 https://host[:port]")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !allowHTTP {
			return "", nil, errors.New("必须使用 https（本地开发可设 SSHWEB_DEV=1）")
		}
	default:
		return "", nil, errors.New("只支持 http/https")
	}
	return u.Scheme + "://" + u.Host, u, nil
}

func parseTrustedProxies(raw string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			p, err := netip.ParsePrefix(part)
			if err != nil {
				return nil, fmt.Errorf("SSHWEB_TRUSTED_PROXIES: %q 不是合法 CIDR", part)
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("SSHWEB_TRUSTED_PROXIES: %q 不是合法 IP", part)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

func loadConfig(args []string, getenv func(string) string, stderr io.Writer) (*Config, error) {
	cfg := &Config{}
	fs := flag.NewFlagSet("sshweb", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDefault := getenv("SSHWEB_DATA")
	if dataDefault == "" {
		dataDefault = "data"
	}
	fs.StringVar(&cfg.DataDir, "data", dataDefault, "数据目录")
	fs.StringVar(&cfg.Listen, "listen", "127.0.0.1:45678", "公开口监听地址")
	fs.StringVar(&cfg.AdminListen, "admin-listen", "127.0.0.1:45679", "管理口监听地址（留空 = 不启用管理口）")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	var err error
	if cfg.Dev, err = envBool(getenv, "SSHWEB_DEV"); err != nil {
		return nil, err
	}
	if cfg.EnableSSH, err = envBool(getenv, "SSHWEB_ENABLE_SSH"); err != nil {
		return nil, err
	}
	if cfg.GeoIP, err = envBool(getenv, "SSHWEB_GEOIP"); err != nil {
		return nil, err
	}

	pub := getenv("SSHWEB_PUBLIC_URL")
	if pub == "" {
		if !cfg.Dev {
			return nil, errors.New("必须设置 SSHWEB_PUBLIC_URL（公开站 https 地址）")
		}
		pub = "http://127.0.0.1:45678"
	}
	origin, pu, err := parseOrigin(pub, cfg.Dev)
	if err != nil {
		return nil, fmt.Errorf("SSHWEB_PUBLIC_URL: %w", err)
	}
	if p := strings.TrimRight(pu.EscapedPath(), "/"); p != "" {
		return nil, errors.New("SSHWEB_PUBLIC_URL 暂不支持子路径部署")
	}
	cfg.PublicOrigin = origin
	cfg.PublicURL = origin

	if cfg.AdminListen != "" {
		ao := getenv("SSHWEB_ADMIN_ORIGIN")
		if ao == "" {
			if !cfg.Dev {
				return nil, errors.New("启用管理口时必须设置 SSHWEB_ADMIN_ORIGIN（管理站 https Origin）")
			}
			ao = "http://127.0.0.1:45679"
		}
		aorigin, au, err := parseOrigin(ao, cfg.Dev)
		if err != nil {
			return nil, fmt.Errorf("SSHWEB_ADMIN_ORIGIN: %w", err)
		}
		if p := strings.TrimRight(au.EscapedPath(), "/"); p != "" {
			return nil, errors.New("SSHWEB_ADMIN_ORIGIN 只能是 Origin，不能带路径")
		}
		// Cookie 不按端口隔离：管理站与公开站必须使用不同主机名，否则管理 Cookie 会被发往公开口。
		if !cfg.Dev && au.Hostname() == pu.Hostname() {
			return nil, errors.New("SSHWEB_ADMIN_ORIGIN 与 SSHWEB_PUBLIC_URL 主机名相同；管理站必须使用独立主机名")
		}
		cfg.AdminOrigin = aorigin
	}

	if cfg.TrustedProxies, err = parseTrustedProxies(getenv("SSHWEB_TRUSTED_PROXIES")); err != nil {
		return nil, err
	}

	if s := strings.TrimSpace(getenv("SSHWEB_LEGACY_AGENT_UNTIL")); s != "" {
		t, err := time.ParseInLocation("2006-01-02", s, time.UTC)
		if err != nil {
			return nil, errors.New("SSHWEB_LEGACY_AGENT_UNTIL 格式应为 YYYY-MM-DD")
		}
		cfg.LegacyAgentUntil = t.Add(24 * time.Hour) // 截止日当天仍可用
	}

	cfg.InitialPassword = getenv("SSHWEB_PASSWORD")
	return cfg, nil
}

// secureCookies：非开发模式一律 Secure（公开站与管理站都强制 https）。
func (c *Config) secureCookies() bool { return !c.Dev }

func (c *Config) legacyAgentAllowed(now time.Time) bool {
	return !c.LegacyAgentUntil.IsZero() && now.Before(c.LegacyAgentUntil)
}
