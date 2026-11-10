package main

// netutil.go — 真实客户端 IP 识别。
// 只有直连地址属于 SSHWEB_TRUSTED_PROXIES 时才读取 X-Forwarded-For / X-Real-IP，
// 并从右往左取第一个不可信的地址；直连客户端伪造的转发头一律忽略。

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

func inPrefixes(a netip.Addr, ps []netip.Prefix) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func parseAddr(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap(), true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil { // 个别代理会带端口
		return ap.Addr().Unmap(), true
	}
	return netip.Addr{}, false
}

func clientIPFrom(r *http.Request, trusted []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remote, ok := parseAddr(host)
	if !ok {
		return host
	}
	if !inPrefixes(remote, trusted) {
		return remote.String()
	}
	if xff := strings.Join(r.Header.Values("X-Forwarded-For"), ","); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			a, ok := parseAddr(parts[i])
			if !ok {
				break
			}
			if !inPrefixes(a, trusted) {
				return a.String()
			}
		}
	}
	if xr := r.Header.Get("X-Real-IP"); xr != "" {
		if a, ok := parseAddr(xr); ok && !inPrefixes(a, trusted) {
			return a.String()
		}
	}
	return remote.String()
}

func (a *App) clientIP(r *http.Request) string {
	return clientIPFrom(r, a.cfg.TrustedProxies)
}
