package main

// security.go — 按监听口区分站点；按鉴权类型做请求校验；统一安全响应头。
//
//   浏览器管理接口（管理口 /api/*）：
//     写操作：必须带 Origin 且等于管理站；缺 Origin 时只接受 Sec-Fetch-Site: same-origin；
//             必须带 X-SSHWeb: 1；有请求体时必须是 application/json
//     读操作：会话鉴权由各接口负责；请求带 Origin 时才校验一致
//   浏览器公开写接口（探针解锁）：同样的 Origin / 自定义头 / JSON 校验，对比公开站 Origin
//   WebSocket：必须带 Origin 且与本监听口站点完全一致
//   Agent / Skill 接口：不涉及 Cookie，用各自的 token，不做 Origin/CSRF 校验

import (
	"context"
	"errors"
	"mime"
	"net/http"
	"strings"
)

type site struct {
	admin  bool   // true = 管理口
	origin string // 本监听口对外的 Origin
}

type ctxKey int

const siteKey ctxKey = 0

func siteOf(r *http.Request) *site {
	s, _ := r.Context().Value(siteKey).(*site)
	return s
}

func onAdminSite(r *http.Request) bool {
	s := siteOf(r)
	return s != nil && s.admin
}

var (
	errBadOrigin     = errors.New("来源校验失败")
	errMissingHeader = errors.New("缺少 X-SSHWeb 请求头")
	errNotJSON       = errors.New("请求体必须是 application/json")
)

func isSafeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

func hasBody(r *http.Request) bool {
	return r.ContentLength > 0 || (r.ContentLength < 0 && r.Body != nil && r.Body != http.NoBody)
}

// checkBrowserWrite 浏览器 Cookie 场景下的写请求校验（CSRF 防护）
func checkBrowserWrite(r *http.Request, wantOrigin string) error {
	if o := r.Header.Get("Origin"); o != "" {
		if o != wantOrigin {
			return errBadOrigin
		}
	} else if r.Header.Get("Sec-Fetch-Site") != "same-origin" {
		return errBadOrigin
	}
	if r.Header.Get("X-SSHWeb") != "1" {
		return errMissingHeader
	}
	if hasBody(r) {
		mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || mt != "application/json" {
			return errNotJSON
		}
	}
	return nil
}

// checkBrowserRead 读请求：带 Origin 时才校验（同源 GET 通常不带 Origin）
func checkBrowserRead(r *http.Request, wantOrigin string) error {
	if o := r.Header.Get("Origin"); o != "" && o != wantOrigin {
		return errBadOrigin
	}
	return nil
}

// adminAPIGuard 包住整个管理口：对 /api/ 路径做请求校验并限制请求体大小
func adminAPIGuard(st *site, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			var err error
			if isSafeMethod(r.Method) {
				err = checkBrowserRead(r, st.origin)
			} else {
				err = checkBrowserWrite(r, st.origin)
			}
			if err != nil {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
		}
		next.ServeHTTP(w, r)
	})
}

// publicBrowserWrite 公开站上供浏览器调用的写接口（探针解锁）
func publicBrowserWrite(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st := siteOf(r)
		if st == nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": errBadOrigin.Error()})
			return
		}
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
			return
		}
		if err := checkBrowserWrite(r, st.origin); err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
		next(w, r)
	}
}

// wsOriginOK WebSocket 握手：Origin 必须存在且与本站完全一致
func wsOriginOK(r *http.Request) bool {
	st := siteOf(r)
	o := r.Header.Get("Origin")
	return st != nil && o != "" && o == st.origin
}

func wsOf(origin string) string {
	switch {
	case strings.HasPrefix(origin, "https://"):
		return "wss://" + strings.TrimPrefix(origin, "https://")
	case strings.HasPrefix(origin, "http://"):
		return "ws://" + strings.TrimPrefix(origin, "http://")
	}
	return ""
}

func contentSecurityPolicy(st *site) string {
	return strings.Join([]string{
		"default-src 'self'",
		"script-src 'self'",
		"style-src 'self' 'unsafe-inline'", // 前端模板含内联 style 属性
		"img-src 'self' data: blob:",
		"font-src 'self' data:",
		"connect-src 'self' " + wsOf(st.origin),
		"object-src 'none'",
		"base-uri 'none'",
		"form-action 'self'",
		"frame-ancestors 'none'",
	}, "; ")
}

// withSite 给请求挂上站点信息并统一加安全响应头
func withSite(st *site, next http.Handler) http.Handler {
	csp := contentSecurityPolicy(st)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		if strings.HasPrefix(r.URL.Path, "/api/") || strings.HasPrefix(r.URL.Path, "/ws/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), siteKey, st)))
	})
}
