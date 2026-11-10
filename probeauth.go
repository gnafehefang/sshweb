package main

// probeauth.go — 探针“密码查看”的授权与隐私：
//   - 解锁 Cookie 带 HMAC 签名：v1.<kid>.<权限版本号>.<过期时间>.<签名>
//     签名密钥随机生成、只用于这一种用途，带 key id 便于轮换
//   - 每个探针有 GrantVersion（查看权限版本号）：管理员撤销已解锁访客或修改查看密码时加 1，
//     旧 Cookie 全部失效；撤销与密码哈希格式互不相关
//   - 解锁接口只接受 POST JSON，按来源失败计数并指数退避；查看密码只存 Argon2id 哈希
//   - IP 掩码同时处理 IPv4 / IPv6；国家识别默认关闭

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	probeUnlockTTL   = 7 * 24 * time.Hour
	minViewPassLen   = 8
	maxUnlockCompare = 50 // unlockpass 最多比对的探针数（每次比对一次 Argon2）
)

// ---------------- 签名密钥 ----------------

type probeCookieKeys struct {
	Active string            `json:"active"`
	Keys   map[string]string `json:"keys"` // kid -> base64(32 字节)
}

type probeSigner struct {
	mu     sync.RWMutex
	active string
	keys   map[string][]byte
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// loadProbeSigner 读取（首次则生成）探针解锁 Cookie 的签名密钥
func (s *Store) loadProbeSigner() (*probeSigner, error) {
	var ks probeCookieKeys
	raw, _ := s.metaGet("probe_cookie_keys")
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &ks); err != nil {
			return nil, fmt.Errorf("probe_cookie_keys 损坏: %w", err)
		}
	}
	if ks.Active == "" || ks.Keys[ks.Active] == "" {
		kid := fmt.Sprintf("k%d", time.Now().Unix())
		if ks.Keys == nil {
			ks.Keys = map[string]string{}
		}
		ks.Keys[kid] = base64.StdEncoding.EncodeToString(randomBytes(32))
		ks.Active = kid
		b, _ := json.Marshal(ks)
		if err := s.metaSet("probe_cookie_keys", string(b)); err != nil {
			return nil, err
		}
	}
	ps := &probeSigner{active: ks.Active, keys: map[string][]byte{}}
	for kid, v := range ks.Keys {
		k, err := base64.StdEncoding.DecodeString(v)
		if err != nil || len(k) < 32 {
			return nil, errors.New("probe_cookie_keys 中有无效密钥")
		}
		ps.keys[kid] = k
	}
	return ps, nil
}

func (ps *probeSigner) mac(key []byte, id, kid string, ver int, exp int64) string {
	m := hmac.New(sha256.New, key)
	fmt.Fprintf(m, "sshweb/probe-unlock/v1|%s|%s|%d|%d", id, kid, ver, exp)
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (ps *probeSigner) sign(id string, ver int, exp time.Time) string {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	e := exp.Unix()
	return fmt.Sprintf("v1.%s.%d.%d.%s", ps.active, ver, e, ps.mac(ps.keys[ps.active], id, ps.active, ver, e))
}

// verify 校验签名、过期时间与权限版本号
func (ps *probeSigner) verify(id, value string, curVer int, now time.Time) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 5 || parts[0] != "v1" {
		return false
	}
	kid := parts[1]
	ver, err1 := strconv.Atoi(parts[2])
	exp, err2 := strconv.ParseInt(parts[3], 10, 64)
	if err1 != nil || err2 != nil || ver != curVer || now.Unix() >= exp {
		return false
	}
	ps.mu.RLock()
	key, ok := ps.keys[kid]
	ps.mu.RUnlock()
	if !ok {
		return false
	}
	want := ps.mac(key, id, kid, ver, exp)
	return hmac.Equal([]byte(want), []byte(parts[4]))
}

// ---------------- Cookie ----------------

func (a *App) probeCookiePrefix() string {
	if a.cfg.secureCookies() {
		return "__Host-pv_"
	}
	return "pv_"
}

func (a *App) setUnlockedCookie(w http.ResponseWriter, pr *Probe) {
	exp := time.Now().Add(probeUnlockTTL)
	http.SetCookie(w, &http.Cookie{
		Name: a.probeCookiePrefix() + pr.ID, Value: a.probeSigner.sign(pr.ID, pr.GrantVersion, exp),
		Path: "/", HttpOnly: true, Secure: a.cfg.secureCookies(), SameSite: http.SameSiteLaxMode,
		MaxAge: int(probeUnlockTTL / time.Second),
	})
}

// readUnlocked 返回请求中签名有效、未过期、版本号匹配的已解锁探针
func (a *App) readUnlocked(r *http.Request) map[string]bool {
	out := map[string]bool{}
	prefix := a.probeCookiePrefix()
	now := time.Now()
	for _, c := range r.Cookies() {
		if !strings.HasPrefix(c.Name, prefix) {
			continue
		}
		id := strings.TrimPrefix(c.Name, prefix)
		pr := a.store.ProbeByID(id)
		if pr == nil || pr.Public {
			continue
		}
		if a.probeSigner.verify(id, c.Value, pr.GrantVersion, now) {
			out[id] = true
		}
	}
	return out
}

// ---------------- 解锁接口（公开站，浏览器 POST） ----------------

func (a *App) unlockAllowed(w http.ResponseWriter, r *http.Request) (string, bool) {
	ip := a.clientIP(r)
	if b, d := a.unlockFails.blocked(ip); b {
		tooMany(w, d)
		return ip, false
	}
	return ip, true
}

func (a *App) checkViewPass(pr *Probe, pass string) (bool, error) {
	if pr == nil || pr.Public || pr.ViewPassHash == "" {
		return false, nil
	}
	return verifyPassword(pass, pr.ViewPassHash)
}

// POST /api/probe/unlock {"id","pass"}
func (a *App) handleProbeUnlock(w http.ResponseWriter, r *http.Request) {
	ip, ok := a.unlockAllowed(w, r)
	if !ok {
		return
	}
	var in struct {
		ID   string `json:"id"`
		Pass string `json:"pass"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "请求格式错误"})
		return
	}
	pr := a.store.ProbeByID(in.ID)
	match, err := a.checkViewPass(pr, in.Pass)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		return
	}
	if !match {
		a.unlockFails.fail(ip) // 探针不存在与密码错误同样计数，不提供枚举线索
		writeJSON(w, 403, map[string]string{"error": "查看密码错误"})
		return
	}
	a.unlockFails.success(ip)
	a.setUnlockedCookie(w, pr)
	writeJSON(w, 200, a.probeView(pr, false, true))
}

// POST /api/probe/unlockpass {"pass"} — 一个密码解锁所有匹配的密码探针
func (a *App) handleProbeUnlockPass(w http.ResponseWriter, r *http.Request) {
	ip, ok := a.unlockAllowed(w, r)
	if !ok {
		return
	}
	var in struct {
		Pass string `json:"pass"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "请求格式错误"})
		return
	}
	n, checked := 0, 0
	if len([]rune(in.Pass)) >= minViewPassLen {
		for _, pr := range a.store.Probes() {
			if pr.Public || pr.ViewPassHash == "" {
				continue
			}
			if checked >= maxUnlockCompare {
				break
			}
			checked++
			match, err := a.checkViewPass(pr, in.Pass)
			if err != nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
				return
			}
			if match {
				a.setUnlockedCookie(w, pr)
				n++
			}
		}
	}
	if n == 0 {
		a.unlockFails.fail(ip)
		writeJSON(w, 403, map[string]string{"error": "没有匹配该密码的探针"})
		return
	}
	a.unlockFails.success(ip)
	writeJSON(w, 200, map[string]any{"unlocked": n})
}

// POST /api/probes/revoke {"id"}（管理员）— 撤销所有已解锁访客：权限版本号加 1
func (a *App) handleProbeRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	var in struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "请求格式错误"})
		return
	}
	pr, err := a.store.UpdateProbe(in.ID, func(p *Probe) error {
		p.GrantVersion++
		return nil
	})
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "grantVersion": pr.GrantVersion})
}

// ---------------- 隐私 ----------------

// maskIP IPv4 只保留前两段，IPv6 只保留前 32 位；无法解析时不显示
func maskIP(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ""
	}
	a = a.Unmap()
	if a.Is4() {
		b := a.As4()
		return fmt.Sprintf("%d.%d.*.*", b[0], b[1])
	}
	p, err := a.Prefix(32)
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(p.Addr().String(), "::") + ":*"
}

// probeDisplayName 给访客看的探针名：未解锁时绝不使用主机名
func probeDisplayName(pr *Probe, hostname string, canSee bool) string {
	if pr.Name != "" {
		return pr.Name
	}
	if canSee && hostname != "" {
		return hostname
	}
	id := pr.ID
	if len(id) > 4 {
		id = id[:4]
	}
	return "探针 #" + id
}

// countryCode 国家识别（默认关闭；开启时会把 IP 发给 ip-api.com）
func (a *App) countryCode(ip string) string {
	if !a.cfg.GeoIP {
		return ""
	}
	return lookupCC(ip)
}
