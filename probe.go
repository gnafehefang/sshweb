package main

// probe.go — 公开探针系统：
//   管理员创建探针（一次性注册码，见 agent.go）→ 目标机一键安装 agent → 周期上报 CPU/内存/磁盘/网速
//   农场里出现一只 📡 探针鸡，点击查看状态卡片
//   支持：完全公开 / 密码查看（见 probeauth.go）/ IP 掩码

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

type Probe struct {
	ID           string    `json:"id"`
	Token        string    `json:"token,omitempty"`        // 旧版明文 token，仅用于加载时迁移为哈希
	TokenHash    string    `json:"tokenHash,omitempty"`    // agent 长期 token 的哈希；空 = 尚未注册
	LegacyAgent  bool      `json:"legacyAgent,omitempty"`  // 最近一次以旧版 ?t= 方式上报
	Name         string    `json:"name,omitempty"`         // 备注名；未解锁的访客看不到主机名
	Public       bool      `json:"public"`                 // true=完全公开 false=密码查看
	ViewPass     string    `json:"viewPass,omitempty"`     // 旧版明文，仅用于加载时迁移为哈希
	ViewPassHash string    `json:"viewPassHash,omitempty"` // 查看密码的 Argon2id 哈希
	GrantVersion int       `json:"grantVersion"`           // 查看权限版本号，撤销授权时加 1
	MaskIP       bool      `json:"maskIP"`                 // 对非管理员掩码 IP
	CreatedAt    time.Time `json:"createdAt"`
}

type probeStats struct {
	Hostname  string  `json:"hostname"`
	OS        string  `json:"os"`
	IP        string  `json:"ip"`
	CPU       float64 `json:"cpu"`       // 0-100
	MemTotal  int64   `json:"memTotal"`  // KB
	MemUsed   int64   `json:"memUsed"`   // KB
	DiskTotal int64   `json:"diskTotal"` // KB
	DiskUsed  int64   `json:"diskUsed"`  // KB
	RxRate    int64   `json:"rxRate"`    // B/s 下行
	TxRate    int64   `json:"txRate"`    // B/s 上行
	Load1     float64 `json:"load1"`     // 1 分钟负载
	Uptime    int64   `json:"uptime"`    // 运行秒数
	Procs     int     `json:"procs"`     // 进程数
	CPUModel  string  `json:"cpuModel"`  // CPU 型号
	CPUCores  int     `json:"cpuCores"`  // 逻辑核数
	LastSeen  time.Time
}

type probeRuntime struct {
	mu    sync.Mutex
	items map[string]*probeStats // probeID -> stats
}

func newProbeRuntime() *probeRuntime {
	return &probeRuntime{items: map[string]*probeStats{}}
}

func (p *probeRuntime) report(id string, st *probeStats) {
	p.mu.Lock()
	p.items[id] = st
	p.mu.Unlock()
}

func (p *probeRuntime) get(id string) *probeStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.items[id]
}

func (p *probeRuntime) remove(id string) {
	p.mu.Lock()
	delete(p.items, id)
	p.mu.Unlock()
}

// 按查看者身份生成探针视图
func (a *App) probeView(pr *Probe, forAdmin bool, unlocked bool) map[string]any {
	st := a.probes.get(pr.ID)
	online := st != nil && time.Since(st.LastSeen) < 15*time.Second
	canSee := forAdmin || pr.Public || unlocked
	hostname := ""
	if st != nil {
		hostname = st.Hostname
	}
	v := map[string]any{
		"id":     pr.ID,
		"name":   probeDisplayName(pr, hostname, canSee),
		"public": pr.Public,
		"online": online,
	}
	if forAdmin {
		v["enrolled"] = pr.TokenHash != ""
		v["legacyAgent"] = pr.LegacyAgent
	}
	if canSee {
		if st != nil {
			ip := st.IP
			if pr.MaskIP && !forAdmin {
				ip = maskIP(ip)
			}
			v["hostname"] = st.Hostname
			v["os"] = st.OS
			v["ip"] = ip
			v["cc"] = a.countryCode(st.IP)
			v["cpu"] = st.CPU
			v["memTotal"] = st.MemTotal
			v["memUsed"] = st.MemUsed
			v["diskTotal"] = st.DiskTotal
			v["diskUsed"] = st.DiskUsed
			v["rxRate"] = st.RxRate
			v["txRate"] = st.TxRate
			v["load1"] = st.Load1
			v["uptime"] = st.Uptime
			v["procs"] = st.Procs
			v["cpuModel"] = st.CPUModel
			v["cpuCores"] = st.CPUCores
			v["lastSeen"] = st.LastSeen.Unix()
		}
	} else {
		v["locked"] = true
	}
	return v
}

func (a *App) probesForClient(forAdmin bool, unlocked map[string]bool) []map[string]any {
	out := []map[string]any{}
	for _, pr := range a.store.Probes() {
		out = append(out, a.probeView(pr, forAdmin, unlocked[pr.ID]))
	}
	return out
}

/* ---------------- HTTP API ---------------- */

// POST /api/probe/join  (admin) — 生成探针 {public, viewPass, maskIP, name}
func (a *App) handleProbeJoin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "method not allowed"})
		return
	}
	var body struct {
		Public   bool   `json:"public"`
		ViewPass string `json:"viewPass"`
		MaskIP   bool   `json:"maskIP"`
		Name     string `json:"name"`
	}
	json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body)
	viewHash := ""
	if !body.Public {
		if len([]rune(body.ViewPass)) < minViewPassLen {
			writeJSON(w, 400, map[string]string{"error": fmt.Sprintf("密码查看模式需要至少 %d 位密码", minViewPassLen)})
			return
		}
		h, err := hashPassword(body.ViewPass, viewArgon)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
			return
		}
		viewHash = h
	}
	pr := &Probe{
		ID:           newID()[:12],
		Name:         cleanText(strings.TrimSpace(body.Name), 32),
		Public:       body.Public,
		ViewPassHash: viewHash,
		MaskIP:       body.MaskIP,
		CreatedAt:    time.Now(),
	}
	code, exp, err := a.store.AddProbeWithEnroll(pr, time.Now())
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "保存失败"})
		return
	}
	writeJSON(w, 200, map[string]any{
		"id":        pr.ID,
		"install":   a.installCommand(code),
		"uninstall": a.uninstallCommand(),
		"expiresAt": exp.Unix(),
	})
}

// GET /api/probes (admin) — 列表；DELETE /api/probes?id=xx — 删除
func (a *App) handleProbes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		out := []map[string]any{}
		for _, pr := range a.store.Probes() {
			st := a.probes.get(pr.ID)
			online := st != nil && time.Since(st.LastSeen) < 15*time.Second
			name := pr.Name
			if name == "" && st != nil {
				name = st.Hostname
			}
			out = append(out, map[string]any{
				"id": pr.ID, "name": name, "public": pr.Public, "maskIP": pr.MaskIP,
				"online":      online,
				"enrolled":    pr.TokenHash != "",
				"legacyAgent": pr.LegacyAgent,
				"createdAt":   pr.CreatedAt,
			})
		}
		writeJSON(w, 200, out)
	case http.MethodDelete:
		id := r.URL.Query().Get("id")
		a.store.DeleteProbe(id)
		a.probes.remove(id)
		writeJSON(w, 200, map[string]string{"ok": "1"})
	default:
		writeJSON(w, 405, map[string]string{"error": "method not allowed"})
	}
}

// POST /api/probe/report — agent 上报（Authorization: Bearer swp_…）
func (a *App) handleProbeReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "method not allowed"})
		return
	}
	pr, legacy, msg := a.agentProbe(r)
	if pr == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": msg})
		return
	}
	if legacy && !pr.LegacyAgent {
		a.store.UpdateProbe(pr.ID, func(p *Probe) error { p.LegacyAgent = true; return nil })
	}
	// 同一探针两次上报至少间隔 2 秒（agent 约每 6 秒一次）
	if prev := a.probes.get(pr.ID); prev != nil && time.Since(prev.LastSeen) < 2*time.Second {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too frequent"})
		return
	}
	var body struct {
		Hostname  string  `json:"hostname"`
		OS        string  `json:"os"`
		CPU       float64 `json:"cpu"`
		MemTotal  int64   `json:"memTotal"`
		MemUsed   int64   `json:"memUsed"`
		DiskTotal int64   `json:"diskTotal"`
		DiskUsed  int64   `json:"diskUsed"`
		RxRate    int64   `json:"rxRate"`
		TxRate    int64   `json:"txRate"`
		Load1     float64 `json:"load1"`
		Uptime    int64   `json:"uptime"`
		Procs     int     `json:"procs"`
		CPUModel  string  `json:"cpuModel"`
		CPUCores  int     `json:"cpuCores"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad json"})
		return
	}
	a.probes.report(pr.ID, &probeStats{
		Hostname: cleanText(body.Hostname, 40), OS: cleanText(body.OS, 40),
		IP:  a.clientIP(r),
		CPU: body.CPU, MemTotal: body.MemTotal, MemUsed: body.MemUsed,
		DiskTotal: body.DiskTotal, DiskUsed: body.DiskUsed,
		RxRate: body.RxRate, TxRate: body.TxRate,
		Load1: body.Load1, Uptime: body.Uptime, Procs: body.Procs,
		CPUModel: cleanText(body.CPUModel, 60), CPUCores: body.CPUCores,
		LastSeen: time.Now(),
	})
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

// cleanText 去掉控制字符并按字符数截断（上报内容会展示给访客）
func cleanText(s string, n int) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			continue
		}
		out = append(out, r)
		if len(out) >= n {
			break
		}
	}
	return string(out)
}

// GET /api/probes/public — 游客/管理员都能拉，按身份裁剪视图；解锁状态存服务端 Cookie
func (a *App) handleProbesPublic(w http.ResponseWriter, r *http.Request) {
	forAdmin := a.authOK(r)
	unlocked := a.readUnlocked(r)
	writeJSON(w, 200, a.probesForClient(forAdmin, unlocked))
}

// POST /api/probe/goodbye — 卸载时 agent 通知面板删除探针记录
func (a *App) handleProbeGoodbye(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "method not allowed"})
		return
	}
	pr, _, msg := a.agentProbe(r)
	if pr == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": msg})
		return
	}
	a.store.DeleteProbe(pr.ID)
	a.probes.remove(pr.ID)
	writeJSON(w, 200, map[string]string{"ok": "1"})
}
