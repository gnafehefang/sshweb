package main

// probe.go — 公开探针系统：
//   管理端生成 token → 任意服务器 curl 一键安装 bash agent → 周期上报 CPU/内存/磁盘/网速
//   农场里出现一只 📡 探针鸡，点击查看状态卡片
//   支持：完全公开 / 密码查看（见 probeauth.go）/ IP 掩码

import (
	"crypto/rand"
	"encoding/hex"
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
	Token        string    `json:"token"`
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
	b := make([]byte, 16)
	rand.Read(b)
	pr := &Probe{
		ID:           newID()[:12],
		Token:        hex.EncodeToString(b),
		Name:         cleanText(strings.TrimSpace(body.Name), 32),
		Public:       body.Public,
		ViewPassHash: viewHash,
		MaskIP:       body.MaskIP,
		CreatedAt:    time.Now(),
	}
	if err := a.store.AddProbe(pr); err != nil {
		writeJSON(w, 500, map[string]string{"error": "保存失败"})
		return
	}
	// v0.5.0：全员无限材料，不再发每日探针奖励
	base := a.cfg.PublicURL
	writeJSON(w, 200, map[string]any{
		"id":        pr.ID,
		"install":   fmt.Sprintf("curl -fsSL '%s/probe/agent.sh?t=%s' | sudo bash", base, pr.Token),
		"uninstall": fmt.Sprintf("curl -fsSL '%s/probe/uninstall.sh' | sudo bash", base),
	})
}

// GET /api/probes (admin) — 列表；DELETE /api/probes?id=xx — 删除
func (a *App) handleProbes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		base := a.cfg.PublicURL
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
				"online":    online,
				"install":   fmt.Sprintf("curl -fsSL '%s/probe/agent.sh?t=%s' | sudo bash", base, pr.Token),
				"createdAt": pr.CreatedAt,
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

// POST /api/probe/report?t=token — agent 上报
func (a *App) handleProbeReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, 405, map[string]string{"error": "method not allowed"})
		return
	}
	token := r.URL.Query().Get("t")
	pr := a.store.ProbeByToken(token)
	if pr == nil {
		writeJSON(w, 404, map[string]string{"error": "invalid token"})
		return
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

// POST /api/probe/goodbye?t=token — 卸载时 agent 通知面板删除探针记录
func (a *App) handleProbeGoodbye(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("t")
	pr := a.store.ProbeByToken(token)
	if pr == nil {
		writeJSON(w, 404, map[string]string{"error": "invalid token"})
		return
	}
	a.store.DeleteProbe(pr.ID)
	a.probes.remove(pr.ID)
	writeJSON(w, 200, map[string]string{"ok": "1"})
}

/* ---------------- agent 安装/卸载脚本 ---------------- */

func agentScript(base, token string) string {
	return `#!/usr/bin/env bash
# SSHWeb 农场探针 agent — 一键安装
set -e
PANEL="` + base + `"
TOKEN="` + token + `"
BIN=/usr/local/bin/sshweb-probe.sh
UNIT=/etc/systemd/system/sshweb-probe.service

cat > /etc/sshweb-probe.env <<ENVEOF
PANEL="$PANEL"
TOKEN="$TOKEN"
ENVEOF
chmod 600 /etc/sshweb-probe.env

cat > "$BIN" <<'AGENT'
#!/usr/bin/env bash
PANEL="__PANEL__"
TOKEN="__TOKEN__"
prev_rx=0; prev_tx=0; prev_t=0
num() { case "$1" in ''|*[!0-9.]*) echo 0;; *) echo "$1";; esac; }
read_net() {
  awk 'NR>2 {gsub(/:/," ",$1); rx+=$2; tx+=$10} END {print rx+0, tx+0}' /proc/net/dev
}
read_cpu() {
  read -r _ u1 n1 s1 i1 w1 irq1 sirq1 st1 _ < /proc/stat
  sleep 1
  read -r _ u2 n2 s2 i2 w2 irq2 sirq2 st2 _ < /proc/stat
  idle=$(( (i2 + w2) - (i1 + w1) ))
  total=$(( (u2+n2+s2+i2+w2+irq2+sirq2+st2) - (u1+n1+s1+i1+w1+irq1+sirq1+st1) ))
  if [ "$total" -le 0 ]; then echo 0; else echo $(( (100 * (total - idle)) / total )); fi
}
read_load() { awk '{print $1}' /proc/loadavg; }
read_procs() { awk '/^procs_running/{r=$2} /^procs_blocked/{b=$2} END{print r+b}' /proc/stat; }
read_uptime() { cut -d. -f1 /proc/uptime; }
read_cpumodel() {
  awk -F': ' '/^model name/{gsub(/"/,"",$2); print $2; exit}' /proc/cpuinfo
}
read_cores() { nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo; }
CPU_MODEL=$(read_cpumodel | tr -d '"\\' | cut -c1-60)
CPU_CORES=$(num "$(read_cores)")
HOST=$(hostname | tr -d '"\\' | cut -c1-40)
while true; do
  cpu=$(read_cpu)
  mem_total=$(awk '/^MemTotal:/{print $2+0}' /proc/meminfo)
  mem_avail=$(awk '/^MemAvailable:/{print $2+0}' /proc/meminfo)
  [ -z "$mem_avail" ] && mem_avail=$(awk '/^MemFree:/{print $2+0}' /proc/meminfo)
  mem_used=$(( mem_total - mem_avail ))
  [ "$mem_used" -lt 0 ] && mem_used=0
  disk_total=$(df -P -k / 2>/dev/null | awk 'NR==2 {print $2+0}')
  disk_used=$(df -P -k / 2>/dev/null | awk 'NR==2 {print $3+0}')
  disk_total=$(num "$disk_total"); disk_used=$(num "$disk_used")
  read -r rx tx < <(read_net)
  rx=$(num "$rx"); tx=$(num "$tx")
  load1=$(num "$(read_load)")
  procs=$(num "$(read_procs)")
  uptime_s=$(num "$(read_uptime)")
  now=$(date +%s)
  rx_rate=0; tx_rate=0
  if [ "$prev_t" -gt 0 ]; then
    dt=$(( now - prev_t ))
    [ "$dt" -gt 0 ] && { rx_rate=$(( (rx - prev_rx) / dt )); tx_rate=$(( (tx - prev_tx) / dt )); }
  fi
  prev_rx=$rx; prev_tx=$tx; prev_t=$now
  PAYLOAD="{\"hostname\":\"$HOST\",\"os\":\"$(uname -sr)\",\"cpu\":$cpu,\"memTotal\":$mem_total,\"memUsed\":$mem_used,\"diskTotal\":$disk_total,\"diskUsed\":$disk_used,\"rxRate\":$rx_rate,\"txRate\":$tx_rate,\"load1\":$load1,\"uptime\":$uptime_s,\"procs\":$procs,\"cpuModel\":\"$CPU_MODEL\",\"cpuCores\":$CPU_CORES}"
  if command -v curl >/dev/null 2>&1; then
    curl -fsS -m 8 -X POST "$PANEL/api/probe/report?t=$TOKEN" -H 'Content-Type: application/json' -d "$PAYLOAD" >/dev/null 2>&1 || true
  elif command -v wget >/dev/null 2>&1; then
    wget -q -T 8 -O /dev/null --post-data="$PAYLOAD" --header='Content-Type: application/json' "$PANEL/api/probe/report?t=$TOKEN" >/dev/null 2>&1 || true
  fi
  sleep 5
done
AGENT
sed -i "s|__PANEL__|$PANEL|; s|__TOKEN__|$TOKEN|" "$BIN"
chmod +x "$BIN"

cat > "$UNIT" <<UNIT
[Unit]
Description=SSHWeb Farm Probe Agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$BIN
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable sshweb-probe >/dev/null 2>&1
systemctl restart sshweb-probe
echo "✅ SSHWeb 探针已安装并启动（服务名 sshweb-probe）"
echo "   卸载： curl -fsSL '$PANEL/probe/uninstall.sh' | sudo bash"
`
}

const uninstallScript = `#!/usr/bin/env bash
set -e
BIN=/usr/local/bin/sshweb-probe.sh
ENVF=/etc/sshweb-probe.env
# 取面板地址与 token（新版读 env 文件；旧版 agent 直接从脚本里解析）
PANEL=""; TOKEN=""
if [ -f "$ENVF" ]; then
  . "$ENVF"
fi
if [ -z "$TOKEN" ] && [ -f "$BIN" ]; then
  PANEL=$(grep -oE 'PANEL="[^"]+"' "$BIN" | head -1 | sed 's/PANEL="//; s/"$//')
  TOKEN=$(grep -oE 'TOKEN="[^"]+"' "$BIN" | head -1 | sed 's/TOKEN="//; s/"$//')
fi
systemctl disable --now sshweb-probe >/dev/null 2>&1 || true
rm -f /etc/systemd/system/sshweb-probe.service "$BIN" "$ENVF"
systemctl daemon-reload
# 通知面板删除探针记录（失败不阻塞，面板端也可在管理面板手动删除）
if [ -n "$PANEL" ] && [ -n "$TOKEN" ]; then
  if command -v curl >/dev/null 2>&1; then
    curl -fsS -m 8 -X POST "$PANEL/api/probe/goodbye?t=$TOKEN" >/dev/null 2>&1 || true
  elif command -v wget >/dev/null 2>&1; then
    wget -q -T 8 -O /dev/null --post-data="" "$PANEL/api/probe/goodbye?t=$TOKEN" >/dev/null 2>&1 || true
  fi
fi
echo "🗑️ SSHWeb 探针已卸载（面板中的探针鸡将在几秒内消失）"
`

func (a *App) handleProbeAgentScript(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("t")
	pr := a.store.ProbeByToken(token)
	if pr == nil {
		http.Error(w, "invalid token", 404)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, agentScript(a.cfg.PublicURL, token))
}

func (a *App) handleProbeUninstallScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, uninstallScript)
}
