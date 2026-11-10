package main

// agent.go — 探针 agent 的注册、鉴权与安装脚本（阶段 2）
//
//   1. 管理员创建探针 → 得到一次性注册码 swe_…（30 分钟有效，只能用一次，库里只存哈希）
//   2. 目标机执行：curl -fsSL '<面板>/probe/agent.sh' | sudo bash -s -- swe_…
//      脚本经标准输入把注册码 POST 到 /api/probe/enroll，换取长期 token swp_…
//   3. token 写入 /etc/sshweb-probe/auth-header（root 0600），systemd 用 LoadCredential=
//      交给 DynamicUser 运行的 agent；agent 用 curl -H @文件 发送，进程参数里没有 token
//   4. 面板只存 token 的哈希；上报/卸载用 Authorization: Bearer swp_…
//   旧版 ?t= 方式默认关闭，仅在 SSHWEB_LEGACY_AGENT_UNTIL 截止日期前兼容。

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const enrollTTL = 30 * time.Minute

func probeTokenHash(tok string) string {
	h := sha256.Sum256([]byte("sshweb/probe-token/v1|" + tok))
	return hex.EncodeToString(h[:])
}

func enrollCodeHash(code string) string {
	h := sha256.Sum256([]byte("sshweb/enroll-code/v1|" + code))
	return hex.EncodeToString(h[:])
}

func validToken(tok, prefix string, hexLen int) bool {
	if !strings.HasPrefix(tok, prefix) || len(tok) != len(prefix)+hexLen {
		return false
	}
	_, err := hex.DecodeString(tok[len(prefix):])
	return err == nil
}

// ---------------- Store：注册码 ----------------

const enrollSchema = `CREATE TABLE IF NOT EXISTS enroll_codes(
	code_hash TEXT PRIMARY KEY, probe_id TEXT NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER)`

var errEnrollInvalid = errors.New("注册码无效、已使用或已过期")

// createEnrollCodeLocked 为探针生成新的注册码，并作废它之前未使用的注册码（调用方持有 s.mu）
func (s *Store) createEnrollCodeLocked(ex execer, probeID string, now time.Time) (string, time.Time, error) {
	code := "swe_" + hex.EncodeToString(randomBytes(16))
	exp := now.Add(enrollTTL)
	if _, err := ex.Exec("DELETE FROM enroll_codes WHERE probe_id=? AND used_at IS NULL", probeID); err != nil {
		return "", time.Time{}, err
	}
	if _, err := ex.Exec("INSERT INTO enroll_codes(code_hash,probe_id,expires_at) VALUES(?,?,?)",
		enrollCodeHash(code), probeID, exp.Unix()); err != nil {
		return "", time.Time{}, err
	}
	return code, exp, nil
}

// AddProbeWithEnroll 新建探针并生成注册码（同一事务）
func (s *Store) AddProbeWithEnroll(pr *Probe, now time.Time) (string, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return "", time.Time{}, err
	}
	defer tx.Rollback()
	if err := upsertJSON(tx, "probes", "id", pr.ID, pr); err != nil {
		return "", time.Time{}, err
	}
	code, exp, err := s.createEnrollCodeLocked(tx, pr.ID, now)
	if err != nil {
		return "", time.Time{}, err
	}
	if err := tx.Commit(); err != nil {
		return "", time.Time{}, err
	}
	s.ProbeList = append(s.ProbeList, cloneProbe(pr))
	return code, exp, nil
}

// RotateProbe 作废现有 token（旧 agent 立即无法上报），并生成新的注册码
func (s *Store) RotateProbe(id string, now time.Time) (string, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := -1
	for i, p := range s.ProbeList {
		if p.ID == id {
			idx = i
		}
	}
	if idx < 0 {
		return "", time.Time{}, errProbeNotFound
	}
	next := cloneProbe(s.ProbeList[idx])
	next.TokenHash, next.LegacyAgent = "", false
	tx, err := s.db.Begin()
	if err != nil {
		return "", time.Time{}, err
	}
	defer tx.Rollback()
	if err := upsertJSON(tx, "probes", "id", next.ID, next); err != nil {
		return "", time.Time{}, err
	}
	code, exp, err := s.createEnrollCodeLocked(tx, id, now)
	if err != nil {
		return "", time.Time{}, err
	}
	if err := tx.Commit(); err != nil {
		return "", time.Time{}, err
	}
	s.ProbeList[idx] = next
	return code, exp, nil
}

// RedeemEnrollCode 原子兑换注册码：检查有效 → 标记已用 → 生成 token → 写入探针，在同一事务内完成。
// 条件更新保证并发兑换同一注册码时只有一个成功。
func (s *Store) RedeemEnrollCode(code string, now time.Time) (probeID, token string, err error) {
	if !validToken(code, "swe_", 32) {
		return "", "", errEnrollInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return "", "", err
	}
	defer tx.Rollback()
	ch := enrollCodeHash(code)
	res, err := tx.Exec("UPDATE enroll_codes SET used_at=? WHERE code_hash=? AND used_at IS NULL AND expires_at>?",
		now.Unix(), ch, now.Unix())
	if err != nil {
		return "", "", err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return "", "", errEnrollInvalid
	}
	if err := tx.QueryRow("SELECT probe_id FROM enroll_codes WHERE code_hash=?", ch).Scan(&probeID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", errEnrollInvalid
		}
		return "", "", err
	}
	idx := -1
	for i, p := range s.ProbeList {
		if p.ID == probeID {
			idx = i
		}
	}
	if idx < 0 {
		return "", "", errEnrollInvalid
	}
	token = "swp_" + hex.EncodeToString(randomBytes(32))
	next := cloneProbe(s.ProbeList[idx])
	next.TokenHash, next.LegacyAgent = probeTokenHash(token), false
	if err := upsertJSON(tx, "probes", "id", next.ID, next); err != nil {
		return "", "", err
	}
	if err := tx.Commit(); err != nil {
		return "", "", err
	}
	s.ProbeList[idx] = next
	return probeID, token, nil
}

// ---------------- HTTP ----------------

func (a *App) installCommand(code string) string {
	return fmt.Sprintf("curl -fsSL '%s/probe/agent.sh' | sudo bash -s -- %s", a.cfg.PublicURL, code)
}

func (a *App) uninstallCommand() string {
	return fmt.Sprintf("curl -fsSL '%s/probe/uninstall.sh' | sudo bash", a.cfg.PublicURL)
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// agentProbe 按 Authorization: Bearer 识别探针；旧版 ?t= 只在兼容期内接受
func (a *App) agentProbe(r *http.Request) (pr *Probe, legacy bool, msg string) {
	if tok := bearerToken(r); tok != "" {
		if !validToken(tok, "swp_", 64) {
			return nil, false, "invalid token"
		}
		if pr := a.store.ProbeByTokenHash(probeTokenHash(tok)); pr != nil {
			return pr, false, ""
		}
		return nil, false, "invalid token"
	}
	if t := r.URL.Query().Get("t"); t != "" {
		if !a.cfg.legacyAgentAllowed(time.Now()) {
			return nil, true, "旧版 agent 已停用：请在管理面板轮换 token 并重新安装"
		}
		if len(t) > 128 {
			return nil, true, "invalid token"
		}
		if pr := a.store.ProbeByTokenHash(probeTokenHash(t)); pr != nil {
			return pr, true, ""
		}
	}
	return nil, false, "invalid token"
}

// POST /api/probe/enroll {"code"} — agent 用一次性注册码换取长期 token
func (a *App) handleProbeEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !a.enrollLimiter.allow(a.clientIP(r)) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many requests"})
		return
	}
	var in struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&in); err != nil {
		writeJSON(w, 400, map[string]string{"error": "bad json"})
		return
	}
	id, tok, err := a.store.RedeemEnrollCode(strings.TrimSpace(in.Code), time.Now())
	if err != nil {
		if errors.Is(err, errEnrollInvalid) {
			writeJSON(w, 403, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 500, map[string]string{"error": "enroll failed"})
		return
	}
	a.probes.remove(id) // 新 agent 重新开始上报
	writeJSON(w, 200, map[string]string{"probeId": id, "token": tok})
}

// POST /api/probes/rotate {"id"}（管理员）— 作废旧 token，生成新的安装命令
func (a *App) handleProbeRotate(w http.ResponseWriter, r *http.Request) {
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
	code, exp, err := a.store.RotateProbe(in.ID, time.Now())
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": err.Error()})
		return
	}
	a.probes.remove(in.ID)
	writeJSON(w, 200, map[string]any{
		"id": in.ID, "install": a.installCommand(code), "uninstall": a.uninstallCommand(), "expiresAt": exp.Unix(),
	})
}

// ---------------- 安装 / 卸载脚本 ----------------

// agentBody 安装到 /usr/local/lib/sshweb-probe/agent.sh 的上报脚本（不含任何秘密）
const agentBody = `#!/usr/bin/env bash
# SSHWeb 农场探针 agent（由 systemd 以无特权用户运行）
PANEL='__PANEL__'
HDR="${CREDENTIALS_DIRECTORY:-/etc/sshweb-probe}/auth-header"
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
CPU_MODEL=$(read_cpumodel | tr -d '"\\' | tr -cd '[:print:]' | cut -c1-60)
CPU_CORES=$(num "$(read_cores)")
HOST=$(hostname | tr -d '"\\' | tr -cd '[:print:]' | cut -c1-40)
OS=$(uname -sr | tr -d '"\\' | tr -cd '[:print:]' | cut -c1-40)
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
  PAYLOAD="{\"hostname\":\"$HOST\",\"os\":\"$OS\",\"cpu\":$cpu,\"memTotal\":$mem_total,\"memUsed\":$mem_used,\"diskTotal\":$disk_total,\"diskUsed\":$disk_used,\"rxRate\":$rx_rate,\"txRate\":$tx_rate,\"load1\":$load1,\"uptime\":$uptime_s,\"procs\":$procs,\"cpuModel\":\"$CPU_MODEL\",\"cpuCores\":$CPU_CORES}"
  # token 只在 HDR 文件里：curl 通过 -H @文件 读取，不出现在进程参数中
  curl -fsS -m 8 -X POST "$PANEL/api/probe/report" -H @"$HDR" -H 'Content-Type: application/json' --data-binary "$PAYLOAD" >/dev/null 2>&1 || true
  sleep 5
done
`

// installTemplate 安装脚本：__PANEL__ 与 __AGENT_BODY__ 由服务端替换
const installTemplate = `#!/usr/bin/env bash
# SSHWeb 农场探针一键安装
#   用法：curl -fsSL '__PANEL__/probe/agent.sh' | sudo bash -s -- <一次性注册码>
set -euo pipefail
PANEL='__PANEL__'
CODE="${1:-}"
ETC=/etc/sshweb-probe
LIB=/usr/local/lib/sshweb-probe
UNIT=/etc/systemd/system/sshweb-probe.service

die() { echo "❌ $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "请用 root 或 sudo 执行"
[[ "$CODE" =~ ^swe_[0-9a-f]{32}$ ]] || die "缺少或无效的注册码（用法：... | sudo bash -s -- swe_xxx）"
command -v curl >/dev/null 2>&1 || die "需要 curl（7.55 及以上）"
command -v systemctl >/dev/null 2>&1 || die "需要 systemd"

# curl 7.55 起支持 -H @文件，token 才能不出现在进程参数里
cv=$(curl --version | head -n1 | awk '{print $2}')
cmaj=${cv%%.*}; crest=${cv#*.}; cmin=${crest%%.*}
if [ "${cmaj:-0}" -lt 7 ] || { [ "$cmaj" -eq 7 ] && [ "${cmin:-0}" -lt 55 ]; }; then
  die "curl 版本过低（$cv），需要 7.55 及以上"
fi
sdv=$(systemctl --version | head -n1 | awk '{print $2}' | tr -cd '0-9')
sdv=${sdv:-0}

umask 077
mkdir -p "$ETC" "$LIB"
chmod 700 "$ETC"

# 用注册码换取长期 token：注册码经标准输入交给 curl，响应写入仅 root 可读的临时文件
TMP=$(mktemp "$ETC/.enroll.XXXXXX")
trap 'rm -f "$TMP"' EXIT
printf '{"code":"%s"}' "$CODE" | curl -fsS -m 15 -X POST "$PANEL/api/probe/enroll" \
  -H 'Content-Type: application/json' --data-binary @- -o "$TMP" \
  || die "注册失败：注册码无效、已使用或已过期（请在管理面板重新生成安装命令）"
TOKEN=$(sed -n 's/.*"token":"\(swp_[0-9a-f]\{64\}\)".*/\1/p' "$TMP")
[ -n "$TOKEN" ] || die "注册响应异常"
printf 'Authorization: Bearer %s\n' "$TOKEN" > "$ETC/auth-header"
unset TOKEN
chmod 600 "$ETC/auth-header"

cat > "$LIB/agent.sh" <<'AGENT_EOF'
__AGENT_BODY__AGENT_EOF
chmod 755 "$LIB" "$LIB/agent.sh"

# 清理旧版 agent 残留（token 曾以全局可读方式写在脚本里）
systemctl disable --now sshweb-probe >/dev/null 2>&1 || true
rm -f /usr/local/bin/sshweb-probe.sh /etc/sshweb-probe.env

COMMON='NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
CapabilityBoundingSet=
AmbientCapabilities=
UMask=0077'

if [ "$sdv" -ge 247 ]; then
  CRED="DynamicUser=yes
LoadCredential=auth-header:$ETC/auth-header
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native"
else
  # systemd < 247 没有 LoadCredential：改用固定的专用用户 + 0400 文件
  id sshweb-probe >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin sshweb-probe
  chown root:sshweb-probe "$ETC"; chmod 750 "$ETC"
  chown sshweb-probe:sshweb-probe "$ETC/auth-header"; chmod 400 "$ETC/auth-header"
  CRED="User=sshweb-probe
Group=sshweb-probe
Environment=CREDENTIALS_DIRECTORY=$ETC"
  echo "⚠️  systemd $sdv 低于 247，已退回到专用用户模式"
fi

cat > "$UNIT" <<UNIT_EOF
[Unit]
Description=SSHWeb Farm Probe Agent
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$LIB/agent.sh
Restart=always
RestartSec=5
$CRED
$COMMON

[Install]
WantedBy=multi-user.target
UNIT_EOF
chmod 644 "$UNIT"

systemctl daemon-reload
systemctl enable sshweb-probe >/dev/null 2>&1
systemctl restart sshweb-probe
echo "✅ SSHWeb 探针已安装并启动（服务 sshweb-probe，无 root 权限运行）"
echo "   卸载： curl -fsSL '$PANEL/probe/uninstall.sh' | sudo bash"
`

const uninstallTemplate = `#!/usr/bin/env bash
# SSHWeb 农场探针卸载
set -u
PANEL='__PANEL__'
ETC=/etc/sshweb-probe
[ "$(id -u)" -eq 0 ] || { echo "请用 root 或 sudo 执行" >&2; exit 1; }
systemctl disable --now sshweb-probe >/dev/null 2>&1 || true
# 通知面板删除探针记录（失败不阻塞，也可在管理面板手动删除）
if [ -f "$ETC/auth-header" ] && command -v curl >/dev/null 2>&1; then
  curl -fsS -m 8 -X POST "$PANEL/api/probe/goodbye" -H @"$ETC/auth-header" >/dev/null 2>&1 || true
fi
rm -f /etc/systemd/system/sshweb-probe.service
rm -rf "$ETC" /usr/local/lib/sshweb-probe
rm -f /usr/local/bin/sshweb-probe.sh /etc/sshweb-probe.env
if id sshweb-probe >/dev/null 2>&1; then userdel sshweb-probe >/dev/null 2>&1 || true; fi
systemctl daemon-reload
echo "🗑️ SSHWeb 探针已卸载"
`

func (a *App) installScript() string {
	body := strings.ReplaceAll(agentBody, "__PANEL__", a.cfg.PublicURL)
	s := strings.ReplaceAll(installTemplate, "__AGENT_BODY__", body)
	return strings.ReplaceAll(s, "__PANEL__", a.cfg.PublicURL)
}

func (a *App) uninstallScript() string {
	return strings.ReplaceAll(uninstallTemplate, "__PANEL__", a.cfg.PublicURL)
}

func (a *App) handleProbeAgentScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, a.installScript())
}

func (a *App) handleProbeUninstallScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, a.uninstallScript())
}
