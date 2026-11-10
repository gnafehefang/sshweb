#!/usr/bin/env bash
# SSHWeb 探针版部署验收
#   用法：scripts/verify-deploy.sh <公开站URL> [VPS公网IP] [管理站Origin]
#   - 在公网上另一台机器执行：检查公开站与端口暴露
#   - 在 tailnet 设备上带第三个参数执行：额外检查管理站
set -u
PUB="${1:?用法: $0 https://farm.example.com [VPS公网IP] [https://admin.ts.net]}"
IP="${2:-}"
ADM="${3:-}"
pass=0; fail=0
ok()  { echo "  ✅ $*"; pass=$((pass+1)); }
bad() { echo "  ❌ $*"; fail=$((fail+1)); }
code() { curl -s -o /dev/null -w '%{http_code}' -m 10 "$@"; }
hdr()  { curl -s -D - -o /dev/null -m 10 "$1" | tr -d '\r' | grep -i "^$2:" | head -1; }

echo "== 公开站 $PUB"
[ "$(code "$PUB/")" = 200 ] && ok "首页 200" || bad "首页不可访问"
case "$PUB" in https://*) ok "使用 https";; *) bad "公开站不是 https";; esac
csp=$(hdr "$PUB/" content-security-policy)
echo "$csp" | grep -q "script-src 'self'" && ok "CSP 已下发" || bad "缺少 CSP"
hdr "$PUB/" strict-transport-security | grep -qi max-age && ok "HSTS 已下发" || bad "缺少 HSTS（在反代上配置）"
for p in /api/login /api/logout /api/password /api/servers /ws/terminal /api/probe/join /api/probes /api/keys /api/admin/clearblocks; do
  c=$(code -X POST -H "Origin: $PUB" -H 'X-SSHWeb: 1' -H 'Content-Type: application/json' -d '{}' "$PUB$p")
  [ "$c" = 404 ] && ok "公开站无管理路由 $p" || bad "公开站 $p 返回 $c（应为 404）"
done
c=$(code "$PUB/api/probe/unlock?id=x&pass=y")
[ "$c" = 405 ] && ok "解锁接口拒绝 GET" || bad "解锁接口 GET 返回 $c（应为 405）"
c=$(code -X POST -H 'Origin: https://evil.example' -H 'X-SSHWeb: 1' -H 'Content-Type: application/json' -d '{"id":"x","pass":"y"}' "$PUB/api/probe/unlock")
[ "$c" = 403 ] && ok "跨站解锁被拒" || bad "跨站解锁返回 $c（应为 403）"
body=$(curl -s -m 10 -H 'X-Forwarded-For: 1.2.3.4' "$PUB/api/probes/public")
echo "$body" | grep -q '"locked":true' && { echo "$body" | grep -o '"locked":true[^}]*' | grep -q hostname && bad "锁定探针暴露了主机名" || ok "锁定探针未暴露主机名"; } || echo "  ℹ️  当前没有密码探针，跳过主机名检查"
# 伪造解锁 Cookie
pid=$(echo "$body" | grep -o '"id":"[0-9a-f]*","locked":true' | head -1 | sed 's/"id":"\([0-9a-f]*\)".*/\1/')
if [ -n "$pid" ]; then
  f=$(curl -s -m 10 -H "Cookie: __Host-pv_$pid=1; probe_unlock_$pid=1" "$PUB/api/probes/public")
  echo "$f" | grep -q "\"id\":\"$pid\",\"locked\":true" && ok "伪造解锁 Cookie 无效" || bad "伪造 Cookie 解锁了探针 $pid"
fi
curl -s -m 10 "$PUB/probe/agent.sh" | grep -q "PANEL='$PUB'" && ok "安装脚本面板地址正确" || bad "安装脚本面板地址与公开站不一致"
c=$(code -H 'Origin: https://evil.example' -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' "$PUB/ws/game")
[ "$c" = 403 ] && ok "跨站 WebSocket 被拒" || bad "跨站 WebSocket 返回 $c（应为 403）"

if [ -n "$IP" ]; then
  echo "== 端口暴露 $IP（请在公网上另一台机器执行）"
  for port in 45678 45679; do
    if timeout 5 bash -c "exec 3<>/dev/tcp/$IP/$port" 2>/dev/null; then bad "端口 $port 对外可达"; else ok "端口 $port 不可达"; fi
  done
fi

if [ -n "$ADM" ]; then
  echo "== 管理站 $ADM（请在 tailnet 设备上执行）"
  s=$(curl -s -m 10 "$ADM/api/session")
  echo "$s" | grep -q '"adminSite":true' && ok "管理站可访问" || bad "管理站不可访问或不是管理口"
  echo "$s" | grep -q '"ssh":false' && ok "网页 SSH 已关闭" || bad "网页 SSH 处于开启状态"
  c=$(code -X POST -H 'Origin: https://evil.example' -H 'X-SSHWeb: 1' -H 'Content-Type: application/json' -d '{"password":"x"}' "$ADM/api/login")
  [ "$c" = 403 ] && ok "管理站跨站写请求被拒" || bad "管理站跨站登录返回 $c（应为 403）"
  c=$(code -X POST -H "Origin: $ADM" -H 'Content-Type: application/json' -d '{"password":"x"}' "$ADM/api/login")
  [ "$c" = 403 ] && ok "缺少 X-SSHWeb 被拒" || bad "缺少 X-SSHWeb 返回 $c（应为 403）"
  c=$(code -H 'Origin: https://evil.example' "$ADM/api/session")
  [ "$c" = 403 ] && ok "带错误 Origin 的读取被拒" || bad "带错误 Origin 的读取返回 $c"
fi

echo
echo "通过 $pass 项，失败 $fail 项"
[ "$fail" -eq 0 ]
