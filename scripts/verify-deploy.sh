#!/usr/bin/env bash
# SSHWeb 探针版部署验收
#   用法：scripts/verify-deploy.sh <公开站URL> [VPS公网IP] [管理站Origin]
#   - 在公网上另一台 Linux 机器（或 WSL）执行：检查公开站与端口暴露
#   - 在 tailnet 设备上带第三个参数执行：额外检查管理站
#
# 结果分三类：✅ 通过 / ❌ 失败 / ⏭ 跳过。
#   请求失败、响应无法解析、缺少工具一律记为失败，不会被当成通过；
#   跳过项表示条件不具备（例如还没有密码探针），不代表该项已验证。
# 退出码：0 = 没有失败项；1 = 有失败项；2 = 参数或依赖缺失。
set -u

PUB="${1:-}"
IP="${2:-}"
ADM="${3:-}"
if [ -z "$PUB" ]; then
  echo "用法: $0 https://farm.example.com [VPS公网IP] [https://vps.tailXXXX.ts.net]" >&2
  exit 2
fi
for tool in curl jq; do
  command -v "$tool" >/dev/null 2>&1 || { echo "缺少依赖：$tool（例如 sudo apt-get install -y $tool）" >&2; exit 2; }
done
PUB="${PUB%/}"; ADM="${ADM%/}"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
pass=0; fail=0; skip=0
ok()  { echo "  ✅ $*"; pass=$((pass+1)); }
bad() { echo "  ❌ $*"; fail=$((fail+1)); }
skp() { echo "  ⏭  $*"; skip=$((skip+1)); }

# fetch <输出文件> <curl 参数…>：打印 HTTP 状态码；curl 本身失败时打印 ERR
fetch() {
  local out="$1"; shift
  local code
  if code=$(curl -sS -o "$out" -D "$out.hdr" -w '%{http_code}' -m 15 "$@" 2>"$out.err"); then
    echo "$code"
  else
    echo "ERR"
  fi
}

# expect <名称> <期望状态码> <实际>
expect() {
  case "$3" in
    ERR|000) bad "$1：请求失败（$(head -c 120 "$TMP/last.err" 2>/dev/null)）" ;;
    "$2")    ok "$1" ;;
    *)       bad "$1：返回 $3，期望 $2" ;;
  esac
}

# req <名称> <期望状态码> <curl 参数…>
req() {
  local name="$1" want="$2"; shift 2
  local code
  code=$(fetch "$TMP/last" "$@")
  expect "$name" "$want" "$code"
}

# has_header <响应头文件> <头名>
has_header() { grep -qi "^$2:" "$1" 2>/dev/null; }

echo "== 公开站 $PUB"
case "$PUB" in https://*) ok "使用 https" ;; *) bad "公开站不是 https" ;; esac

code=$(fetch "$TMP/home" "$PUB/")
if [ "$code" = 200 ]; then
  ok "首页 200"
  has_header "$TMP/home.hdr" content-security-policy && grep -qi "script-src 'self'" "$TMP/home.hdr" \
    && ok "CSP 已下发" || bad "缺少 CSP"
  has_header "$TMP/home.hdr" strict-transport-security && ok "HSTS 已下发" || bad "缺少 HSTS（在反代上配置）"
else
  bad "首页请求失败：$code"
fi

code=$(fetch "$TMP/sess" "$PUB/api/session")
if [ "$code" != 200 ]; then
  bad "公开站 /api/session 请求失败：$code"
elif jq -e '.adminSite == false and .loggedIn == false' "$TMP/sess" >/dev/null 2>&1; then
  ok "公开站不是管理口"
else
  bad "公开站 /api/session 异常：$(head -c 200 "$TMP/sess")"
fi

for p in /api/login /api/logout /api/password /api/servers /ws/terminal /api/probe/join /api/probes \
         /api/probes/revoke /api/probes/rotate /api/keys /api/admin/clearblocks; do
  req "公开站无管理路由 $p" 404 -X POST -H "Origin: $PUB" -H 'X-SSHWeb: 1' -H 'Content-Type: application/json' -d '{}' "$PUB$p"
done
req "解锁接口拒绝 GET" 405 "$PUB/api/probe/unlock?id=x&pass=y"
req "跨站解锁被拒" 403 -X POST -H 'Origin: https://evil.example' -H 'X-SSHWeb: 1' \
  -H 'Content-Type: application/json' -d '{"id":"x","pass":"y"}' "$PUB/api/probe/unlock"
# WebSocket 握手只在 HTTP/1.1 上有效
req "跨站 WebSocket 被拒" 403 --http1.1 -H 'Origin: https://evil.example' -H 'Connection: Upgrade' \
  -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' "$PUB/ws/game"

code=$(fetch "$TMP/agent.sh" "$PUB/probe/agent.sh")
if [ "$code" != 200 ]; then
  bad "安装脚本请求失败：$code"
elif grep -qF "PANEL='$PUB'" "$TMP/agent.sh"; then
  ok "安装脚本面板地址正确"
else
  bad "安装脚本面板地址与公开站不一致"
fi

# 探针隐私：按对象检查字段，不依赖 JSON 字段顺序
LOCKED_KEYS='["id","locked","name","online","public"]'
code=$(fetch "$TMP/probes" "$PUB/api/probes/public")
if [ "$code" != 200 ]; then
  bad "探针列表请求失败：$code"
elif ! jq -e 'type == "array"' "$TMP/probes" >/dev/null 2>&1; then
  bad "探针列表不是 JSON 数组"
else
  nlocked=$(jq '[.[] | select(.locked == true)] | length' "$TMP/probes")
  if [ "$nlocked" -eq 0 ]; then
    skp "没有密码探针：未检查锁定探针字段与伪造 Cookie（建好密码探针后重跑）"
  else
    extra=$(jq -r --argjson allow "$LOCKED_KEYS" \
      '[.[] | select(.locked == true) | {id, extra: ((keys - $allow) | join(","))} | select(.extra != "")]
       | map("\(.id): \(.extra)") | join("; ")' "$TMP/probes")
    if [ -z "$extra" ]; then
      ok "锁定探针（$nlocked 只）只下发 id/name/online/public/locked"
    else
      bad "锁定探针下发了受保护字段：$extra"
    fi
    for id in $(jq -r '.[] | select(.locked == true) | .id' "$TMP/probes"); do
      case "$id" in ''|*[!0-9a-f]*) bad "探针 ID 格式异常：$id"; continue ;; esac
      code=$(fetch "$TMP/forged" -H "Cookie: __Host-pv_$id=1; pv_$id=1; probe_unlock_$id=1" "$PUB/api/probes/public")
      if [ "$code" != 200 ]; then
        bad "伪造 Cookie 请求失败（$id）：$code"
      elif [ "$(jq -r --arg id "$id" '[.[] | select(.id == $id)][0].locked // "missing"' "$TMP/forged" 2>/dev/null)" = "true" ]; then
        ok "伪造解锁 Cookie 无效（$id）"
      else
        bad "伪造 Cookie 解锁了探针或响应异常（$id）"
      fi
    done
  fi
fi

if [ -n "$IP" ]; then
  echo "== 端口暴露 $IP（请在公网上另一台机器执行）"
  for port in 45678 45679; do
    curl -s -o /dev/null -m 5 "http://$IP:$port/" 2>/dev/null
    rc=$?
    case "$rc" in
      7)  ok "端口 $port 拒绝连接" ;;
      28) ok "端口 $port 连接超时（被过滤）" ;;
      0|52|56) bad "端口 $port 对外可达（curl 退出码 $rc）" ;;
      *)  bad "端口 $port 无法判断：curl 退出码 $rc（检查 IP 是否填对、本机网络是否正常）" ;;
    esac
  done
else
  skp "未提供 VPS 公网 IP：未检查端口暴露"
fi

if [ -n "$ADM" ]; then
  echo "== 管理站 $ADM（请在 tailnet 设备上执行）"
  code=$(fetch "$TMP/asess" "$ADM/api/session")
  if [ "$code" != 200 ]; then
    bad "管理站 /api/session 请求失败：$code（是否已连上 tailnet？）"
  elif ! jq -e '.adminSite == true' "$TMP/asess" >/dev/null 2>&1; then
    bad "该地址不是管理口：$(head -c 200 "$TMP/asess")"
  else
    ok "管理站可访问"
    jq -e '.ssh == false' "$TMP/asess" >/dev/null 2>&1 && ok "网页 SSH 已关闭" || bad "网页 SSH 处于开启状态"
  fi
  req "管理站跨站写请求被拒" 403 -X POST -H 'Origin: https://evil.example' -H 'X-SSHWeb: 1' \
    -H 'Content-Type: application/json' -d '{"password":"x"}' "$ADM/api/login"
  req "缺少 X-SSHWeb 被拒" 403 -X POST -H "Origin: $ADM" -H 'Content-Type: application/json' \
    -d '{"password":"x"}' "$ADM/api/login"
  req "带错误 Origin 的读取被拒" 403 -H 'Origin: https://evil.example' "$ADM/api/session"
else
  skp "未提供管理站地址：未检查管理站"
fi

echo
echo "通过 $pass 项，失败 $fail 项，跳过 $skip 项（跳过不等于通过）"
[ "$fail" -eq 0 ]
