#!/usr/bin/env bash
# SSHWeb 备份恢复：解压到新数据卷 → 在副本上完整读取数据库（含 WAL）并检查 → 确认后切换。
#   用法：sudo scripts/restore-backup.sh <备份文件.tgz> [--yes|--check-only]
#   - 检查阶段任何一步失败立即退出；原数据卷始终不改动、不删除
#   - 切换只改 docker-compose.override.yml 里 sshweb-probe-data 卷这一项，其他内容原样保留；
#     改动前后用 docker compose config 比对，除该卷外出现任何差异即拒绝，并恢复原文件
#   - 改动 override 之后，任何命令失败、检查不通过或被中断（Ctrl-C、kill、终端断开），
#     都会恢复原 override、重建容器，并确认容器回到原卷
#   - --check-only：只做检查，不切换
set -euo pipefail

cd "$(dirname "$0")/.."   # 仓库根目录（docker-compose.yml 所在）

# 当前版本必需的表及其列，与 store.go / agent.go / skill.go 的建表语句一致（restore_script_test.go 会核对）
REQUIRED_SCHEMA="meta:k,v servers:id,data probes:id,data players:ip,data blocks:x,y,z,type apikeys:key,name,created_at apikeys_v2:id,hash,prefix,name,created_at enroll_codes:code_hash,probe_id,expires_at,used_at"
VOLKEY=sshweb-probe-data
OVR=docker-compose.override.yml

B="${1:-}"
MODE="${2:-}"
# check：只读检查 → edit：已改 override，容器未动 → switch：已开始重建容器 → done：切换成功
PHASE=check
N="" CUR="" BAK="" NEWOVR=""

say()  { echo "$*" >&2; }
die()  { echo "❌ $*" >&2; exit 1; }
step() { echo; echo "== $*"; }
mount_of() { docker inspect "$1" --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}'; }
# jqc <jq 参数…>：在一次性 alpine 容器里运行 jq（宿主机不需要安装 jq），数据走标准输入
jqc() { docker run --rm -i alpine sh -euc 'apk add --no-cache jq >/dev/null 2>&1; exec jq "$@"' jq "$@"; }

# 改动 override 之后的失败与中断统一走这里
rollback() {
  set +e
  say ""
  say "⚠️  切换没有完成（退出码 $1），正在退回原配置…"
  local ok=0
  if [ -n "$BAK" ]; then cp -p "$BAK" "$OVR" || ok=1; else rm -f "$OVR" || ok=1; fi
  if [ "$ok" -ne 0 ]; then
    say "❌ 无法恢复 $OVR（原内容备份：${BAK:-原本没有该文件，应删除它}）。"
    say "   请手动恢复后执行 docker compose up -d --force-recreate sshweb；原卷 $CUR 未改动。"
    exit 1
  fi
  if [ "$PHASE" = edit ]; then
    say "已恢复 $OVR；容器没有重建，仍在使用原卷 $CUR。新卷 $N 未被使用，可用 docker volume rm $N 删除。"
    exit 1
  fi
  local st mnt
  docker compose up -d --force-recreate sshweb >&2 || say "⚠️  回滚时 docker compose up 返回失败，下面检查容器实际状态"
  sleep 5
  st=$(docker inspect sshweb --format '{{.State.Status}} {{.RestartCount}}' 2>/dev/null)
  mnt=$(mount_of sshweb 2>/dev/null)
  if [ "$st" = "running 0" ] && [ "$mnt" = "$CUR" ]; then
    say "已退回原卷 $CUR，容器运行正常。新卷 $N 保留未删除，排查后可用 docker volume rm $N 删除。"
  else
    say "❌ 自动退回未能确认成功（容器状态：${st:-读取失败}，挂载的卷：${mnt:-读取失败}）。"
    say "   $OVR 已恢复为切换前的内容，原卷 $CUR 未改动。请手动执行 docker compose up -d --force-recreate sshweb 并检查。"
  fi
  exit 1
}

on_exit() {
  local rc=$?
  trap - EXIT
  trap '' INT TERM HUP        # 收尾与回滚期间不再响应中断
  [ -z "$NEWOVR" ] || rm -f "$NEWOVR"
  case "$PHASE" in
    check)
      if [ "$rc" -ne 0 ] && [ -n "$N" ]; then
        say "（原卷 ${CUR:-未知} 未改动；新卷 $N 未被使用，可用 docker volume rm $N 删除）"
      fi ;;
    edit|switch) rollback "$rc" ;;
  esac
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

[ -n "$B" ] || die "用法: $0 <备份文件.tgz> [--yes|--check-only]"
case "$MODE" in ""|--yes|--check-only) ;; *) die "未知参数：$MODE" ;; esac
[ -f "$B" ] && [ -s "$B" ] || die "备份文件不存在或为空：$B"
B=$(readlink -f "$B")
command -v docker >/dev/null 2>&1 || die "需要 docker"
[ -f docker-compose.yml ] || die "找不到 docker-compose.yml，请在仓库目录运行"

step "1/6 检查备份文件 $B"
gzip -t "$B" || die "压缩包损坏"
LIST=$(tar tzf "$B") || die "无法读取压缩包内容"
grep -qx './sshweb.db' <<<"$LIST" || die "压缩包里没有 ./sshweb.db"
if grep -Eq '(^/|(^|/)\.\.(/|$))' <<<"$LIST"; then die "压缩包含有绝对路径或 ..，拒绝解压"; fi
echo "压缩包完整，包含：$(tr '\n' ' ' <<<"$LIST")"

step "2/6 读取当前服务与 Compose 配置"
IMG=$(docker inspect sshweb --format '{{.Config.Image}}') || die "找不到 sshweb 容器"
CUR=$(mount_of sshweb) || die "读不到当前数据卷"
[ -n "$CUR" ] || die "读不到当前数据卷"
SSH_ON=$(docker inspect sshweb --format '{{range .Config.Env}}{{println .}}{{end}}' | sed -n 's/^SSHWEB_ENABLE_SSH=//p')
APPUSER=$(docker run --rm --entrypoint /bin/sh "$IMG" -c 'echo "$(id -u):$(id -g)"') || die "无法读取镜像 $IMG 的运行用户"
echo "镜像 $IMG，当前数据卷 $CUR，应用用户 $APPUSER，SSHWEB_ENABLE_SSH=${SSH_ON:-0}"
# 配置里可能有密钥：只在内存里比对，不落盘、不打印取值
BEFORE=$(docker compose config --format json) || die "docker compose config 失败，请先修正 Compose 配置"
VOLINFO=$(jqc -r --arg k "$VOLKEY" \
  '(.volumes[$k] // {}) | "\(.name // "")\t\((keys - ["name","external"]) | join(","))"' <<<"$BEFORE") \
  || die "无法解析 docker compose config 的输出"
CFGVOL=${VOLINFO%%$'\t'*}
EXTRA=${VOLINFO#*$'\t'}
[ "$CFGVOL" = "$CUR" ] || die "Compose 配置里的数据卷（${CFGVOL:-未定义}）与运行中容器挂载的卷（$CUR）不一致，请先确认当前部署状态"
[ -z "$EXTRA" ] || die "数据卷 $VOLKEY 配置了 $EXTRA，本脚本只支持默认本地卷，请手动恢复"

N="sshweb-restore-$(date +%Y%m%d%H%M%S)-$RANDOM"
step "3/6 解压到新数据卷 $N"
if docker volume inspect "$N" >/dev/null 2>&1; then N=""; die "数据卷已存在，请重试"; fi
docker volume create "$N" >/dev/null
docker run --rm -v "$N":/data -v "$(dirname "$B")":/backup:ro alpine \
  tar xzf "/backup/$(basename "$B")" -C /data

step "4/6 检查文件属主"
WRONG=$(docker run --rm -v "$N":/data:ro alpine \
  find /data -mindepth 1 \( ! -user "${APPUSER%:*}" -o ! -group "${APPUSER#*:}" \) -print)
[ -z "$WRONG" ] || die "以下文件属主不是应用用户 $APPUSER：$(tr '\n' ' ' <<<"$WRONG")"
echo "全部文件属主为 $APPUSER"

# db_report <卷名>：复制到临时目录后正常打开（会应用 WAL）；检查完整性、必需的表与列、关键记录；
# 任何查询出错都失败退出。成功时每张必需的表输出一行“表名=行数”
db_report() {
  docker run --rm -i -e REQUIRED_SCHEMA="$REQUIRED_SCHEMA" -v "$1":/data:ro alpine sh -eu <<'EOF'
apk add --no-cache sqlite >/dev/null
mkdir -p /work
cp -a /data/. /work/
cd /work
q() { sqlite3 -bail -batch sshweb.db "$1"; }
r=$(q 'PRAGMA integrity_check;' 2>&1) || { echo "无法打开数据库：$r"; exit 1; }
[ "$r" = ok ] || { echo "integrity_check 失败：$r"; exit 1; }
[ -n "${REQUIRED_SCHEMA:-}" ] || { echo "没有收到必需表清单"; exit 1; }
for spec in $REQUIRED_SCHEMA; do
  t=${spec%%:*}; cols=${spec#*:}
  n=$(q "SELECT count(*) FROM (SELECT $cols FROM \"$t\");" 2>&1) \
    || { echo "必需的表 $t 缺失或缺少列（需要 $cols）：$n"; exit 1; }
  case "$n" in ''|*[!0-9]*) echo "表 $t 的行数无法识别：$n"; exit 1 ;; esac
  echo "$t=$n"
done
pw=$(q "SELECT count(*) FROM meta WHERE k='admin_pw' AND v LIKE '\$argon2id\$%';" 2>&1) || { echo "查询 meta 失败：$pw"; exit 1; }
[ "$pw" = 1 ] || { echo "缺少管理密码哈希（meta.admin_pw）"; exit 1; }
ck=$(q "SELECT count(*) FROM meta WHERE k='probe_cookie_keys';" 2>&1) || { echo "查询 meta 失败：$ck"; exit 1; }
[ "$ck" = 1 ] || { echo "缺少探针 Cookie 签名密钥"; exit 1; }
legacy=$(q "SELECT count(*) FROM meta WHERE k='password';" 2>&1) || { echo "查询 meta 失败：$legacy"; exit 1; }
[ "$legacy" = 0 ] || { echo "存在旧版明文管理密码"; exit 1; }
EOF
}

step "5/6 在副本上完整读取数据库（含 WAL）"
NEW_REPORT=$(db_report "$N") || die "恢复卷检查失败：$(grep -Ev '^[a-z0-9_]+=[0-9]+$' <<<"$NEW_REPORT")"
for spec in $REQUIRED_SCHEMA; do
  t=${spec%%:*}
  grep -Eq "^$t=[0-9]+\$" <<<"$NEW_REPORT" || die "恢复卷检查结果里没有表 $t 的行数，停止"
done
servers=$(sed -n 's/^servers=//p' <<<"$NEW_REPORT")
if [ "${SSH_ON:-0}" != 1 ] && [ "$servers" != 0 ]; then
  die "恢复卷里有 $servers 条服务器记录，探针模式会拒绝启动"
fi
echo "完整性 ok；必需的表与列齐全；管理密码哈希与签名密钥存在"
CUR_NOTE="当前卷正在使用，行数仅供参考"
CUR_REPORT=$(db_report "$CUR" 2>&1) || { CUR_NOTE="当前卷读取失败（$(tail -n 1 <<<"$CUR_REPORT")），仅列出恢复卷"; CUR_REPORT=""; }
printf '%-14s %-10s %s\n' 表 恢复卷 当前卷
for spec in $REQUIRED_SCHEMA; do
  t=${spec%%:*}
  printf '%-14s %-10s %s\n' "$t" "$(sed -n "s/^$t=//p" <<<"$NEW_REPORT")" "$(sed -n "s/^$t=//p" <<<"$CUR_REPORT")"
done
echo "（$CUR_NOTE）"

if [ "$MODE" = --check-only ]; then
  echo; echo "✅ 检查通过（--check-only，未切换）。新卷 $N 未被使用，如不需要可执行：docker volume rm $N"
  exit 0
fi

step "6/6 切换到新卷"
if [ "$MODE" != --yes ]; then
  read -r -p "确认把服务切换到 $N？原卷 $CUR 会保留。输入 yes 继续：" ans
  if [ "$ans" != yes ]; then echo "已取消。新卷 $N 保留未使用，可用 docker volume rm $N 删除。"; exit 0; fi
fi

# 先在临时文件里生成新 override：已有文件只改目标卷这一项（mikefarah/yq，保留注释与其他内容）
NEWOVR="$OVR.new-$$"
if [ -e "$OVR" ]; then
  [ -f "$OVR" ] && [ ! -L "$OVR" ] || die "$OVR 不是普通文件，拒绝修改"
  BAK="$OVR.bak-$(date +%Y%m%d%H%M%S)"
  cp -p "$OVR" "$BAK"
  cp -p "$OVR" "$NEWOVR"      # 沿用原文件的属主与权限
  docker run --rm -i -e K="$VOLKEY" -e V="$N" alpine sh -euc '
    { apk add --no-cache yq-go || apk add --no-cache yq; } >/dev/null 2>&1
    yq --version 2>&1 | grep -q mikefarah || { echo "需要 mikefarah/yq" >&2; exit 1; }
    exec yq eval ".volumes[strenv(K)] = {\"external\": true, \"name\": strenv(V)}" -' \
    <"$OVR" >"$NEWOVR" || die "无法改写 $OVR，未做任何改动"
else
  printf '# restore-backup.sh 生成：服务改用恢复卷\nvolumes:\n  %s:\n    external: true\n    name: %s\n' "$VOLKEY" "$N" >"$NEWOVR"
  chmod 644 "$NEWOVR"
fi

PHASE=edit
mv -f "$NEWOVR" "$OVR"
NEWOVR=""
AFTER=$(docker compose config --format json) || die "改动后 docker compose config 失败，$OVR 无法安全合并"
# 去掉目标卷后，改动前后的完整配置必须一致；只报告有差异的路径，不打印取值
VERDICT=$(printf '%s\n%s\n' "$BEFORE" "$AFTER" | jqc -rs --arg k "$VOLKEY" --arg n "$N" '
  def strip: del(.volumes[$k]);
  .[0] as $b | .[1] as $a | ($a.volumes[$k] // {}) as $v
  | if ($v.name // "") != $n or ($v.external // false) != true then "target"
    elif ($b | strip) == ($a | strip) then "ok"
    else ($b | strip) as $x | ($a | strip) as $y
      | ([$x, $y] | map([paths(scalars)]) | add | unique
         | map(. as $p | select((try ($x | getpath($p)) catch "\u0000") != (try ($y | getpath($p)) catch "\u0000")))
         | map(map(tostring) | join(".")) | .[:8]) as $d
      | "other:" + (if ($d | length) > 0 then ($d | join(", ")) else "结构不同" end)
    end') || die "比对改动前后的配置失败"
case "$VERDICT" in
  ok) ;;
  target) die "改动后 Compose 没有让 $VOLKEY 指向 $N（是否设置了 COMPOSE_FILE，或存在 compose.yaml / compose.override.yaml？）" ;;
  *) die "改动 $OVR 后，除数据卷外还有配置发生变化（${VERDICT#other:}），拒绝切换" ;;
esac
echo "$OVR 只改动了 $VOLKEY 卷，其他配置不变（原文件备份：${BAK:-原本没有该文件}）"

PHASE=switch
docker compose up -d --force-recreate sshweb
sleep 5
STATE=$(docker inspect sshweb --format '{{.State.Status}} {{.RestartCount}}')
MNT=$(mount_of sshweb)
if [ "$STATE" != "running 0" ] || [ "$MNT" != "$N" ]; then
  docker compose logs --tail 20 sshweb >&2 || true
  die "切换后容器状态为 ${STATE:-未知}，挂载的卷为 ${MNT:-未知}"
fi
PHASE=done
echo
echo "✅ 已切换到 $N，容器运行正常。请登录管理站核对探针与数据。"
echo "   原卷 $CUR 已保留；确认无误前不要删除。"
if [ -n "$BAK" ]; then
  echo "   退回：cp -p $BAK $OVR，然后执行 docker compose up -d --force-recreate sshweb"
else
  echo "   退回：删除 $OVR，然后执行 docker compose up -d --force-recreate sshweb"
fi
