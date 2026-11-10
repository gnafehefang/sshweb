#!/usr/bin/env bash
# SSHWeb 备份恢复：解压到新数据卷 → 在副本上完整读取数据库（含 WAL）并检查 → 确认后切换。
#   用法：sudo scripts/restore-backup.sh <备份文件.tgz> [--yes]
#   - 任何一步失败立即退出；原数据卷始终不改动、不删除
#   - 切换通过 docker-compose.override.yml 完成；切换后容器没有正常运行会自动退回
#   - --check-only：只做检查，不切换
set -euo pipefail

cd "$(dirname "$0")/.."   # 仓库根目录（docker-compose.yml 所在）

B="${1:-}"
MODE="${2:-}"
die()  { echo "❌ $*" >&2; exit 1; }
step() { echo; echo "== $*"; }

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

step "2/6 读取当前服务信息"
IMG=$(docker inspect sshweb --format '{{.Config.Image}}') || die "找不到 sshweb 容器"
CUR=$(docker inspect sshweb --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}')
[ -n "$CUR" ] || die "读不到当前数据卷"
SSH_ON=$(docker inspect sshweb --format '{{range .Config.Env}}{{println .}}{{end}}' | sed -n 's/^SSHWEB_ENABLE_SSH=//p')
APPUSER=$(docker run --rm --entrypoint /bin/sh "$IMG" -c 'echo "$(id -u):$(id -g)"') || die "无法读取镜像 $IMG 的运行用户"
echo "镜像 $IMG，当前数据卷 $CUR，应用用户 $APPUSER，SSHWEB_ENABLE_SSH=${SSH_ON:-0}"

N="sshweb-restore-$(date +%Y%m%d%H%M%S)-$RANDOM"
step "3/6 解压到新数据卷 $N"
if docker volume inspect "$N" >/dev/null 2>&1; then die "数据卷 $N 已存在"; fi
docker volume create "$N" >/dev/null
cleanup_hint() { echo "（原卷 $CUR 未改动；新卷 $N 未被使用，可用 docker volume rm $N 删除）" >&2; }
trap 'rc=$?; [ $rc -eq 0 ] || cleanup_hint' EXIT
docker run --rm -v "$N":/data -v "$(dirname "$B")":/backup:ro alpine \
  tar xzf "/backup/$(basename "$B")" -C /data

step "4/6 检查文件属主"
WRONG=$(docker run --rm -v "$N":/data:ro alpine \
  find /data -mindepth 1 \( ! -user "${APPUSER%:*}" -o ! -group "${APPUSER#*:}" \) -print)
[ -z "$WRONG" ] || die "以下文件属主不是应用用户 $APPUSER：$(tr '\n' ' ' <<<"$WRONG")"
echo "全部文件属主为 $APPUSER"

# db_report <卷名>：复制到临时目录后正常打开（会应用 WAL），检查完整性与关键记录，输出统计
db_report() {
  docker run --rm -i -v "$1":/data:ro alpine sh -eu <<'EOF'
apk add --no-cache sqlite >/dev/null
mkdir -p /work
cp -a /data/. /work/
cd /work
r=$(sqlite3 sshweb.db 'PRAGMA integrity_check;')
[ "$r" = ok ] || { echo "integrity_check 失败：$r"; exit 1; }
pw=$(sqlite3 sshweb.db "SELECT count(*) FROM meta WHERE k='admin_pw' AND v LIKE '\$argon2id\$%';")
[ "$pw" = 1 ] || { echo "缺少管理密码哈希（meta.admin_pw）"; exit 1; }
ck=$(sqlite3 sshweb.db "SELECT count(*) FROM meta WHERE k='probe_cookie_keys';")
[ "$ck" = 1 ] || { echo "缺少探针 Cookie 签名密钥"; exit 1; }
legacy=$(sqlite3 sshweb.db "SELECT count(*) FROM meta WHERE k='password';")
[ "$legacy" = 0 ] || { echo "存在旧版明文管理密码"; exit 1; }
for t in probes players blocks servers apikeys_v2 enroll_codes; do
  n=$(sqlite3 sshweb.db "SELECT count(*) FROM $t;" 2>/dev/null || echo "无此表")
  echo "$t=$n"
done
EOF
}

step "5/6 在副本上完整读取数据库（含 WAL）"
NEW_REPORT=$(db_report "$N") || die "恢复卷检查失败：$NEW_REPORT"
CUR_REPORT=$(db_report "$CUR" 2>/dev/null) || CUR_REPORT="（当前卷读取失败）"
servers=$(sed -n 's/^servers=//p' <<<"$NEW_REPORT")
if [ "${SSH_ON:-0}" != 1 ] && [ "$servers" != 0 ]; then
  die "恢复卷里有 $servers 条服务器记录，探针模式会拒绝启动"
fi
echo "完整性 ok，管理密码哈希与签名密钥存在"
printf '%-14s %-12s %s\n' 表 恢复卷 当前卷
paste -d' ' <(sed 's/=/ /' <<<"$NEW_REPORT") <(sed 's/^[^=]*=//' <<<"$CUR_REPORT") |
  while read -r t a b; do printf '%-14s %-12s %s\n' "$t" "$a" "$b"; done

if [ "$MODE" = --check-only ]; then
  echo; echo "✅ 检查通过（--check-only，未切换）。新卷 $N 未被使用，如不需要可执行：docker volume rm $N"
  trap - EXIT
  exit 0
fi

step "6/6 切换到新卷"
if [ "$MODE" != --yes ]; then
  read -r -p "确认把服务切换到 $N？原卷 $CUR 会保留。输入 yes 继续：" ans
  if [ "$ans" != yes ]; then echo "已取消。新卷 $N 保留未使用。"; trap - EXIT; exit 0; fi
fi
OVR=docker-compose.override.yml
BAK=""
if [ -f "$OVR" ]; then BAK="$OVR.bak-$(date +%Y%m%d%H%M%S)"; cp "$OVR" "$BAK"; fi
printf 'volumes:\n  sshweb-probe-data:\n    external: true\n    name: %s\n' "$N" > "$OVR"

rollback() {
  echo "⚠️  切换后检查未通过，退回原配置" >&2
  if [ -n "$BAK" ]; then mv -f "$BAK" "$OVR"; else rm -f "$OVR"; fi
  docker compose up -d --force-recreate sshweb >&2 || true
  exit 1
}
docker compose up -d --force-recreate sshweb || rollback
sleep 5
STATE=$(docker inspect sshweb --format '{{.State.Status}} {{.RestartCount}}') || rollback
MNT=$(docker inspect sshweb --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}')
[ "$STATE" = "running 0" ] && [ "$MNT" = "$N" ] || { docker compose logs --tail 20 sshweb >&2 || true; rollback; }
trap - EXIT
echo
echo "✅ 已切换到 $N，容器运行正常。请登录管理站核对探针与数据。"
echo "   原卷 $CUR 已保留；确认无误前不要删除。退回：恢复或删除 $OVR 后执行 docker compose up -d --force-recreate sshweb"
