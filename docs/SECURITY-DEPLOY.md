# 探针版安全部署指南（fork v0.6.0）

本文对应安全加固方案的阶段 1、2：**不保存任何 SSH 凭据的探针版**。网页 SSH（阶段 3）尚未实施，默认关闭，不建议在公网实例上开启。

## 1. 架构

```
访客浏览器 ──https──> 宿主机 Caddy/Nginx ──> 127.0.0.1:45678 ──> 容器 公开口
你的设备  ──tailnet https──> tailscale serve ──> 127.0.0.1:45679 ──> 容器 管理口
被监控机 agent ──https──> 公开站 /api/probe/enroll、/api/probe/report
```

- **公开口**：农场展示、探针上报/解锁、安装脚本、Skill 接口。没有任何管理路由，管理 Cookie 在这里不生效。
- **管理口**：登录、探针管理、API Key、清图。只映射到宿主机回环地址，经 Tailscale Serve 以 HTTPS 发布到 tailnet。
- 管理站必须使用与公开站**不同的主机名**（推荐直接用 tailnet 的 `*.ts.net` 地址）：Cookie 不按端口隔离，同主机名下管理员浏览公开农场时会把管理 Cookie 发给公开口。

## 2. 首次部署

### 2.1 准备

- 一台 VPS，已安装 Docker / Docker Compose、Caddy（或 Nginx）、Tailscale。
- 公开站域名（如 `farm.example.com`）解析到 VPS。
- Tailscale 管理后台启用 HTTPS 证书（MagicDNS + HTTPS），**不要开启 Funnel**。

### 2.2 访问规则（Tailscale）

在 tailnet 策略里给 VPS 打标签，只允许你的账户访问它的 443。示例（按你的实际账户修改，并删除默认的“全部放行”规则）：

```json
{
  "tagOwners": { "tag:farm": ["autogroup:admin"] },
  "acls": [
    { "action": "accept", "src": ["you@example.com"], "dst": ["tag:farm:443"] }
  ]
}
```

### 2.3 配置 Compose

编辑仓库里的 `docker-compose.yml`：

| 变量 | 填写 |
|---|---|
| `SSHWEB_PUBLIC_URL` | `https://farm.example.com` |
| `SSHWEB_ADMIN_ORIGIN` | `https://<机器名>.<tailnet>.ts.net`（`tailscale serve status` 可查） |
| `SSHWEB_TRUSTED_PROXIES` | 容器网络网关，默认示例为 `172.30.10.1` |

要点：

- 使用**全新的具名卷** `sshweb-probe-data`，不要挂载任何旧版数据卷。数据目录出现 `data.json`、`data.json.migrated`、服务器记录或旧版明文密码时，程序会拒绝启动。
- 端口映射必须写 `127.0.0.1:`。Docker 发布的端口会绕过 ufw，不写宿主机地址就等于对公网开放。
- 容器内必须监听 `0.0.0.0`（已写在 `command` 里），访问范围由宿主机侧映射控制。

### 2.4 首次启动

用 `read -s` 输入密码，避免进入 shell 历史；`sudo` 默认丢弃环境变量，需 `--preserve-env`：

```bash
read -rs -p '管理密码（至少 12 位）: ' SSHWEB_PASSWORD; echo
export SSHWEB_PASSWORD
sudo --preserve-env=SSHWEB_PASSWORD docker compose up -d --build
unset SSHWEB_PASSWORD
sudo docker compose logs sshweb | tail
```

看到“管理密码已设置”后，**重建一次容器，让新容器不再携带初始密码**。数据库只保存 Argon2id 哈希，
但创建容器时密码已写进容器配置（`docker inspect` 可见）；宿主机 `unset` 或 `restart` 都不会清除它：

```bash
sudo docker compose up -d --force-recreate sshweb
sudo docker inspect sshweb --format '{{range .Config.Env}}{{println .}}{{end}}' | grep '^SSHWEB_PASSWORD='
# 应输出 SSHWEB_PASSWORD=（等号后为空）
```

不要把密码写进 `.env` 或 Compose 文件；之后在管理面板里修改密码。

### 2.5 公开站反代（Caddy）

```caddy
farm.example.com {
	encode zstd gzip
	header Strict-Transport-Security "max-age=31536000"
	reverse_proxy 127.0.0.1:45678 {
		# 用真实来源覆盖转发头，不透传客户端自带的值
		header_up X-Forwarded-For {remote_host}
		header_up X-Real-IP {remote_host}
	}
}
```

Nginx 写法见 README 的反代示例（`proxy_set_header X-Forwarded-For $remote_addr;`，覆盖而不是追加）。

> 如果公开站前面还有 CDN，需要先在 Caddy 层配置 CDN 的可信地址段并取 CDN 提供的客户端 IP 头，否则所有访客会被识别为 CDN 节点地址。

### 2.6 管理站（Tailscale Serve）

```bash
sudo tailscale serve --bg --https=443 http://127.0.0.1:45679
tailscale serve status   # 确认地址与 SSHWEB_ADMIN_ORIGIN 一致
```

在已加入 tailnet 的设备上打开 `https://<机器名>.<tailnet>.ts.net` 登录管理。

登录失败锁定按来源地址计数。Tailscale Serve 是否附带 `X-Forwarded-For` 取决于其版本：附带时按 tailnet 设备地址分别计数，
不附带时管理站所有请求共用一个来源、锁定整体生效。以实际部署为准。
如果自己输错密码被锁，等待锁定结束（首次 15 分钟），或重启容器清空内存中的计数。

### 2.7 确认可信代理地址

```bash
ip -4 -o addr | grep 172.30.10   # 应看到某个 br-… 网卡上的 172.30.10.1/24
```

该地址应与 `SSHWEB_TRUSTED_PROXIES` 一致。部署后在管理站查看一只探针的 IP：显示被监控机的真实公网地址即为正确；显示 `172.30.10.1` 说明反代没有传递 `X-Forwarded-For` 或可信地址填错。

## 3. 部署探针

1. 管理站 →「☰ 管理」→「📡 部署探针」，选择公开或密码查看（查看密码至少 8 位）。默认建议密码查看；备注名不要写真实主机名、IP 或业务名称。
2. 复制安装命令，在被监控机执行（30 分钟内有效，只能用一次）：

   ```bash
   curl -fsSL 'https://farm.example.com/probe/agent.sh' | sudo bash -s -- swe_xxxxxxxx
   ```

3. 要求：systemd、curl 7.55 及以上。systemd ≥ 247 时 agent 以 `DynamicUser` 运行并通过 `LoadCredential` 读取 token；更低版本退回到专用用户 `sshweb-probe`。
4. token 只在被监控机 `/etc/sshweb-probe/auth-header`（root 0600）中，面板只存哈希。怀疑泄露时，在管理面板对该探针点 🔑 轮换，并在被监控机重新执行新的安装命令。
5. 卸载：`curl -fsSL 'https://farm.example.com/probe/uninstall.sh' | sudo bash`
6. 查看密码泄露时，在管理面板对该探针点 🔒 修改查看密码：旧密码立即不能再解锁，已发出的解锁 Cookie 全部失效，agent 不受影响。
   只想让已解锁的访客重新输入密码（密码没有泄露）时，用 🔁 撤销即可；🔁 不会改变密码，知道密码的人仍能重新解锁。
   对公开探针点 🔒，会改为密码查看。

隐私边界：

- 未解锁的密码探针仍公开备注名和在线状态。
- IP 掩码只遮 IP；获准查看（公开探针或已解锁）的人仍能看到主机名、系统版本、CPU 型号、资源用量等。

旧版 `?t=` agent 默认不被接受。新部署直接使用新版 agent 即可；如需兼容，设置 `SSHWEB_LEGACY_AGENT_UNTIL=YYYY-MM-DD`（建议为新版发布后 60 天内的具体日期）。

## 4. 验收

脚本需要 `curl` 和 `jq`，按对象检查 JSON 字段；请求失败、响应无法解析、缺少工具都记为失败，
条件不具备的项记为“跳过”（跳过不等于通过）。建议在 Linux 或 WSL 上运行。

在**公网上另一台机器**执行：

```bash
scripts/verify-deploy.sh https://farm.example.com <VPS公网IP>
```

在**已加入 tailnet 的设备**上再执行一次，附带管理站地址：

```bash
scripts/verify-deploy.sh https://farm.example.com <VPS公网IP> https://<机器名>.<tailnet>.ts.net
```

在 **VPS 本机**确认端口只绑定回环地址：

```bash
ss -ltnp | grep -E ':4567[89]'   # 只应出现 127.0.0.1:45678 / 127.0.0.1:45679
```

## 5. 默认关闭 / 已移除的功能

| 功能 | 状态 | 原因 |
|---|---|---|
| 网页 SSH 终端 | 默认关闭（`SSHWEB_ENABLE_SSH=0`） | 凭据加密、主机密钥校验、进程拆分属于阶段 3，尚未实施 |
| 任何人在公开站创建探针 | 改为仅管理员 | 公开注册会被滥用 |
| 默认密码 `admin888` | 移除 | 首次启动必须设置 |
| 国旗识别（ip-api.com） | 默认关闭（`SSHWEB_GEOIP=1` 开启） | 明文 HTTP，且会把访客/探针 IP 发给第三方 |
| 旧版 `?t=` agent | 默认关闭 | token 出现在 URL 和全局可读的脚本里 |
| 导入旧版 `data.json` | 移除 | 可能重新导入明文凭据 |

## 6. 备份与恢复

Compose 会给卷名加项目前缀（默认 `sshweb_sshweb-probe-data`）。下面的命令从运行中的容器读出实际卷名，避免写错：

```bash
V=$(sudo docker inspect sshweb --format '{{range .Mounts}}{{if eq .Destination "/data"}}{{.Name}}{{end}}{{end}}'); echo "$V"
```

备份（停机几秒，保证 SQLite 文件一致），并校验压缩包：

```bash
B=/root/backup/sshweb-$(date +%F).tgz
sudo mkdir -p /root/backup
sudo docker compose stop
sudo docker run --rm -v "$V":/data:ro -v /root/backup:/backup alpine tar czf "/backup/$(basename "$B")" -C /data .
sudo docker compose start
sudo gzip -t "$B" && sudo tar tzf "$B" | grep -qx './sshweb.db' && echo "备份可用：$B"
```

恢复时**不要覆盖现有数据卷**：解压到新卷、检查后切换，原卷保留到恢复验收完成。

```bash
B=/root/backup/sshweb-2026-11-10.tgz          # 换成要恢复的文件
N=sshweb-restore-$(date +%Y%m%d%H%M)
sudo gzip -t "$B" && sudo tar tzf "$B" | grep -qx './sshweb.db' || { echo "备份不可用，停止"; false; }
sudo docker volume create "$N"
sudo docker run --rm -v "$N":/data -v "$(dirname "$B")":/backup:ro alpine tar xzf "/backup/$(basename "$B")" -C /data
sudo docker run --rm -v "$N":/data:ro alpine sh -c \
  'apk add --no-cache sqlite >/dev/null && sqlite3 "file:/data/sshweb.db?immutable=1" "PRAGMA integrity_check;" && ls -ln /data'
# integrity_check 应输出 ok；文件属主应与原卷一致（可对比 docker run --rm -v "$V":/data:ro alpine ls -ln /data）
```

确认无误后，用 `docker-compose.override.yml` 让服务改用新卷（Compose 会自动合并该文件）：

```bash
printf 'volumes:\n  sshweb-probe-data:\n    external: true\n    name: %s\n' "$N" | sudo tee docker-compose.override.yml
sudo docker compose up -d --force-recreate sshweb
```

验收通过前保留原卷；要退回，删除 `docker-compose.override.yml` 后再执行一次 `up -d --force-recreate`。

探针版的库中没有 SSH 凭据，但包含管理密码哈希、探针 Cookie 签名密钥和各类 token 哈希，备份仍应妥善保管。

## 7. 关于开启网页 SSH

阶段 3（进程拆分、凭据加密、主机密钥校验、迁移状态机）完成前，**不要在公网实例上设置 `SSHWEB_ENABLE_SSH=1`**。当前代码中的相关加固只有：编辑服务器时改连接目标必须重填凭据、切换认证方式清理旧凭据、终端随会话撤销/过期关闭、`/test` 只接受 POST。
