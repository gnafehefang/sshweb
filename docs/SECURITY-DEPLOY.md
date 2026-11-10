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

```bash
SSHWEB_PASSWORD='至少12位的强密码' docker compose up -d --build
docker compose logs sshweb | tail
```

看到“管理密码已设置”后，**从 compose 文件和 shell 历史中删除 `SSHWEB_PASSWORD`**，之后在管理面板里修改密码。再次启动时如仍提供该变量，日志会提示已忽略。

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

Tailscale Serve 不会附带 `X-Forwarded-For`，所以管理站上所有请求在程序看来来自同一地址：登录失败锁定对管理站是整体生效的。
如果自己输错密码被锁，等待锁定结束（首次 15 分钟），或重启容器清空内存中的计数。

### 2.7 确认可信代理地址

```bash
docker network inspect $(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}' sshweb) \
  -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}'
```

输出应与 `SSHWEB_TRUSTED_PROXIES` 一致。部署后在管理站查看一只探针的 IP：显示被监控机的真实公网地址即为正确；显示 `172.30.10.1` 说明反代没有传递 `X-Forwarded-For` 或可信地址填错。

## 3. 部署探针

1. 管理站 →「☰ 管理」→「📡 部署探针」，选择公开或密码查看（查看密码至少 8 位）。
2. 复制安装命令，在被监控机执行（30 分钟内有效，只能用一次）：

   ```bash
   curl -fsSL 'https://farm.example.com/probe/agent.sh' | sudo bash -s -- swe_xxxxxxxx
   ```

3. 要求：systemd、curl 7.55 及以上。systemd ≥ 247 时 agent 以 `DynamicUser` 运行并通过 `LoadCredential` 读取 token；更低版本退回到专用用户 `sshweb-probe`。
4. token 只在被监控机 `/etc/sshweb-probe/auth-header`（root 0600）中，面板只存哈希。怀疑泄露时，在管理面板对该探针点 🔑 轮换，并在被监控机重新执行新的安装命令。
5. 卸载：`curl -fsSL 'https://farm.example.com/probe/uninstall.sh' | sudo bash`

旧版 `?t=` agent 默认不被接受。新部署直接使用新版 agent 即可；如需兼容，设置 `SSHWEB_LEGACY_AGENT_UNTIL=YYYY-MM-DD`（建议为新版发布后 60 天内的具体日期）。

## 4. 验收

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

## 6. 备份

```bash
docker run --rm -v sshweb-probe-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/sshweb-probe-$(date +%F).tgz -C /data .
```

探针版的库中没有 SSH 凭据，但包含管理密码哈希、探针 Cookie 签名密钥和各类 token 哈希，备份仍应妥善保管。

## 7. 关于开启网页 SSH

阶段 3（进程拆分、凭据加密、主机密钥校验、迁移状态机）完成前，**不要在公网实例上设置 `SSHWEB_ENABLE_SSH=1`**。当前代码中的相关加固只有：编辑服务器时改连接目标必须重填凭据、切换认证方式清理旧凭据、终端随会话撤销/过期关闭、`/test` 只接受 POST。
