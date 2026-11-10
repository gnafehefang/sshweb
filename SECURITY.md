# SSHWeb 安全说明（fork）

- 部署方式与威胁模型见 [docs/SECURITY-DEPLOY.md](docs/SECURITY-DEPLOY.md)。
- 数据目录：`data/`（0700），SQLite 数据库 `sshweb.db`。
  - 管理密码、探针查看密码：Argon2id 哈希
  - 探针 token、注册码、API Key：SHA-256 哈希
  - 开启网页 SSH 时的 SSH 密码 / 私钥：**目前仍为明文**，请把数据目录与备份当作 SSH 私钥同等保护
- 本版本不导入旧版 `data.json` / `data.json.migrated`；数据目录出现这类文件会拒绝启动。
- 发现安全问题请私下联系仓库维护者，不要直接公开 issue。
