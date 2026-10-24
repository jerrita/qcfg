# qcfg

自托管的个人配置同步工具。服务端保存配置文件的权威版本与历史，多台设备通过 CLI 拉取、推送；以「项目」为单位组织文件，每台设备按需订阅。

- 单个二进制，同时包含服务端（REST API + WebUI）与客户端
- 基于基线版本的三方比较，冲突时停止并提示，不会静默覆盖
- 跨平台路径：`~`、`$XDG_CONFIG_HOME`、`%APPDATA%` 等变量，可按 OS 覆盖路径或限定平台
- WebUI 在线查看、编辑、对比历史版本、恢复；管理设备与授权
- 设备通过 device code 登录，在 WebUI 审批并限定可访问的项目
- 内容以 AES-256-GCM 加密落盘

## 部署服务端

Docker：

```sh
docker run -d --name qcfg -p 8080:8080 -v qcfg-data:/data ghcr.io/jerrita/qcfg:latest
docker logs qcfg   # 首次启动打印随机生成的 WebUI 管理员密码
```

Docker Compose，`compose.yaml`：

```yaml
services:
  qcfg:
    image: ghcr.io/jerrita/qcfg:latest
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      QCFG_ADMIN_PASSWORD: ${QCFG_ADMIN_PASSWORD}   # WebUI 管理员密码，至少 8 位
    volumes:
      - qcfg-data:/data

volumes:
  qcfg-data:
```

```sh
echo 'QCFG_ADMIN_PASSWORD=change-me-please' > .env
docker compose up -d
```

或直接运行：

```sh
qcfg serve --listen :8080 --data ./data
```

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--listen` | `:8080` | 监听地址 |
| `--data` | `./data` | 数据目录（`qcfg.db` 与 `master.key`） |
| `--tls-cert` / `--tls-key` | | 启用 HTTPS；也可置于反向代理之后 |
| `--max-file-size` | `4194304` | 单文件大小上限（字节） |
| `--keep-versions` | `50` | 每个文件保留的版本数，`0` 为不限 |

- 管理员密码：设置环境变量 `QCFG_ADMIN_PASSWORD` 后每次启动以其为准；未设置时首次启动随机生成，可用 `qcfg serve passwd --data ./data` 修改（Docker 中为 `docker exec -it qcfg /qcfg serve passwd --data /data`）
- 加密密钥可由环境变量 `QCFG_MASTER_KEY`（64 位十六进制）提供；备份时需同时备份数据库与密钥

## 安装客户端

一键安装最新 release（Linux x64/arm64、macOS arm64），默认安装到 `~/.local/bin`，可用 `QCFG_INSTALL_DIR` 指定：

```sh
curl -fsSL https://raw.githubusercontent.com/jerrita/qcfg/master/scripts/install.sh | sh
```

Windows x64（PowerShell），默认安装到 `%LOCALAPPDATA%\Programs\qcfg` 并加入用户 PATH：

```powershell
irm https://raw.githubusercontent.com/jerrita/qcfg/master/scripts/install.ps1 | iex
```

也可从 [Releases](https://github.com/jerrita/qcfg/releases) 手动下载，或：

```sh
go install github.com/jerrita/qcfg/cmd/qcfg@latest
```

或克隆后 `make build`，产物位于 `bin/qcfg`；`make release` 构建多平台二进制。

## 使用

登录：终端显示用户码，在 WebUI 的 `/activate` 页面输入并批准，可修改设备名与可访问项目。

```sh
qcfg auth login --server https://cfg.example.com
```

在一台设备上添加文件（项目不存在时自动创建）：

```sh
qcfg add dotfiles ~/.gitconfig
qcfg add nvim ~/.config/nvim/init.lua --os windows='%LOCALAPPDATA%/nvim/init.lua'
qcfg add ssh ~/.ssh/config --platforms linux,darwin --mode 0600
```

在其他设备上订阅并同步：

```sh
qcfg ls                 # 列出项目及本机订阅情况
qcfg pull dotfiles      # 首次拉取即订阅
qcfg sync               # 双向同步所有已订阅项目
```

处理冲突：

```sh
qcfg status                        # 查看各文件状态，不写入
qcfg diff dotfiles/.gitconfig      # 远端与本地的差异
qcfg sync --ours   dotfiles/.gitconfig   # 以本地为准
qcfg sync --theirs dotfiles/.gitconfig   # 以远端为准
```

其他命令：

```sh
qcfg log dotfiles/.gitconfig               # 版本历史
qcfg restore dotfiles/.gitconfig --rev 3   # 将历史版本设为新版本
qcfg rm dotfiles/.gitconfig                # 服务端停止跟踪，本地文件保留
qcfg unsubscribe dotfiles                  # 本机取消订阅，本地文件保留
```

全局参数 `--dry-run` 预览变更，`--json` 输出机器可读结果。覆盖本地文件前会备份到 `~/.local/state/qcfg/backup/`（Windows 为 `%LOCALAPPDATA%\qcfg\backup\`）。

本机排除项目中的部分文件，编辑 `~/.config/qcfg/config.toml`：

```toml
[projects]
ssh = { exclude = ["id_rsa"] }
```

设计细节见 [docs/design.md](docs/design.md)。
