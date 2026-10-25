# qcfg 设计

## 1. 定位

qcfg 是自托管的个人配置同步工具：一个服务端保存配置文件的权威版本与历史，多台设备通过 CLI 拉取、推送。用户以「项目」为单位组织文件，每台设备按需订阅项目。

- 多用户：项目共享，由管理员创建用户并分配项目权限，每台设备持有独立 token
- 服务端可读文件内容：WebUI 可直接查看、编辑、对比；落盘使用服务端密钥加密
- 冲突检测：基于基线版本的三方比较，冲突时停止并提示用户
- 跨平台：统一路径写法，可按 OS 覆盖或限定平台

## 2. 架构

单个二进制 `qcfg`，同时包含客户端与服务端：

```
qcfg serve          # 服务端：REST API + 内嵌 WebUI
qcfg <其它命令>      # 客户端
```

```
┌──────── 设备 A/B/C ────────┐         ┌──────────── qcfg serve ────────────┐
│ qcfg CLI                   │  HTTPS  │ /api/v1  (Bearer token)            │
│ ~/.config/qcfg/config.toml │ ──────▶ │ /        WebUI (session cookie)    │
│ ~/.local/state/qcfg/       │         │ SQLite 元数据 + 加密 blob           │
└────────────────────────────┘         └────────────────────────────────────┘
```

技术选型：

| 组件 | 选择 | 理由 |
|---|---|---|
| CLI | `spf13/cobra` | 子命令与补全 |
| HTTP | 标准库 `net/http`（1.22+ 路由） | 无额外框架 |
| 存储 | SQLite，`modernc.org/sqlite` | 纯 Go，便于交叉编译 |
| WebUI | `html/template` + htmx，`go:embed` | 无前端构建链，单文件部署 |
| 加密 | AES-256-GCM | 标准库实现 |

## 3. 数据模型

### 3.1 服务端

```
user      (id, name UNIQUE, password_hash, admin, all_projects, created_at)

user_project (user_id, project_id)                   -- 用户可访问的项目

project   (id, name UNIQUE, description, created_at, updated_at)

file      (id, project_id, name, path, paths_json, platforms_json,
           mode, head_rev, deleted, created_at, updated_at)
           UNIQUE(project_id, name)

version   (id, file_id, rev, sha256, size, blob_id,
           device, message, created_at)
           UNIQUE(file_id, rev)

blob      (id, sha256 UNIQUE, nonce, ciphertext)     -- 内容寻址，去重

device    (id, name UNIQUE, token_hash, created_at, last_seen_at, last_ip, revoked,
           all_projects, kind, user_id)              -- kind: device | pat

device_project (device_id, project_id)               -- 设备/token 可访问的项目

device_request (id, code_hash UNIQUE, user_code UNIQUE, name, ip, status,
                all_projects, projects_json, user_id, created_at, expires_at)
                                                     -- 待审批的登录请求

setting   (key, value)                               -- 服务设置
```

- `rev`：每个文件独立递增的整数，从 1 开始
- `sha256`：明文哈希，用于客户端比对；`blob` 按明文哈希去重，内容以 AES-GCM 加密存储
- 文件权限只记录在文件定义的 `mode` 中
- `version.device` 记录设备或 token 名，WebUI 修改记为 `web`
- 访问范围：`all_projects=1` 表示全部项目（含之后新建的），否则仅限 `device_project` 中的项目；设备与 PAT 共用同一命名空间与授权模型，`kind` 区分两者
- 用户权限：管理员可访问全部项目并管理用户；普通用户仅能管理获授权项目中的文件。设备和 PAT 归属于创建或批准它的用户，有效权限为自身授权与所属用户当前权限的交集；普通用户只管理自己的设备和 PAT，管理员可管理全部设备和 PAT
- 首位注册用户为管理员，注册成功后关闭公开注册；旧版本的管理员密码迁移至用户名 `admin`，已有设备、PAT 和审批请求归属于该账号
- 删除文件为软删除，历史保留；同名重新添加时恢复并沿用历史

### 3.2 文件定义

`name` 为项目内唯一标识，默认取路径的 basename。路径规则：

```jsonc
{
  "name": "config.json",
  "path": "~/.proj-a/config.json",          // 默认路径
  "paths": {                                // 可选，按 OS 覆盖
    "windows": "%APPDATA%/proj-a/config.json",
    "darwin":  "~/Library/Application Support/proj-a/config.json"
  },
  "platforms": ["linux", "darwin"],          // 可选，限定同步平台；为空表示全部
  "mode": "0600"
}
```

- 支持变量：`~`、`$HOME`、`$XDG_CONFIG_HOME`、`%APPDATA%`、`%USERPROFILE%`；`/` 在 Windows 下自动转换
- 解析顺序：`paths[GOOS]` → `path`；当前 OS 不在 `platforms` 内时跳过该文件
- `mode` 在类 Unix 系统写入时应用，Windows 忽略

### 3.3 客户端

`~/.config/qcfg/config.toml`（权限 0600）：

```toml
server = "https://cfg.example.com"
token  = "qcfg_xxxxxxxx"
device = "laptop"

[projects]                 # 本机订阅的项目
proj-a = {}
ssh    = { exclude = ["id_rsa"] }   # 可选：本机排除部分文件
```

`~/.local/state/qcfg/state.json`：记录每个已同步文件的基线

```json
{ "proj-a/config.json": { "rev": 7, "sha256": "…", "path": "/home/u/.proj-a/config.json" } }
```

`~/.local/state/qcfg/backup/`：覆盖本地文件前的备份，保留最近 N 份。

Windows 下对应 `%APPDATA%\qcfg\` 与 `%LOCALAPPDATA%\qcfg\`。

## 4. 同步算法

对每个文件计算三个哈希：本地 L、基线 B（state 中记录）、远端 R（服务端 head）。

| 条件 | 判定 | 动作 |
|---|---|---|
| L = R | 已一致 | 更新基线 |
| L = B，R ≠ B | 远端更新 | 拉取 |
| L ≠ B，R = B | 本地修改 | 推送 |
| L ≠ B，R ≠ B，L ≠ R | 冲突 | 跳过并报告 |
| 本地不存在 | 新设备或本地缺失 | 拉取 |
| 无基线，本地与远端均存在且不同 | 首次同步冲突 | 跳过并报告 |

推送时携带基线版本 `If-Match: <rev>`，服务端发现 head 已变化返回 `409`，客户端按冲突处理，保证并发推送不会互相覆盖。

冲突解决：

```
qcfg sync --ours   proj-a/config.json   # 以本地为准推送
qcfg sync --theirs proj-a/config.json   # 以远端为准覆盖本地
qcfg diff proj-a/config.json            # 查看差异后手动编辑，再 --ours
```

本地写入流程：备份旧文件 → 写入同目录临时文件 → 设置权限 → `rename` 原子替换 → 更新 state。

## 5. CLI

```
qcfg auth login [--server URL] [--name NAME] [--token TOKEN]
qcfg auth logout
qcfg auth status

qcfg ls                          # 列出服务端所有项目，标注本机是否订阅
qcfg ls <project>                # 列出项目文件及本机解析路径
qcfg status [project...]         # 显示每个文件的同步状态（不发生写入）

qcfg sync [project...]           # 双向同步已订阅项目；有冲突时退出码非 0
qcfg pull <project> [file...] [--force]   # 拉取；首次拉取即订阅
qcfg push <project> [file...] [--force] [-m MSG]
qcfg diff <project>[/file]

qcfg add <project> <path> [--name N] [--os windows=PATH ...] [--platforms linux,darwin]
qcfg rm  <project>/<file>        # 服务端软删除，本地文件保留
qcfg unsubscribe <project>       # 本机取消订阅，本地文件保留

qcfg log <project>/<file>
qcfg restore <project>/<file> --rev N   # 将历史版本设为新 head

qcfg serve [--listen :8080] [--data ./data]
qcfg serve passwd                # 设置 WebUI 管理员密码
```

- 管理员设备执行 `add` 时自动创建不存在的项目；普通用户需先由管理员创建并授权项目
- `--force`：跳过冲突检查，强制覆盖
- 全局参数：`--dry-run`、`--json`（机器可读输出）

`auth login` 流程（device code）：

1. 客户端调用 `POST /device/code` 提交设备名（默认 hostname），获得私密的 device code 与 8 位用户码（`XXXX-XXXX`）
2. 终端提示打开 `<server>/activate` 并输入用户码
3. 用户登录后在该页面输入用户码，确认设备名（可修改）与可访问项目后批准或拒绝；设备归属于批准者，授权范围受其项目权限限制
4. 客户端按 `interval` 轮询 `POST /device/token`，批准后获得 token 写入配置；请求 10 分钟后过期

`auth login --token` 跳过上述流程：调用 `GET /whoami` 验证 WebUI 中创建的 PAT（或设备 token），通过后直接写入配置。

## 6. API

所有接口前缀 `/api/v1`，除 `/device/*` 外鉴权头 `Authorization: Bearer`，接受设备 token 与 PAT，JSON 编码；文件内容以 base64 放在 JSON 中，或通过 `/raw` 以二进制传输。

设备只能访问自身与所属用户均获授权的项目，其余项目在列表中不出现、单独访问返回 `404`。项目的新建、修改与删除仅限管理员账号的设备或 PAT，普通用户调用这些接口返回 `403`；管理员设备/token 新建的项目自动加入其可访问范围。PAT 无管理 REST 接口，创建与授权仅通过 WebUI。

```
POST   /device/code                           {name} → {device_code, user_code, expires_in, interval}
POST   /device/token                          {device_code} → {token, device}
                                              400 authorization_pending / access_denied / expired_token

GET    /whoami

GET    /projects
POST   /projects                              {name, description}
GET    /projects/{p}                          项目信息 + 文件清单（含 head rev/sha256）
PATCH  /projects/{p}
DELETE /projects/{p}

POST   /projects/{p}/files                    {name, path, paths, platforms, mode}
PATCH  /projects/{p}/files/{f}                修改路径定义
DELETE /projects/{p}/files/{f}

GET    /projects/{p}/files/{f}/raw[?rev=N]    内容；响应头 X-Qcfg-Rev、X-Qcfg-Sha256
PUT    /projects/{p}/files/{f}/raw            上传新版本；请求头 If-Match: <base rev>，0 表示首次
                                              201 新版本 / 409 冲突 / 200 内容未变
GET    /projects/{p}/files/{f}/versions
POST   /projects/{p}/files/{f}/restore        {rev}
```

`sync` 每个项目只需一次 `GET /projects/{p}` 获取清单，之后仅对需拉取或推送的文件发起请求。

## 7. 服务端

### 7.1 数据目录

```
data/
  qcfg.db        # SQLite（WAL 模式）
  master.key     # 32 字节随机密钥，首次启动生成，权限 0600
```

`master.key` 可由环境变量 `QCFG_MASTER_KEY` 替代。备份时需同时备份 db 与密钥。

### 7.2 安全

- token：`qcfg_` + 32 字节随机数（base62），服务端只存 SHA-256；可在 WebUI 吊销
- PAT：`qcfg_pat_` + 32 字节随机数，同样只存 SHA-256，不过期，WebUI 中创建（明文仅显示一次）、按项目授权、吊销或删除
- device code：32 字节随机数，服务端只存 SHA-256；用户码取自 20 个辅音字母，需用户登录后输入；每个 IP 同时待审批的请求数上限 3
- WebUI：用户名与密码登录，密码使用 argon2id 哈希；首位用户通过注册创建管理员，后续用户由管理员创建。已有管理员账号的密码可由环境变量 `QCFG_ADMIN_PASSWORD` 在启动时覆盖，或用 `qcfg serve passwd` 修改。HttpOnly + SameSite=Strict 会话 cookie（会话保存在内存，重启后需重新登录），表单 CSRF token，同一 IP 15 分钟内失败 5 次即限速；每次请求读取当前用户权限
- 传输：内置 `--tls-cert/--tls-key`，或置于反向代理之后
- 限制：单文件大小上限（默认 4 MiB），每文件保留版本数上限（默认 50，0 为不限）

## 8. WebUI

| 页面 | 功能 |
|---|---|
| 注册 / 登录 | 首位用户注册管理员，此后以用户名与密码登录 |
| 用户 | 管理员创建用户、查看用户列表、分配和调整项目权限；修改自己的用户名 |
| 项目列表 | 获授权项目的项目名、文件数、最近更新时间；管理员新建/删除 |
| 项目详情 | 文件表格：名称、路径（含 OS 覆盖）、head rev、更新设备与时间；新增/编辑路径定义 |
| 文件 | 文本文件在线查看与编辑（保存即新版本）；二进制文件上传/下载 |
| 历史 | 版本列表、任意两版本 diff、恢复 |
| 激活 | 输入用户码，确认设备名与可访问项目，批准或拒绝 |
| 设备 | 设备列表、可访问项目、最近在线时间与 IP、吊销；单个设备页修改可访问项目 |
| Tokens | PAT 创建（明文仅显示一次）、列表、按项目授权、吊销/删除；单个 token 页修改可访问项目 |

## 9. 代码结构

```
cmd/qcfg/main.go
internal/
  cli/        # cobra 命令
  client/     # API 客户端
  syncer/     # 三方比较、冲突判定、原子写入、备份
  pathx/      # 路径变量展开与 OS 解析
  state/      # 本地配置与 state 读写
  server/     # HTTP 路由、鉴权中间件、API handler
  web/        # WebUI handler、templates/、static/（go:embed）
  store/      # SQLite 访问与迁移
  crypto/     # blob 加解密、token 生成与哈希
  model/      # 共享类型（API DTO）
```

## 10. 里程碑

1. 存储与 API：store、crypto、server 的项目/文件/版本接口，token 鉴权
2. CLI 核心：auth、ls、add、push、pull、status
3. 同步：syncer 三方比较、sync、diff、冲突解决、原子写入与备份
4. WebUI：登录、项目、文件编辑、历史与 diff、设备管理
5. 发布：多平台构建（linux/darwin/windows × amd64/arm64）、Dockerfile
