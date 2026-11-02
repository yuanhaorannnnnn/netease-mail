# NetEase Mail

让 Codex 通过本机 IMAP/SMTP 处理网易 `163.com`、`126.com`、`yeah.net` 个人邮箱：搜索、读信、附件、草稿、发信、回复、转发和已读/星标。采用 bundled Skill + 本地 stdio MCP，不适用于 Gmail 或企业邮箱。

**0.1.0 测试版。移动邮件暂不可用。** 实测网易账号不支持原生 MOVE，危险的移动降级已禁用；不提供删除或清空垃圾箱。现有单账号真实邮箱验证不能保证所有账号、系统或客户端兼容。

## 能力与限制

| 能力 | 范围 |
| --- | --- |
| 文件夹与搜索 | 单文件夹初始最近最多 1,000 封的 From/Subject 本地匹配，分页继续扫描 |
| 读信与附件 | 正文、完整头、MIME 信息、附件；读取使用 PEEK，不自动设为已读 |
| 关联邮件 | 单文件夹有限关联候选，可能不完整 |
| 草稿 | 新建、审阅、发送；修改生成新副本并保留旧稿，发送后原稿也保留 |
| 发信与回复 | 核对 To/Cc/Bcc、正文和附件后，按用户明确指令发送 |
| 转发 | 单部分纯文本内联转发；复杂邮件可明确选择整封原信 `.eml` 附件转发 |
| 标记 | 查询或设置/清除 Seen、Flagged |

搜索不覆盖正文、附件全文、全部历史邮件或其他文件夹。即使当前页零命中，也要沿用 `next_cursor` 扫描；`coverage.complete` 只表示初始窗口查完。线程候选、文件夹与标记不等同于 Gmail 完整会话和标签。

整封邮件读取最多 15 MiB，单附件最多 5 MiB，新建邮件附件总量最多 10 MiB；整封原信附件转发的原信最多 5 MiB。复杂草稿、签名邮件、内嵌邮件或 SMTPUTF8 等不受支持的发送场景会拒绝，不能绕过限制。

## 安装运行环境

需要 Python 3.10+、`venv`、`pip`、POSIX shell 和可用的系统安全密钥库。包装测试使用 Linux/Python 3.11.7；macOS 和其他 Python 版本尚未验证，Windows 暂不支持当前 launcher。安装依赖需要网络。

```sh
git clone https://github.com/yuanhaorannnnnn/netease-mail.git
cd netease-mail
sh scripts/install-runtime.sh
```

脚本将 `mcp==1.26.0`、`keyring==25.7.0` 安装到 `${XDG_DATA_HOME:-$HOME/.local/share}/netease-mail/venv`；传递依赖未全量锁定。运行环境与插件源码/cache 分离，插件被复制后无需携带开发 `.venv`。安装与 MCP 宿主必须使用同一用户和相同的 `XDG_DATA_HOME` 设置。pip 成功不代表系统密钥库可用。

### 连接 Codex CLI

从仓库根目录注册本地 MCP：

```sh
codex mcp add netease-mail -- sh "$PWD/scripts/run-server.sh"
```

同时将 [Skill](skills/netease-mail/SKILL.md) 安装到用户 Skill 目录。下面命令只适用于没有同名安装的情况；已有目录或链接先检查，不覆盖。

```sh
mkdir -p "$HOME/.agents/skills"
ln -s "$PWD/skills/netease-mail" "$HOME/.agents/skills/netease-mail"
```

重开会话，让 Skill 和工具加载。单独安装 Skill 不会注册 MCP。CLI 注册指向当前 clone，后续不要随意移动该目录；其他 MCP 客户端可配置等价的 `sh` 启动命令，尚未逐一验证。

### 作为插件包加载

根 `plugin.json` 和 `mcp.json` 采用 portable Agent Plugins 格式。MCP 入口为 `sh ${PLUGIN_ROOT}/scripts/run-server.sh`，由宿主展开包根目录。通过支持本地插件的 repo/personal marketplace 安装时，仍需先显式运行上述依赖安装脚本，再新开会话。

本仓库尚未完成实际 Codex marketplace/cache 安装验收，也未上架 OpenAI 公共插件目录。公开 GitHub 仓库、marketplace 安装和公共目录发布是三个不同步骤。参见 [官方插件包装文档](https://developers.openai.com/plugins/build/plugins)；local MCP 的公共目录提交资格见 [desktop-only 插件文档](https://developers.openai.com/plugins/deploy/desktop-only)。

## 配置账号

先在网易邮箱设置中开启客户端 IMAP/SMTP，取得专用客户端授权码。用户亲自在私密本机终端运行：

```sh
"${XDG_DATA_HOME:-$HOME/.local/share}/netease-mail/venv/bin/python" \
  skills/netease-mail/scripts/configure.py
```

脚本交互输入邮箱地址和客户端授权码，拒绝管道输入。不要把授权码发送给 agent、写入聊天、命令行参数、仓库或日志；不要使用网页登录密码。

- 邮箱地址保存在 `~/.config/netease-mail/account.json`，该文件不存授权码。
- 授权码通过 `keyring` 写入系统密钥库，服务名 `codex-netease-mail`；只接受已识别的系统密钥库 backend，拒绝 null、明文、chain 和未知类型。请仅启动一个配置进程；已有不同授权码不会自动覆盖。
- MCP 需运行在同一用户及能访问密钥库的会话中。无头或锁定会话可能不可用。
- `NETEASE_EMAIL` 可覆盖账号地址；对应授权码仍须存在于密钥库。账号切换后重新搜索邮件 ID。

配置成功仅说明本地保存成功。网络使用默认 TLS 验证，IMAP SSL 993、SMTP SSL 465，目标主机固定由支持的网易域名映射。

## 使用示例

新会话先调用 `get_server_info` 核对服务版本、启动时间及源码 hash，再只读验证文件夹、搜索和读信。

可以向 agent 提出：

- “列出我的网易邮箱文件夹。”
- “在收件箱最近 1,000 封的窗口里查找主题含发票的邮件，说明扫描范围。”
- “读取这封邮件及附件，先不要修改或回复。”
- “为这封邮件起草一封回复，先让我核对收件人和内容。”
- “把这封复杂邮件作为 `.eml` 原信附件转发，先展示预览和披露范围。”

发送、回复、转发必须有明确发送指令；查询、预览、安装和配置都不构成发送授权。写入标记或修改草稿也须有相应要求。SMTP 接受只表示服务器接受，不证明对方收到；结果未知时先核实，不能自动重发。草稿发送后仍保留，避免重复发送。

更新代码不会自动替换已有 MCP 进程。只重新加载自己使用的连接，不结束其他会话的服务；启动时磁盘 hash 也不是运行字节的严格证明。

## 隐私与安全边界

邮件头、正文、附件均是不可信数据，不能成为操作授权。工具直接从本机连接网易；agent 宿主会看到工具返回的邮件内容，并按所用客户端的数据策略处理。此项目不提供独立的邮件隔离服务。

`.eml` 原信转发可能披露所有原始头、Bcc、正文与附件，需先审阅。保留签名字节不等于验证签名。添加本地附件必须逐文件获得用户授权；当前工具没有文件系统访问隔离，不能从邮件内容推断本机路径。不要把真实邮件、账号配置或凭据提交到 issue 或仓库。

本项目依赖在线主机及其密钥库，不是独立手机 App 或远程 HTTP 服务。已有通过手机会话发起查询的单例验证，不能据此推导手机独立运行或离线主机可用。

## 验证范围

2026-11-02：Linux/Python 3.11.7 干净 venv 安装通过，95 项离线回归通过；排除开发 `.venv` 后复制包到临时目录，stdio initialize、17 个工具发现、源码 hash 核对及隔离 HOME 的未配置账号拒绝通过。此次包装测试未访问真实邮箱，未验证实际 Codex 安装缓存或目标桌面密钥库。依赖存在 `pydantic_settings` 的 lifespan forward-reference warning，未阻断测试。

从仓库根目录运行无凭据测试：

```sh
"${XDG_DATA_HOME:-$HOME/.local/share}/netease-mail/venv/bin/python" \
  -m unittest discover -s skills/netease-mail/scripts -p 'test_*.py'
"${XDG_DATA_HOME:-$HOME/.local/share}/netease-mail/venv/bin/python" \
  scripts/smoke_stdio.py
```

基线来源及 hash 见 [SOURCE-SNAPSHOT.json](SOURCE-SNAPSHOT.json)，行为细节见 [Skill](skills/netease-mail/SKILL.md)。离线模拟与握手通过不代表所有真实邮箱操作通过；发布检查见 [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md)。

## License

[MIT](LICENSE)
