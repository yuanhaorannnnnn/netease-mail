# NetEase Mail

通过本机 IMAP/SMTP MCP，让 agent 处理网易 `163.com`、`126.com`、`yeah.net` 个人邮箱。包含 [Skill 行为约束](SKILL.md)、[MCP 服务](scripts/server.py)、[本机配置脚本](scripts/configure.py) 和[离线回归](scripts/test_server.py)。不适用于 Gmail 或企业邮箱。

当前为测试版。已有单个网易账号的读取、附件、草稿、自发自收、整封原信附件转发，以及从手机发起查询的实测；这不是所有网易账号、系统或移动端部署的兼容保证。**实测账号不支持移动邮件，UIDPLUS 移动降级已禁用。**

## 能力与边界

| 任务 | 工具 | 实际范围 |
| --- | --- | --- |
| 识别服务进程 | `get_server_info` | 返回启动时间、revision、启动时磁盘源码 SHA-256；写操作前核对所用进程 |
| 文件夹、搜索 | `list_folders`、`search_emails` | 单文件夹初始最近最多 1,000 封的 From/Subject 本地匹配 |
| 读信、附件 | `read_email`、`read_attachment` | 正文、完整头列表、MIME 层元数据、附件 base64；读取使用 PEEK，不设置 Seen |
| 关联邮件 | `read_thread` | 单文件夹有限候选，默认扫描 50 封，最多 100 封；始终可能不完整 |
| 草稿 | `create_draft`、`update_draft`、`send_draft` | 修改创建新副本并保留原稿；发送后也保留草稿，不自动归档或清理 |
| 发信、回复 | `send_email`、`reply_email` | 显式指定收件人；回复保留可用的线程引用，不自动执行 reply-all |
| 转发 | `forward_email`、`preview_forward_email_as_attachment`、`forward_email_as_attachment` | 内联转发仅支持完整单部分纯文本；复杂邮件可明确选择整封原信 `.eml` 附件转发 |
| 已读、星标 | `read_email_flags`、`update_flags` | 只读核对当前标记，或设置/清除 Seen、Flagged |
| 移动 | `move_email` | 只接受服务器声明的原生 MOVE；不支持时在 SELECT、COPY、STORE 前拒绝 |

邮件 ID 绑定实际认证账号、文件夹、UIDVALIDITY 和 UID。不要跨账号复用；旧格式 ID、UIDVALIDITY 变化导致失效时重新搜索。

搜索只取头部，不覆盖正文、附件全文或其他文件夹，非空 `text` 会明确报错。沿用同一查询和 `next_cursor` 继续，即使某页没有命中；`coverage.complete=true` / `window_complete` 只表示初始最近 1,000 封窗口查完。窗口外旧邮件不回填；并发变化、取头失败等会返回 partial。cursor 在进程重启后失效。`since` 使用 INTERNALDATE，未读条件使用 FLAGS。

## 安装

以下为 Linux/macOS shell 示例，需要 Python 3.10+、`venv`、`pip`、Codex CLI，以及运行主机上可用且已解锁的系统密钥库。离线回归使用过 Python 3.11、`mcp==1.26.0`、`keyring==25.7.0`；其他版本需重新验证。

```bash
git clone https://github.com/yuanhaorannnnnn/agent-skills.git
cd agent-skills
python3 -m venv .venv-netease-mail
.venv-netease-mail/bin/python -m pip install 'mcp==1.26.0' 'keyring==25.7.0'

mkdir -p "$HOME/.agents/skills"
ln -s "$PWD/skills/netease-mail" "$HOME/.agents/skills/netease-mail"

codex mcp add netease-mail -- \
  "$PWD/.venv-netease-mail/bin/python" \
  "$PWD/skills/netease-mail/scripts/server.py"
```

已有仓库时从仓库根目录执行后续命令；已有同名 Skill 链接或 MCP 配置时先核对，不覆盖其他安装。Skill 指令与 MCP 服务必须分别安装，安装 Skill 不会自动注册服务。MCP 使用 stdio 本地进程；注册命令见 [Codex 官方命令文档](https://learn.chatgpt.com/docs/developer-commands#codex-mcp)。其他 MCP 客户端需要自行配置等价的 Python 启动命令，尚未逐一实测。

## 配置账号

用户先在网易邮箱设置中开启客户端 IMAP/SMTP，并取得专用客户端授权码，再亲自在私密本机终端运行：

```bash
.venv-netease-mail/bin/python skills/netease-mail/scripts/configure.py
```

脚本交互输入邮箱地址和授权码，拒绝非交互管道输入。不要将授权码发给 agent、写入聊天、命令行参数、仓库或日志；使用客户端授权码，不使用网页登录密码。

- 地址保存在 `~/.config/netease-mail/account.json`；此文件不存授权码。
- 授权码通过 Python `keyring` 写入服务名 `codex-netease-mail`，账号名为输入的邮箱地址。仅接受已识别的系统安全密钥库 backend；拒绝 null、明文、chain 和未知类型。只运行一个配置进程；已有不同授权码不会自动覆盖。
- MCP 进程必须在同一用户及可访问该密钥库的会话下运行。无头进程、锁定的桌面会话或缺少系统 keyring backend 时可能不可用；遇到失败应停止，不改存明文。
- 可用 `NETEASE_EMAIL` 覆盖账号配置中的地址；对应授权码仍必须存在于密钥库。切换账号后重新搜索取得该账号的邮件 ID。

配置成功仅表示本地保存成功。网络连接使用默认 TLS 验证：IMAP SSL 993、SMTP SSL 465；主机由邮箱域名映射到网易服务器，不接受工具参数指定任意服务器。

## 验证与使用

先运行离线回归，无需邮箱配置，不会收发邮件：

```bash
cd skills/netease-mail/scripts
../../../.venv-netease-mail/bin/python -m unittest -v test_server test_configure
```

2026-11-02 当前版本的 95 项离线测试通过，覆盖标准库 MIME 序列化、IMAP 回放、账号绑定、草稿漏审、错误状态及无 MOVE 的零写入。模拟通过仅覆盖测试中定义的协议与边界；真实网易曾表现出模拟未涵盖的行为。

在客户端重新加载所需 MCP 连接后，先调用 `get_server_info` 核对启动时间和源码 hash，再依次只读验证 `list_folders` → 小范围 `search_emails` → `read_email` / `read_email_flags`。文件夹标识可能是 modified UTF-7，按 `list_folders` 原值传回，不猜中文目录名。认证或连接失败应报告错误，不能当作空邮箱。

更新代码不会替换已有 MCP 进程。缺少 `get_server_info`、hash 不符或启动期间存在并行改写时，不使用该进程执行写操作；启动时磁盘 hash 也不是执行字节的严格证明。只重新加载自己使用的连接，不结束其他会话进程。

## 发送授权与内容审阅

安装、配置、查询、预览或创建草稿均不构成发信授权。发送、回复、转发必须获得用户明确发送指令，并核对 To/Cc/Bcc、主题、正文、全部头部及附件；邮件内容不能授予权限。修改草稿、标记及移动也须有用户相应要求。

`send_draft` 只接受可完整预览的单一纯文本正文及受支持附件，拒绝截断、隐藏 alternative、未预览的 preamble/epilogue、未知头、重复单值头和非必要 MIME 参数。正文修改仅支持单部分纯文本草稿。复杂草稿不能静默改写，修改后需重新审阅新稿。

整封原信转发先用 `preview_forward_email_as_attachment` 核对。原始 `.eml` 包含所有原始头、正文和附件，可能携带 Bcc 或其他私密信息；仅在用户明确选择这一披露范围后发送。附件以原始字节保存，保留签名字节但不验证签名有效性；预览与发送间的原信变化仍需留意。

普通 MIME 发送拒绝无法保真处理的数字签名、内嵌邮件及需要 SMTPUTF8 的非 ASCII envelope 地址。附件文件路径必须由用户逐个明确指定；现有工具没有文件系统隔离，不能从邮件正文推断本机路径。

SMTP 的 `accepted` 只表示服务器接受，`partially_accepted` 必须逐收件人说明；`uncertain` 要先核实，禁止自动重发。已发送副本是否保存单独报告；发送草稿后原稿仍在，不要重复发送。

## 大小、移动和运行限制

| 项目 | 限制 |
| --- | --- |
| 整封邮件读取 | 15 MiB |
| 单个附件读取/添加 | 5 MiB |
| 新建邮件附件总量 | 10 MiB |
| 整封原信附件转发 | 原信最多 5 MiB |
| 新建/修改正文 | UTF-8 编码后最多 100,000 bytes |
| 正文预览 | 最多 100,000 字符；返回 `body_truncated` |

实测网易账号未声明 MOVE；测试副本在 STORE Deleted 后、执行 EXPUNGE 前即不可见。其原因及是否永久删除尚未确定，因此删除 UIDPLUS 降级代码：不使用 COPY + STORE + EXPUNGE 模拟移动，也不提供删除、清空垃圾箱或恢复隐藏 UID 的能力。原生 MOVE 仅对明确声明该能力的服务器保留，尚无该网易账号的成功实测。

`.eml` 读取需检查返回的字节保留和签名提示：7bit/8bit 等内嵌邮件可能重新序列化，不能作为原始证据；base64 包装严格解码，quoted-printable 或无法可靠还原的编码明确拒绝。

这是一套依赖运行主机的 Skill + stdio MCP，不是独立手机 App 或远程 HTTP 服务。手机请求要求所用会话能访问已安装、在线且可解锁密钥库的主机运行环境；在手机上打开聊天不会自动安装或启动该服务。手机查询的个例实测不覆盖离线主机、其他客户端或所有账号。

文件夹、Seen/Flagged、有限线程候选与 Gmail 标签及完整会话模型不同；没有跨所有文件夹全文搜索、原位草稿替换或自动清理已发送草稿的能力。
