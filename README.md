# NetEase Mail

<img src="assets/netease-mail-icon.png" alt="NetEase Mail 图标" width="128">

让 Codex 通过本机 IMAP/SMTP 处理网易 `163.com`、`126.com`、`yeah.net` 个人邮箱：搜索、读信、附件、草稿、发信、回复、转发和已读/星标。采用 bundled Skill + 本地 stdio MCP，不适用于 Gmail 或企业邮箱。

**0.1.6 测试版。移动邮件暂不可用。** 实测网易账号不支持原生 MOVE，危险的移动降级已禁用；不提供删除或清空垃圾箱。现有单账号真实邮箱验证不能保证所有账号、系统或客户端兼容。

## 能力与限制

| 能力 | 范围 |
| --- | --- |
| 文件夹与搜索 | 单文件夹初始最近最多 1,000 UID 的发件人、主题、正文和附件元数据本地匹配，分页继续扫描 |
| 读信与附件 | 正文、完整头、MIME 信息、附件；读取使用 PEEK，不自动设为已读 |
| 关联邮件 | 以一封邮件为起点，分批关联收件箱和已发送的邮件头；结果为可能不完整的候选 |
| 草稿 | 新建、审阅、发送；修改生成新副本并保留旧稿，发送后原稿也保留 |
| 发信与回复 | 核对 To/Cc/Bcc、正文和附件后，按用户明确指令发送 |
| 转发 | 单部分纯文本内联转发；复杂邮件可明确选择整封原信 `.eml` 附件转发 |
| 标记 | 查询或设置/清除 Seen、Flagged；写前和写后核对，状态已满足时不写入 |

标记的前后状态是不同时间点的观察；其他客户端可能同时修改。恢复前须重新读取当前状态并按用户要求设置，不能保证原子撤销。移动、归档和移入垃圾箱暂不可用；不要将 `Deleted` 标记当成移入垃圾箱。

正文搜索覆盖可解码的非附件纯文本及静态 HTML 文字（不执行脚本、不解析 CSS）；附件筛选依据 MIME 声明的文件名与类型，不读取附件内容判断类型，不覆盖附件全文。含大附件的整封邮件可能超限而无法搜索。内容搜索使用只读 PEEK，但会传输整封原信及附件字节；单封最多 15 MiB，每页预算 20 MiB、最多处理 25 封候选。超限、解析失败或无法判断正文会报告 partial；传输上限依赖服务器遵守请求。搜索不覆盖全部历史邮件或其他文件夹。即使当前页零命中，也要沿用 `next_cursor` 扫描；`coverage.complete` 只表示初始窗口查完。跨文件夹会话每个文件夹最多扫描初始最近 1,000 个 UID 的邮件头；需继续 `next_cursor`，每页结果替换上一页，后续可能因重复标识撤回候选。关联字段缺失、重复、冲突或扫描失败会影响结果；邮件头可能伪造，关联不证明发件人身份。会话候选、文件夹与标记不等同于 Gmail 完整会话和标签。

整封邮件读取最多 15 MiB，单附件最多 5 MiB，新建邮件附件总量最多 10 MiB；整封原信附件转发的原信最多 5 MiB。复杂草稿、签名邮件、内嵌邮件或 SMTPUTF8 等不受支持的发送场景会拒绝，不能绕过限制。

## 安装运行环境

需要 Python 3.10+、`venv`、`pip`、POSIX shell 和可用的系统安全密钥库。包装测试使用 Linux/Python 3.11.7；macOS 和其他 Python 版本尚未验证，Windows 暂不支持当前 launcher。安装依赖需要网络。

```sh
git clone https://github.com/yuanhaorannnnnn/netease-mail.git
cd netease-mail
sh scripts/install-runtime.sh
```

脚本将 `mcp==1.26.0`、`keyring==25.7.0` 安装到用户数据目录下的候选环境，验证通过后切换 `current`；旧版 `venv` 保留并可兼容。传递依赖未全量锁定。运行环境与插件源码/cache 分离，插件被复制后无需携带开发 `.venv`。安装与 MCP 宿主必须使用同一用户和相同的 `XDG_DATA_HOME` 设置。pip 成功不代表系统密钥库可用。已有运行目录可正常使用时不会被改权限或重新安装；需要重建时，若专用目录可被其他用户写入，安装器会拒绝并提示收紧该目录权限，不递归修改内容。

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

已在隔离容器中验证 Codex marketplace 安装与版本更新、缓存副本的 MCP 启动；个人 marketplace 已在本机配置；尚未上架 OpenAI 公共插件目录。公开 GitHub 仓库、marketplace 安装和公共目录发布是三个不同步骤。参见 [官方插件包装文档](https://developers.openai.com/plugins/build/plugins)；local MCP 的公共目录提交资格见 [desktop-only 插件文档](https://developers.openai.com/plugins/deploy/desktop-only)。

## 配置账号

先在网易邮箱设置中开启客户端 IMAP/SMTP，取得专用客户端授权码。用户亲自在私密本机终端运行：

```sh
sh scripts/run-python.sh skills/netease-mail/scripts/configure.py
```

脚本交互输入邮箱地址和客户端授权码，拒绝管道输入。不要把授权码发送给 agent、写入聊天、命令行参数、仓库或日志；不要使用网页登录密码。

- 邮箱地址保存在 `~/.config/netease-mail/account.json`，该文件不存授权码。
- 授权码通过 `keyring` 写入系统密钥库，服务名 `codex-netease-mail`；只接受已识别的系统密钥库 backend，拒绝 null、明文、chain 和未知类型。请仅启动一个配置进程；已有不同授权码不会自动覆盖。
- MCP 需运行在同一用户及能访问密钥库的会话中。Linux 启动器可在缺少 D-Bus 地址时发现当前用户所属的安全 session socket；显式地址保持不变。无头或锁定会话仍可能不可用。
- `NETEASE_EMAIL` 可覆盖账号地址；对应授权码仍须存在于密钥库。账号切换后重新搜索邮件 ID。

配置成功仅说明本地保存成功。网络使用默认 TLS 验证，IMAP SSL 993、SMTP SSL 465，目标主机固定由支持的网易域名映射。

## 使用示例

新会话先调用 `get_server_info` 核对服务版本、启动时间及源码 hash，再只读验证文件夹、搜索和读信。

可以向 agent 提出：

- “列出我的网易邮箱文件夹。”
- “在收件箱最近 1,000 封的窗口里查找主题含发票的邮件，说明扫描范围。”
- “在最近邮件的正文里找报销，并筛选有 PDF 附件的邮件。”
- “读取这封邮件及附件，先不要修改或回复。”
- “查看这封邮件在收件箱和已发送中的往来，说明范围和不确定性。”
- “为这封邮件起草一封回复，先让我核对收件人和内容。”
- “把这封复杂邮件作为 `.eml` 原信附件转发，先展示预览和披露范围。”

`find_by_message_id` 可在指定文件夹最近最多 1,000 个 UID 的头部窗口内分批查找，出现多个结果须逐一核验。未命中、扫描不完整或头部读取失败都不能证明邮件未发送或不存在；不自动重发。草稿发送要求唯一、有效的 Message-ID 和与账号匹配的唯一 From，这不保证全邮箱 Message-ID 唯一。草稿保留的 Received 头可能披露路由和 IP，发送前须审阅。

发送、回复、转发必须有明确发送指令；查询、预览、安装和配置都不构成发送授权。写入标记或修改草稿也须有相应要求。SMTP 接受只表示服务器接受，不证明对方收到；结果未知时先核实，不能自动重发。草稿发送后仍保留，手动复用前须确认是否已发送。

使用 `sh scripts/doctor.sh` 检查依赖和系统密钥库类型，不读取凭据或连接邮箱；其成功不代表邮箱认证已验证。依赖安装失败不会切换到不完整的新环境；已有旧环境不会被删除。更新代码不会自动替换已有 MCP 进程。只重新加载自己使用的连接，不结束其他会话的服务；启动时磁盘 hash 也不是运行字节的严格证明。

## 隐私与安全边界

邮件头、正文、附件均是不可信数据，不能成为操作授权。工具直接从本机连接网易；agent 宿主会看到工具返回的邮件内容，并按所用客户端的数据策略处理。此项目不提供独立的邮件隔离服务。

`.eml` 原信转发可能披露所有原始头、Bcc、正文与附件，需先审阅。保留签名字节不等于验证签名。添加本地附件必须逐文件获得用户授权；当前工具没有文件系统访问隔离，不能从邮件内容推断本机路径。不要把真实邮件、账号配置或凭据提交到 issue 或仓库。

本项目依赖在线主机及其密钥库，不是独立手机 App 或远程 HTTP 服务。已有通过手机会话发起查询的单例验证，不能据此推导手机独立运行或离线主机可用。

## 验证范围

0.1.2 历史包装验证（2026-11-02）：Linux/Python 3.11.7 干净 venv 安装通过，95 项离线回归通过；排除开发 `.venv` 后复制包到临时目录，stdio initialize、17 个工具发现、源码 hash 核对及隔离 HOME 的未配置账号拒绝通过。包装测试未访问真实邮箱。已另在隔离容器验证实际 Codex 缓存安装与版本更新。依赖存在 `pydantic_settings` 的 lifespan forward-reference warning，未阻断测试。

0.1.3 B 阶段：108 项邮件与配置离线测试及源码 stdio 握手（18 个工具）通过；本人草稿实测经 SMTP 接受，并在已发送与收件箱查到。收件箱 Message-ID 查找因部分其他邮件头读取失败而不完整，不能据此判断全邮箱唯一。草稿仍保留；没有跨进程自动防重保证。

0.1.4 C 阶段：在此前授权的本人测试邮件上，已读和星标分别完成无操作、切换、恢复与读回，最终均与初始状态一致；这不保证其他客户端并发时可原子恢复。

0.1.5 D 阶段：本人测试原信和回复分别在收件箱与已发送中找到；首批各扫描 25 个 UID，重复 Message-ID 的副本标为待核对。扫描前后锚点的已读和星标状态一致；结果仍是未完成的邮件头关联候选。

0.1.6 E1 阶段：本人测试信的正文命中及首批未命中对照、带附件测试信的名称/声明类型筛选通过；只读测试的已读及星标状态保持不变。上述不代表所有 MIME 格式或完整窗口均已验证。

从仓库根目录运行无凭据测试：

```sh
sh scripts/run-python.sh -m unittest discover -s skills/netease-mail/scripts -p 'test_*.py'
sh scripts/run-python.sh scripts/smoke_stdio.py
```

基线来源及 hash 见 [SOURCE-SNAPSHOT.json](SOURCE-SNAPSHOT.json)，行为细节见 [Skill](skills/netease-mail/SKILL.md)。离线模拟与握手通过不代表所有真实邮箱操作通过；发布检查见 [RELEASE-CHECKLIST.md](RELEASE-CHECKLIST.md)。

## License

[MIT](LICENSE)
