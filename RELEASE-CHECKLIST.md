# 发布前检查

当前状态：已导入发布候选基线；源码 hash 见 SOURCE-SNAPSHOT.json。干净运行环境安装、95 项离线回归、复制后 stdio 握手、17 个工具发现、来源 hash 核对及未配置账号错误边界通过。官方 plugin/MCP JSON schema 校验通过。这不代表实际 Codex marketplace/cache 安装或真实邮箱功能通过。下面是最终发布检查表，尚未逐项完成。

1. 按照用户接受的范围验收 A/B/C（文件夹移动暂不支持），确认唯一源码版本、提交或文件 hash，冻结导入期间的修改；复制可发布源码及运行所需参考资料，排除账号、授权码、邮件样本、真实附件和运行日志。不得把开发目录符号链接作为公开包源码。
2. 核对源码 License 与依赖许可证，补齐 LICENSE、作者、真实 repository URL、发行版本。确定支持的 Python 版本和依赖版本；明确 Linux/macOS/Windows 中实际验证过的平台及 keyring backend。
3. 确定可重复依赖安装方案，在隔离干净环境安装。确认 MCP 启动使用的解释器与安装依赖的解释器一致；PATH、桌面宿主环境、密钥库未解锁时给出可理解错误。
4. 将 `examples/mcp.json` 的已验证配置放到根 `mcp.json`；校验 JSON/schema，核对所有路径留在包内。不要保留指向旧开发 checkout 或个人目录的入口。
5. 在临时 repo marketplace 验证发现、安装、新会话装载、stdio initialize、tools/list 与 get_server_info。确认运行进程来自本次发行源码；老进程不能充当新包验证。
6. 无凭据测试错误边界；有凭据时先只读测试文件夹、搜索、读取、附件。搜索分页说明实际窗口，不能把服务端或局部搜索的空结果当成全邮箱不存在。
7. 写入与发送只用另行明确授权的测试操作，核对全部收件人和附件，检查发送回执与草稿/已发送副本状态；未知发送结果不得自动重发。发送成功不证明收件方收到。
8. 检查插件副本能独立运行，不依赖 agent-skills checkout、个人 MCP 配置或已有进程；安装不应改变个人 marketplace。手机/远程能力需单独验证本机连接条件，不能从本机通过推导支持。
9. 检查包清单和秘密信息，执行适合最终源码的测试，再创建公开 GitHub 仓库及发布。GitHub 发布不等同于 OpenAI 公共目录上架；后者须另走资格与审核流程。

2026-11-02 包装验证：Linux/Python 3.11.7，空 venv 安装固定直接依赖，85/85 离线回归通过。排除 .venv 后复制发行包至临时目录，以独立数据目录 venv 启动复制包：initialize、tools/list（17）、get_server_info hash 对照通过；隔离 HOME 且未配置账号时 list_folders 明确拒绝。未使用真实邮箱。依赖发出 pydantic_settings lifespan forward-reference warning，但握手及测试通过。实际 Codex 安装、目标桌面密钥库、其他系统与真实邮箱仍待验证。
