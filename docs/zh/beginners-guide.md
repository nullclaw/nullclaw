# NullClaw 新手入门指南

**阅读对象：** 非技术背景的用户。你不需要知道什么是 vtable、sandbox 或 WASM 模块。本文使用通俗易懂的语言，从头解释每个概念。

---

## 页面导航

**本文适合谁**
- 你下载或安装了 NullClaw，想在深入配置之前先了解它是什么。
- 你从未配置过 AI 模型、设置过 webhook 或编辑过 JSON 文件。
- 你想用日常语言了解 NullClaw 能为你做什么。

**开始前需要准备什么**
- 一台运行 macOS、Linux 或 Windows 的电脑。
- 一个来自支持提供商的 API 密钥（本指南会逐步演示如何获取）。

**看完本文后**
- 继续阅读 [安装指南](./installation.md)，获取在系统上安装 NullClaw 的具体命令。
- 然后继续阅读 [配置指南](./configuration.md)，逐步完成配置。
- 学习过程中可以随时回到本文作为参考。

---

## 1. NullClaw 是什么？

**一句话概括：** NullClaw 是一个小型、快速、安全的 AI 助手，完全运行在你自己的机器上。它没有内置 AI 模型——你需要连接一个自己选择并付费的模型提供商，比如 OpenRouter、OpenAI 或 Anthropic。

可以这样理解：

| 比喻 | 含义 |
|---|---|
| NullClaw 是**大脑** | 它负责倾听、思考、规划和行动。 |
| 你的 AI 提供商（OpenRouter 等）是**知识引擎** | 它生成文本、回答问题、处理图像。 |
| **频道**（Telegram、Discord 等）是你的**通信方式** | 就像选择电子邮件还是短信——频道负责传递消息。 |

**为什么要用它，而不是直接打开 ChatGPT？**

| 使用场景 | ChatGPT | NullClaw |
|---|---|---|
| 在 Telegram 或 Discord 里跟机器人聊天 | 不支持 | 支持——直接连接 |
| 能读写你电脑上的文件 | 非常有限 | 支持——完全访问 |
| 能运行 shell 命令 | 不支持 | 支持——安全沙箱保护 |
| 能在 5 美元的树莓派上运行 | 不支持 | 支持 |
| 所有数据保留在本地 | 不支持 | 支持 |
| 连接到你的自有基础设施 | 不支持 | 支持 |
| 完全离线（无需 API 密钥） | 不支持 | 不支持——需要 API 密钥 |

NullClaw 最适合**高级用户**和**开发者**，他们希望 AI 按照自己的方式、在自己的硬件上运行，连接到自己的工具和频道。

---

## 2. 你可以要求 NullClaw 做什么？

配置完成后，NullClaw 可以处理各种任务。以下是通俗语言描述的示例：

**信息查询与研究**
- "总结这个 URL 的文章内容"
- "今天东京的天气怎么样？"（通过网页搜索工具）
- "找出上周所有关于项目 X 的邮件"

**文件操作**
- "读取我工作区里叫 notes.md 的文件"
- "把会议摘要写到 meeting-notes.md 里"
- "把会议记录追加到每日日志中"
- "修改 README，添加安装说明"

**Shell 与系统**
- "检查还剩多少磁盘空间"
- "显示服务器日志的最后 50 行"
- "运行备份脚本，告诉我是否成功"

**编程与开发**
- "写一个 Python 脚本，读取 CSV 文件并输出柱状图"
- "解释这个错误信息是什么意思"
- "给登录函数添加一个单元测试"

**自动化**
- "每天早上 9 点提醒我检查服务器状态"
- "当我在 Telegram 上发送包含 'deploy' 的消息时，运行部署脚本"
- "把这个重要笔记存入记忆，下次我问的时候提醒我"

**通信频道**
- "给我的 Discord 频道发一条消息"
- "回复刚刚给我发消息的 Telegram 用户"
- "在我们的 Slack 频道发布一条更新"

**硬件操作（进阶）**
- "读取连接到我树莓派的温度传感器的数据"
- "让连接在 Arduino 13 号引脚的 LED 闪烁"

---

## 3. 核心概念：各部分如何配合工作

在配置任何东西之前，理解三个核心部分会很有帮助：

### 部分 1 — 聊天界面（如何与它对话）

与 NullClaw 互动有两种方式：

**CLI 模式（命令行）：** 在终端窗口中输入消息。适合快速任务和测试。

```bash
nullclaw agent -m "2 + 2 等于多少？"
```

**交互模式：** 一个更会话化的会话，保持打开状态：

```bash
nullclaw agent
# 然后输入你的消息
```

**Gateway 模式：** 最强大的配置方式。启动一个本地 Web 服务器，监听消息。其他程序或频道（Telegram、Discord 等）可以连接到它并投递用户消息。这就是让 NullClaw 在 Telegram 或 Discord 里响应的方法。

```bash
nullclaw gateway
# 运行在 http://127.0.0.1:3000
```

### 部分 2 — 频道（消息如何进出）

**频道**是 NullClaw 和消息服务之间的桥梁。就像一条电话线——每个频道是不同的电话号码。

NullClaw 开箱即支持多种频道：

| 频道 | 连接目标 |
|---|---|
| CLI | 你的终端（无外部连接） |
| Telegram | 你的 Telegram 机器人 |
| Discord | 你的 Discord 机器人 |
| Signal | 你的 Signal 账号 |
| Slack | 你的 Slack 工作区 |
| WhatsApp | 你的 WhatsApp Business 账号 |
| Email | 你的电子邮件收件箱和发件服务 |
| Matrix | Matrix/Element 消息平台 |
| Nostr | Nostr 去中心化协议 |
| Webhook | 任何 HTTP 端点（用于自定义集成） |
| IRC | 互联网中继聊天 |
| Lark / 飞书 | 飞书工作区 |
| DingTalk | 钉钉工作区 |
| QQ | QQ 消息平台 |
| iMessage | macOS iMessage |
| Mattermost | Mattermost 自托管聊天 |

**重要的安全概念：** 默认情况下，频道只接受来自你指定的白名单用户的消息。白名单为空的频道不接受任何人。这是刻意的设计——防止陌生人控制你的 AI。

### 部分 3 — Gateway（消息路由器）

**Gateway** 是中心枢纽，负责：
1. 从频道（Telegram、Discord 等）接收消息
2. 将消息发送给 AI 进行处理
3. 将 AI 的响应通过正确的频道发回去

```
用户发送消息
       ↓
   频道（Telegram/Discord 等）
       ↓
   Gateway（消息路由器，端口 :3000）
       ↓
   AI 模型（OpenRouter/OpenAI 等）
       ↓
   NullClaw 大脑（思考、使用工具、决策）
       ↓
   回复
       ↓
   Gateway → 频道 → 用户
```

默认情况下，Gateway 只监听你本地机器（`127.0.0.1:3000`）。这意味着外部没有任何人能访问它。要允许外部访问（例如接收来自互联网的 Telegram 消息），你需要使用**隧道（Tunnel）**——一种通过 Cloudflare 或 ngrok 等服务将你的本地 Gateway 安全暴露给外部世界的方式。

---

## 4. 五分钟快速上手

### 步骤 1 — 获取 API 密钥

NullClaw 需要一个 AI 模型来思考。你需要提供 API 密钥。最简单的开始方式是 **OpenRouter**，它通过单一账号提供对多种模型的访问：

1. 访问 [openrouter.ai](https://openrouter.ai) 并创建一个免费账号。
2. 进入**密钥（Keys）**页面，创建一个新 API 密钥。复制它——你只会看到一次。
3. （可选）为账号充值，以便 AI 能实际响应。即使 5 美元也足够尝试所有功能。

> **什么是 API 密钥？** 可以把它想象成密码。它向 AI 服务证明你是谁，并记录你的用量。妥善保管它——任何拥有你密钥的人都可以使用你的账号。

### 步骤 2 — 安装 NullClaw

**macOS / Linux（推荐）：**

```bash
brew install nullclaw
```

**Windows：**

从 [NullClaw 发布页](https://github.com/nullclaw/nullclaw/releases) 下载 Windows `.zip` 压缩包，解压后将其中的 `nullclaw.exe` 放到你能找到的地方。

**从源码构建（所有平台）：**

```bash
git clone https://github.com/nullclaw/nullclaw.git
cd nullclaw
zig build -Doptimize=ReleaseSmall
# 二进制文件位于 zig-out/bin/nullclaw
```

### 步骤 3 — 配置 NullClaw

运行交互式设置向导：

```bash
nullclaw onboard --interactive
```

向导会问你一些问题。以下是每个问题的含义：

| 问题 | 如何回答 |
|---|---|
| Provider（提供商） | 选择 `openrouter` |
| API Key | 粘贴你的 OpenRouter 密钥 |
| Default model（默认模型） | 直接回车接受建议的模型 |
| Workspace directory（工作区目录） | 直接回车使用默认路径（NullClaw 存储文件的地方） |
| Gateway host | 直接回车（保持本地和安全） |
| Gateway port | 直接回车（默认为 3000） |
| Enable channels?（启用频道？） | 如果只想先试用 CLI 模式，输入 `n` |

### 步骤 4 — 测试

```bash
nullclaw agent -m "你好！你能介绍一下你自己吗？"
```

几秒内你应该会收到 AI 的回复。

### 步骤 5 — 启动 Gateway

如果你想让 NullClaw 监听来自 Telegram、Discord 或其他频道的消息：

```bash
nullclaw gateway
```

你会看到确认信息，表明 Gateway 正在 `127.0.0.1:3000` 运行。

要停止它，按 `Ctrl+C`。

---

## 5. 记忆系统如何工作

NullClaw 内置了记忆系统。这意味着它可以记住你在多次对话中告诉它的事情。

### 它如何存储记忆

记忆存储在你电脑上的本地数据库中（默认情况下是 `~/.nullclaw/memory.db` 的 SQLite 数据库）。除非你配置了远程记忆后端，否则不会发送到云端。

### 记忆操作类型

| 命令 | 功能 |
|---|---|
| `/memory-store <事实>` | 将一个事实保存到长期记忆 |
| `/memory-recall <主题>` | 检索与某个主题相关的事实 |
| `/memory-forget <事实>` | 从记忆中删除一个特定事实 |
| `/memory-list` | 列出当前记忆中所有内容 |
| `/scratch` | 打开一个临时记事本，用于快速记录 |

### 对话示例

```
你：记住，我的服务器管理员密码是 SuperSecret123。
NullClaw：好的。我已经把这个事实安全地存入记忆了。

你：我之前跟你说过关于我服务器的什么？
NullClaw：你提到过你的服务器管理员密码是 SuperSecret123。
```

### 何时清理记忆

- 你不小心分享了敏感信息 → 使用 `/memory-forget` 或让 NullClaw 删除它。
- 记忆变得不准确了 → 用更正确的版本更新它。
- 你想要一个全新的开始 → 运行 `nullclaw memory purge` 清除所有内容。

> **隐私提示：** 默认情况下，所有记忆数据都保留在你的机器上。NullClaw 不会把你的对话历史或记忆内容发送到 AI 提供商，除非你明确配置了远程记忆后端。

---

## 6. 安全功能：保护你自己

NullClaw 内置了多项安全功能。你不需要理解技术细节——只需要知道它们存在。

### 功能 1 — 工作区隔离（它能访问哪些文件）

默认情况下，NullClaw 只能在名为**工作区（workspace）**的特定文件夹中读写文件。它无法访问你的整个文件系统。这防止它意外读取敏感文件，如密码、SSH 密钥或个人文档。

工作区通常位于 `~/.nullclaw/workspace/`。你可以在配置中更改它。

### 功能 2 — 沙箱（它能运行哪些命令）

当 NullClaw 需要运行 shell 命令（如 `ls` 或 `git`）时，它会在**沙箱（sandbox）**中运行——一个限制命令行为的受限环境。它不能：
- 访问工作区以外的文件
- 修改系统设置
- 安装软件
- 访问其他用户的数据

### 功能 3 — 配对（谁能使用 Gateway）

当 Gateway 运行时，它使用**配对（pairing）**——一个安全检查，要求任何连接者提供有效的配对码。这防止陌生人对你的 NullClaw 通过 Gateway 发送命令。

### 功能 4 — 频道白名单（哪些用户可以和它说话）

每个消息频道都有一个**白名单（allowlist）**——批准的用户 ID 或用户名列表。只有白名单上的用户才能通过该频道向 NullClaw 发送消息。白名单为空的频道不接受任何人。

### 功能 5 — 加密的密钥

你的 API 密钥和其他敏感凭据使用强加密算法（ChaCha20-Poly1305）**加密存储**在磁盘上。即使有人复制了你的配置文件，没有加密密钥也无法读取你的 API 密钥。

### 默认情况下 NullClaw 不能做什么

- 访问工作区以外的文件
- 没有配置邮件凭据就发送邮件
- 没有正确的机器人令牌就发布到频道
- 不经过沙箱就运行任意 shell 命令
- 没有明确的隧道配置就不能暴露给公共互联网

---

## 7. 新手常见错误

### 错误 1 — 在不理解的情况下将 Gateway 暴露到互联网

**会发生什么：** 你设置了 `gateway.host = "0.0.0.0"` 使 Gateway 可从任何地方访问。默认情况下，这是被故意阻止的。如果你绕过它而没有配置配对和白名单，陌生人可能会向你的 AI 发送命令。

**解决方法：** 使用隧道（Cloudflare Tunnel、ngrok 或 Tailscale）而不是直接开放端口。隧道允许你从外部访问本地 Gateway，同时保持安全控制。

### 错误 2 — 公共频道白名单为空

**会发生什么：** 你连接了 Telegram 机器人但把 `allow_from` 留空。没有人能给它发消息。

**解决方法：** 把你的 Telegram 用户 ID 设置到 `allow_from` 中。在 Telegram 上使用 `@userinfobot` 可以找到你的用户 ID。

### 错误 3 — API 密钥和提供商不匹配

**会发生什么：** 你粘贴了 OpenAI 的密钥但在配置中把提供商设置为 `openrouter`。NullClaw 会拒绝它，因为 OpenRouter 和 OpenAI 的密钥格式不同。

**解决方法：** 把提供商名称与密钥所属的服务匹配。OpenRouter 密钥以 `sk-or-` 开头，OpenAI 密钥以 `sk-` 开头。

### 错误 4 — 忘记保持 Gateway 运行

**会发生什么：** 你用 CLI（`nullclaw agent`）开始对话，但期望它响应 Telegram 消息。CLI 模式和 Gateway 模式是分开的——频道消息需要 Gateway 运行才能工作。

**解决方法：** 在终端窗口中保持 Gateway 运行，或作为后台服务运行（`nullclaw service start`）。使用 `nullclaw service status` 检查它是否正在运行。

### 错误 5 — 把敏感信息存在错误的地方

**会发生什么：** 你用 `/memory-store` 让 NullClaw 记住你的密码。虽然记忆在静态时是加密的，但在使用时会解密到内存中。

**解决方法：** 对于真正敏感的数据使用密钥管理功能，或者只在记忆系统中存储非敏感的偏好和事实。

---

## 8. 通俗排障指南

| 症状 | 可能原因 | 尝试方法 |
|---|---|---|
| "API 密钥无效"错误 | 密钥错误、提供商错误或密钥已过期 | 运行 `nullclaw onboard --interactive` 重新输入密钥 |
| Telegram 机器人无响应 | 机器人令牌错误、webhook 未设置或机器人未启动 | 运行 `nullclaw channel start telegram` 并检查 Telegram 中的机器人隐私设置 |
| Gateway 无法启动 | 端口 3000 已被占用 | 用 `nullclaw gateway --port 3001` 更换端口 |
| AI 响应但不记得之前的消息 | 会话历史未加载或记忆不工作 | 检查配置中 `memory.auto_save` 是否为 `true` |
| NullClaw 找不到文件 | 文件在工作区以外 | 把文件移入工作区，或检查你的 `allowed_paths` 配置 |
| 速率限制错误（429） | 你触发了 API 提供商的用量限制 | 等待，或切换到不同的提供商/模型 |

### 诊断命令

运行以下命令获取完整健康检查：

```bash
nullclaw doctor
```

它会检查所有内容——配置有效性、API 密钥、频道状态、记忆等。如果需要帮助调试，请分享输出结果。

---

## 9. 术语表

| 术语 | 通俗解释 |
|---|---|
| **API 密钥** | 一个密码，让 NullClaw 能够与 AI 服务通信。妥善保管。 |
| **频道（Channel）** | 消息到达 NullClaw 的方式——Telegram、Discord、邮件等。 |
| **Gateway** | 在频道和 AI 之间路由消息的中心枢纽。 |
| **提供商（Provider）** | NullClaw 连接的 AI 服务——OpenRouter、OpenAI、Anthropic 等。 |
| **模型（Model）** | 用于特定任务的 AI 大脑——Claude Sonnet、GPT-4o、Llama 等。 |
| **工作区（Workspace）** | NullClaw 被允许访问的电脑上的特定文件夹。 |
| **沙箱（Sandbox）** | 一个受限环境，防止命令做有害的事情。 |
| **配对（Pairing）** | 一个安全码，防止陌生人使用你的 Gateway。 |
| **白名单（Allowlist）** | 允许通过某个频道发送消息的批准用户列表。 |
| **隧道（Tunnel）** | 一种安全隧道，将你的本地 Gateway 暴露到互联网。 |
| **记忆（Memory）** | NullClaw 在多次对话中存储事实和偏好的长期存储。 |
| **工具（Tool）** | NullClaw 可以使用的功能——读取文件、运行命令、发送消息等。 |
| **Agent** | 一个配置好的 NullClaw 实例，有自己的身份、模型和工作区。 |
| **vtable** | （技术术语）一种在不更改调用代码的情况下交换实现的模式。使用 NullClaw 不需要理解这个。 |

---

## 10. 下一步

- **[安装指南](./installation.md)** — 在你的系统上安装 NullClaw。
- **[配置指南](./configuration.md)** — 逐步完成配置。
- **[使用与运维](./usage.md)** — 日常命令和服务管理。
- **[命令参考](./commands.md)** — 完整的 CLI 命令参考。

如果本指南中有不清楚的地方，请在 [github.com/nullclaw/nullclaw](https://github.com/nullclaw/nullclaw) 提交 issue——你的反馈有助于改进文档。
