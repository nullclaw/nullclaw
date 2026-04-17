# Beginner's Guide to NullClaw

**Audience:** Non-technical users. You do not need to know what a vtable, sandbox, or WASM module is. This guide uses plain English and explains every concept from scratch.

---

## Page Guide

**Who this page is for**
- You downloaded or installed NullClaw and want to know what it is before going further.
- You have never configured an AI model, set up a webhook, or edited a JSON file.
- You want to understand what NullClaw can do for you in everyday terms.

**What you need to start**
- A computer running macOS, Linux, or Windows.
- An API key from a supported AI provider (the guide walks you through getting one).

**Read this next**
- After this guide, move to [Installation](./installation.md) for the exact commands to install NullClaw on your system.
- Then continue to [Configuration](./configuration.md) for the step-by-step configuration walkthrough.
- Keep this guide handy as a reference while you are learning.

---

## 1. What is NullClaw?

**In one sentence:** NullClaw is a small, fast, and secure AI assistant that runs entirely on your own machine. It does not have a built-in AI model — you connect it to one you choose and pay for, like OpenRouter, OpenAI, or Anthropic.

Think of it like this:

| Metaphor | What it means |
|---|---|
| NullClaw is the **brain** | It listens, thinks, plans, and acts. |
| Your AI provider (OpenRouter, etc.) is the **knowledge engine** | It generates text, answers questions, and processes images. |
| The **channel** (Telegram, Discord, etc.) is how you talk to it | Like choosing email vs. text messaging — the channel transports messages. |

**Why would you use this instead of just opening ChatGPT?**

| Use case | ChatGPT | NullClaw |
|---|---|---|
| Chat with a bot on Telegram or Discord | No | Yes — connects directly |
| AI that reads and writes files on your computer | Very limited | Yes — full access |
| AI that runs shell commands | No | Yes — safely sandboxed |
| Runs on a $5 Raspberry Pi | No | Yes |
| Keeps all data on your machine | No | Yes |
| Connects to your own infrastructure | No | Yes |
| 100% offline without an API key | No | No — needs an API key |

NullClaw is best for **power users** and **developers** who want AI that works on their terms, on their hardware, connected to their tools and channels.

---

## 2. What You Can Ask NullClaw to Do

Once configured, NullClaw can handle a wide range of tasks. Here are examples phrased in plain English:

**Information & Research**
- "Summarize this article from a URL"
- "What is the weather in Tokyo today?" (via web search tool)
- "Find all emails from the last week about project X"

**File Operations**
- "Read the file called notes.md in my workspace"
- "Write a summary of our meeting to meeting-notes.md"
- "Append the meeting notes to the daily log"
- "Edit the README to add installation instructions"

**Shell & System**
- "Check how much disk space is left"
- "Show me the last 50 lines of the server log"
- "Run a backup script and tell me if it succeeded"

**Coding & Development**
- "Write a Python script that reads a CSV and outputs a bar chart"
- "Explain what this error message means"
- "Add a unit test for the login function"

**Automation**
- "Every day at 9am, remind me to check the server status"
- "When I send a message on Telegram containing 'deploy', run the deploy script"
- "Store this important note in memory and recall it when I ask"

**Communication Channels**
- "Send a message to my Discord channel"
- "Reply to the Telegram user who just messaged me"
- "Post an update to our Slack channel"

**Hardware (advanced)**
- "Read the temperature from the sensor connected to my Raspberry Pi"
- "Blink the LED on pin 13 of my Arduino"

---

## 3. The Mental Model: How It All Fits Together

Before you configure anything, it helps to understand the three moving parts:

### Part 1 — The Chat Interface (how you talk to it)

You have two ways to interact with NullClaw:

**CLI mode (command-line):** You type messages in a terminal window. Good for quick tasks and testing.

```bash
nullclaw agent -m "What is 2 + 2?"
```

**Interactive mode:** A more conversational session that stays open:

```bash
nullclaw agent
# then type your messages
```

**Gateway mode:** The most powerful setup. Starts a local web server that listens for messages. Other programs or channels (Telegram, Discord, etc.) can connect to it and deliver messages from users. This is how you get NullClaw to respond inside Telegram or Discord.

```bash
nullclaw gateway
# runs at http://127.0.0.1:3000
```

### Part 2 — Channels (how messages get in and out)

A **channel** is a bridge between NullClaw and a messaging service. Think of it like a phone line — each channel is a different phone number.

NullClaw supports many channels out of the box:

| Channel | What it connects to |
|---|---|
| CLI | Your terminal (no external connection) |
| Telegram | Your Telegram bot |
| Discord | Your Discord bot |
| Signal | Your Signal account |
| Slack | Your Slack workspace |
| WhatsApp | Your WhatsApp Business account |
| Email | Your email inbox and outgoing mail |
| Matrix | Matrix/Element messaging |
| Nostr | Nostr decentralized protocol |
| Webhook | Any HTTP endpoint (for custom integrations) |
| IRC | Internet Relay Chat |
| Lark / Feishu | Lark/Feishu workspace |
| DingTalk | DingTalk workspace |
| QQ | QQ messaging |
| iMessage | macOS iMessage |
| Mattermost | Mattermost self-hosted chat |

**Important security concept:** By default, a channel only accepts messages from a list of approved users you specify. A channel with an empty allowlist accepts nobody. This is intentional — it prevents strangers from controlling your AI.

### Part 3 — The Gateway (the message router)

The **gateway** is the central hub that:
1. Receives messages from channels (Telegram, Discord, etc.)
2. Sends them to the AI for processing
3. Sends the AI's responses back through the correct channel

```
User sends message
       ↓
   Channel (Telegram/Discord/etc.)
       ↓
   Gateway (message router at :3000)
       ↓
   AI Model (OpenRouter/OpenAI/etc.)
       ↓
   NullClaw Brain (thinks, uses tools, decides)
       ↓
   Response
       ↓
   Gateway → Channel → User
```

By default, the gateway only listens on your local machine (`127.0.0.1:3000`). This means nobody outside your computer can reach it. To allow external access (for example, to receive Telegram messages from the internet), you use a **tunnel** — a secure tunnel that exposes your local gateway to the outside world through a service like Cloudflare or ngrok.

---

## 4. Getting Started in 5 Minutes

### Step 1 — Get an API Key

NullClaw needs an AI model to think with. You provide the API key. The easiest way to start is **OpenRouter**, which gives you access to many models through a single account:

1. Go to [openrouter.ai](https://openrouter.ai) and create a free account.
2. Go to **Keys** and create a new API key. Copy it — you will only see it once.
3. (Optional) Add credit to your account so the AI can actually respond. Even $5 is enough to try everything.

> **What is an API key?** Think of it like a password. It proves to the AI service that you are who you say you are and tracks how much you use. Keep it safe — anyone with your key can use your account.

### Step 2 — Install NullClaw

**macOS / Linux (recommended):**

```bash
brew install nullclaw
```

**Windows:**

Download the Windows `.zip` archive from the [NullClaw releases page](https://github.com/nullclaw/nullclaw/releases), extract it, and put the included `nullclaw.exe` somewhere you can find it.

**From source (all platforms):**

```bash
git clone https://github.com/nullclaw/nullclaw.git
cd nullclaw
zig build -Doptimize=ReleaseSmall
# binary will be at zig-out/bin/nullclaw
```

### Step 3 — Configure It

Run the interactive setup wizard:

```bash
nullclaw onboard --interactive
```

The wizard will ask you questions. Here is what each question means:

| Question | What to answer |
|---|---|
| Provider | Choose `openrouter` |
| API Key | Paste your OpenRouter key |
| Default model | Press Enter to accept the suggested model |
| Workspace directory | Press Enter to use the default (where NullClaw stores files) |
| Gateway host | Press Enter (keeps it local and safe) |
| Gateway port | Press Enter (defaults to 3000) |
| Enable channels? | Type `n` if you just want to try CLI mode first |

### Step 4 — Test It

```bash
nullclaw agent -m "Hello! Can you explain what you are?"
```

You should get a response from the AI within a few seconds.

### Step 5 — Start the Gateway

If you want NullClaw to listen for messages from Telegram, Discord, or another channel:

```bash
nullclaw gateway
```

You will see output confirming the gateway is running at `127.0.0.1:3000`.

To stop it, press `Ctrl+C`.

---

## 5. How Memory Works

NullClaw has a built-in memory system. This means it can remember things you told it across conversations.

### How it stores memories

Memories are stored in a local database on your computer (by default, a SQLite database at `~/.nullclaw/memory.db`). Nothing is sent to the cloud unless you configure it to use a remote memory backend.

### Types of memory operations

| Command | What it does |
|---|---|
| `/memory-store <fact>` | Saves a fact to long-term memory |
| `/memory-recall <topic>` | Retrieves facts related to a topic |
| `/memory-forget <fact>` | Removes a specific fact from memory |
| `/memory-list` | Lists everything currently in memory |
| `/scratch` | Opens a temporary notepad for quick notes |

### Example conversation

```
You: Remember that my server's admin password is SuperSecret123.
NullClaw: Done. I've stored that fact securely in memory.

You: What did I tell you about my server?
NullClaw: You mentioned that your server's admin password is SuperSecret123.
```

### When to clear memory

- You shared something sensitive by mistake → use `/memory-forget` or ask NullClaw to delete it.
- The memory becomes inaccurate → update it with a corrected version.
- You want a fresh start → run `nullclaw memory purge` to clear everything.

> **Privacy note:** All memory data stays on your machine by default. NullClaw does not send your conversation history or memory contents to the AI provider unless you explicitly configure a remote memory backend.

---

## 6. Keeping Yourself Safe

NullClaw has several safety features built in. You do not need to understand the technical details — just know that they exist.

### Feature 1 — Workspace Isolation (files it can access)

By default, NullClaw can only read and write files inside a specific folder called the **workspace**. It cannot access your whole filesystem. This prevents it from accidentally reading sensitive files like passwords, SSH keys, or personal documents.

The workspace is typically `~/.nullclaw/workspace/`. You can change it in the configuration.

### Feature 2 — Sandbox (commands it can run)

When NullClaw needs to run a shell command (like `ls` or `git`), it runs it inside a **sandbox** — a restricted environment that limits what the command can do. It cannot:
- Access files outside the workspace
- Modify system settings
- Install software
- Access other users' data

### Feature 3 — Pairing (who can use the gateway)

When the gateway is running, it uses **pairing** — a security check that requires anyone connecting to present a valid pairing code. This prevents strangers from sending commands to your NullClaw through the gateway.

### Feature 4 — Channel Allowlists (which users can talk to it)

Each messaging channel has an **allowlist** — a list of approved user IDs or usernames. Only users on the allowlist can send messages to NullClaw through that channel. A channel with an empty allowlist accepts nobody.

### Feature 5 — Encrypted Secrets

Your API keys and other sensitive credentials are stored **encrypted** on disk using a strong encryption algorithm (ChaCha20-Poly1305). Even if someone copies your config file, they cannot read your API keys without the encryption key.

### What NullClaw Cannot Do By Default

- Access files outside the workspace
- Send emails without email credentials configured
- Post to channels without proper bot tokens
- Run arbitrary shell commands without going through the sandbox
- Expose itself to the public internet without an explicit tunnel configuration

---

## 7. Common Beginner Mistakes

### Mistake 1 — Exposing the gateway to the internet without understanding it

**What happens:** You set `gateway.host = "0.0.0.0"` to make the gateway accessible from anywhere. By default, this is blocked intentionally. If you override it without pairing and allowlists configured, strangers could send commands to your AI.

**Fix:** Use a tunnel (Cloudflare Tunnel, ngrok, or Tailscale) instead of opening ports directly. Tunnels let you access your local gateway from outside while keeping the security controls in place.

### Mistake 2 — Empty allowlist on a public channel

**What happens:** You connect a Telegram bot but leave `allow_from` empty. No one can message it.

**Fix:** Set `allow_from` to the Telegram user IDs of people who should be allowed to talk to your bot. Use `@userinfobot` on Telegram to find your user ID.

### Mistake 3 — Wrong provider for your API key

**What happens:** You paste an OpenAI key but set the provider to `openrouter` in the config. NullClaw rejects it because OpenRouter and OpenAI have different key formats.

**Fix:** Match the provider name to the service the key belongs to. OpenRouter keys start with `sk-or-`, OpenAI keys start with `sk-`.

### Mistake 4 — Forgetting to keep the gateway running

**What happens:** You start a conversation with the CLI (`nullclaw agent`) but expect it to respond to Telegram messages. CLI mode and gateway mode are separate — the gateway needs to be running for channel-based messages to work.

**Fix:** Keep the gateway running in a terminal window or as a background service (`nullclaw service start`). Use `nullclaw service status` to check if it is running.

### Mistake 5 — Storing sensitive information in the wrong place

**What happens:** You ask NullClaw to remember your password using `/memory-store`. While memory is encrypted at rest, it is decrypted into memory during use.

**Fix:** Use the secrets management feature for truly sensitive data, or use the memory system for non-sensitive preferences and facts only.

---

## 8. Troubleshooting in Plain English

| Symptom | Likely Cause | What to Try |
|---|---|---|
| "API key invalid" error | Wrong key, wrong provider, or key expired | Run `nullclaw onboard --interactive` and re-enter your key |
| No response from Telegram bot | Bot token wrong, webhook not set up, or bot not started | Run `nullclaw channel start telegram` and check the bot's privacy settings in Telegram |
| Gateway won't start | Port 3000 already in use | Change the port with `nullclaw gateway --port 3001` |
| AI responds but doesn't remember previous messages | Session history not loaded or memory not working | Check if `memory.auto_save` is `true` in config |
| NullClaw says it can't find a file | File is outside the workspace | Move the file into the workspace, or check your `allowed_paths` config |
| Rate limit error (429) | You hit the API provider's usage limit | Wait, or switch to a different provider/model |

### Diagnostic command

Run this to get a full health check:

```bash
nullclaw doctor
```

It checks everything — config validity, API key, channel status, memory, and more. Share the output if you need help debugging.

---

## 9. Glossary

| Term | Plain English Definition |
|---|---|
| **API Key** | A password that lets NullClaw talk to an AI service. Keep it secret. |
| **Channel** | A way for messages to reach NullClaw — Telegram, Discord, email, etc. |
| **Gateway** | The central hub that routes messages between channels and the AI. |
| **Provider** | The AI service NullClaw connects to — OpenRouter, OpenAI, Anthropic, etc. |
| **Model** | The specific AI brain used for a task — Claude Sonnet, GPT-4o, Llama, etc. |
| **Workspace** | The specific folder on your computer that NullClaw is allowed to access. |
| **Sandbox** | A restricted environment that prevents commands from doing harmful things. |
| **Pairing** | A security code that prevents strangers from using your gateway. |
| **Allowlist** | A list of approved users who are allowed to message a channel. |
| **Tunnel** | A secure tunnel that exposes your local gateway to the internet. |
| **Memory** | NullClaw's long-term storage for facts and preferences across conversations. |
| **Tool** | A capability NullClaw can use — reading files, running commands, sending messages, etc. |
| **Agent** | A configured instance of NullClaw with its own identity, model, and workspace. |
| **vtable** | (Technical) A pattern for swapping implementations without changing calling code. You do not need to understand this to use NullClaw. |

---

## 10. Next Steps

- **[Installation](./installation.md)** — Get NullClaw installed on your system.
- **[Configuration](./configuration.md)** — Walk through the configuration step by step.
- **[Usage and Operations](./usage.md)** — Daily commands and service management.
- **[Commands](./commands.md)** — Full reference of every CLI command.

If something in this guide was unclear, open an issue at [github.com/nullclaw/nullclaw](https://github.com/nullclaw/nullclaw) — your feedback helps improve the documentation for everyone.
