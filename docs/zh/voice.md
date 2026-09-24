# 语音（Voice）

NullClaw 支持通过 OpenAI 兼容的 Whisper 端点进行音频转录，实现消息渠道的语音输入。

## 配置

```json
{
  "tools": {
    "media": {
      "audio": {
        "enabled": true,
        "provider": "groq",
        "model": "whisper-large-v3",
        "language": "zh"
      }
    }
  }
}
```

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `enabled` | bool | `true` | 启用音频转录 |
| `provider` | string | `groq` | STT 提供商 |
| `model` | string | `whisper-large-v3` | Whisper 模型 |
| `base_url` | string | — | 自定义端点 |
| `language` | string | — | ISO 639-1 语言代码 |

## 支持的提供商

- Groq、OpenAI、Telnyx，或任何 OpenAI 兼容的 STT 端点（通过 `base_url`）

## 工作原理

1. 接收音频文件（如 Telegram 语音消息）
2. 流式写入临时文件以节省内存
3. Multipart POST 到 Whisper 端点
4. 解析转录文本，替换对话中的音频附件

## 相关页面

- [配置指南](./configuration.md)
