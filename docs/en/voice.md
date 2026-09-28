# Voice

NullClaw supports audio transcription via OpenAI-compatible Whisper endpoints, enabling voice input from messaging channels.

## Configuration

```json
{
  "tools": {
    "media": {
      "audio": {
        "enabled": true,
        "provider": "groq",
        "model": "whisper-large-v3",
        "language": "en"
      }
    }
  }
}
```

### Config Fields

| Field | Type | Default | Notes |
|-------|------|---------|-------|
| `enabled` | bool | `true` | Enable audio transcription |
| `provider` | string | `groq` | STT provider name |
| `model` | string | `whisper-large-v3` | Whisper model variant |
| `base_url` | string | — | Custom endpoint override |
| `language` | string | — | ISO 639-1 code (e.g., `en`, `ru`, `zh`) |

## Supported Providers

| Provider | Endpoint |
|----------|----------|
| Groq | `https://api.groq.com/openai/v1/audio/transcriptions` |
| OpenAI | `https://api.openai.com/v1/audio/transcriptions` |
| Telnyx | `https://api.telnyx.com/v2/ai/audio/transcriptions` |
| Custom | Set `base_url` to any OpenAI-compatible STT endpoint |

The provider's API key is resolved from `models.providers.<name>.api_key`.

## How It Works

1. Audio file is received (e.g., Telegram voice message)
2. File is streamed to a temp file to minimize memory usage
3. Multipart POST to the Whisper endpoint with model and language params
4. JSON response `{"text": "transcribed text"}` is parsed
5. Transcribed text replaces the audio attachment in the conversation

## Channel Integration

Telegram voice messages are automatically transcribed when audio is enabled. The agent sees the transcribed text instead of an audio file reference.

## Related

- [Configuration](./configuration.md) — Full config reference
