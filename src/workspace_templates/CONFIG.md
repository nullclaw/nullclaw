# CONFIG.md - Generated Config Guide

This file is a quick guide to the main settings that `nullclaw onboard` configures in `config.json`.
It is intentionally scoped to the most common onboarding fields, not the full config schema.

## Core Fields

- `workspace`: workspace directory used for local files and generated bootstrap docs.
- `models.providers.<provider>.api_key`: provider credential. Onboarding writes this only if you enter a key; env vars still work.
- `models.providers.<provider>.base_url`: custom endpoint override used for custom/OpenAI-compatible providers and similar manual endpoint overrides.
- `agents.defaults.model.primary`: default model route in `provider/model` format.

## Common Defaults

- `default_temperature`: effective default `0.7`.
- `memory.backend`: backend selected during onboarding.
- `memory.profile`: derived from the backend choice.
- `memory.auto_save`: backend-specific default chosen by onboarding.
- `tunnel.provider`: one of `none`, `cloudflare`, `ngrok`, `tailscale`.
- `agents.defaults.heartbeat`: onboarding normally leaves heartbeat at runtime defaults (`every: 30m`, `enabled: false`) until you edit it manually.

## Autonomy Settings

Onboarding maps the autonomy choice to these fields:

- `autonomy.level`: `supervised`, `full`, or `yolo`.
- `autonomy.require_approval_for_medium_risk`: `true` for supervised, otherwise `false`.
- `autonomy.block_high_risk_commands`: `true` for supervised/autonomous, `false` for fully autonomous/yolo.

## Channel Configuration

When you configure channels in the wizard, channel-specific credentials and allowlists are written under `channels`.

- credentials stay inside the relevant channel block
- `allow_from` controls who may talk to the agent
- omitted channel blocks mean the channel is not configured

## Practical Notes

- Environment variables still work even when `config.json` omits API keys.
- Unknown keys are usually ignored, but prefer keeping `config.json` minimal and explicit.
- If you change providers manually, keep `agents.defaults.model.primary` aligned with the provider entry you configured.
