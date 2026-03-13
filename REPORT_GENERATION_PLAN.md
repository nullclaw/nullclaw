# Report Generation & Delivery — Onderzoeksresultaten + Plan

> **Status:** Zig delivery pipeline KLAAR — nullclaw-rag PDF generatie nog te doen
> **Datum:** 13 maart 2026
> **Laatste update:** 13 maart 2026
> **Doel:** Donna kan op verzoek PDF-rapporten genereren en bezorgen via WhatsApp, e-mail, Telegram of NAS

---

## 1. Huidige Situatie

### Wat al werkt
| Component | Status | Details |
|-----------|--------|---------|
| **Telegram documenten** | ✅ Volledig | `sendDocument()` + `sendMediaMultipart()` in `telegram.zig:1555-1610` |
| **Bus media array** | ✅ Publiek | `makeOutboundWithMedia()` nu publiek (`bus.zig:223`) |
| **Channel VTable** | ✅ Alle channels | Telegram, WhatsApp en Email verwerken media; rest negeert het graceful |
| **Message tool markers** | ✅ Geïmplementeerd | `extractMediaMarkers()` in `message.zig` — parsed `[DOCUMENT:]`, `[FILE:]`, `[IMAGE:]` naar media array |
| **WhatsApp documenten** | ✅ Geïmplementeerd | `sendDocument()` in `whatsapp.zig` — Cloud API `type: "document"` met link + caption |
| **E-mail bijlagen** | ✅ Geïmplementeerd | `sendMessageWithMedia()` in `email.zig` — multipart/mixed met base64 attachments + MIME type detectie |
| **NAS** | ✅ Bestaat al | Synology NAS gemount op `/mnt/nas/donna/`, skill `nas-documents` met `write_file` + `copy_from_workspace` |
| **Laravel Media Library** | ✅ Geïnstalleerd | `spatie/laravel-medialibrary` v11.21 in nullclaw-rag |
| **PDF lezen** | ✅ Geïnstalleerd | `spatie/pdf-to-text` v1.54 (alleen ingest, niet generatie) |

### Wat ontbreekt (nullclaw-rag kant)
| Component | Gap |
|-----------|-----|
| **PDF generatie** | Geen PDF-generatiepakket in nullclaw-rag (geen dompdf/snappy/browsershot) |
| **Report API endpoint** | `POST /api/v1/reports` + `GET /api/v1/reports/{id}/download` nog niet aangemaakt |
| **ReportService** | Data aggregatie + Blade templates + dompdf integratie |
| **Report model** | Eloquent model met Media Library koppeling voor gegenereerde PDFs |

---

## 2. Voorgestelde Architectuur

```
Gebruiker: "Maak een performance rapport van afgelopen week"
        │
        ▼
┌─────────────────────────────────────────────┐
│  Donna (Zig Agent)                          │
│  1. Herkent rapport-verzoek                 │
│  2. Roept report_generate tool aan          │
│     → POST nullclaw-rag/api/v1/reports      │
│  3. Ontvangt PDF URL/pad                    │
│  4. Stuurt via kanaal met [DOCUMENT:] marker│
└────────────┬────────────────────────────────┘
             │
     ┌───────┴───────┐
     ▼               ▼
┌─────────┐   ┌──────────────────────┐
│ Channel │   │ nullclaw-rag         │
│ Delivery│   │ (Laravel)            │
│         │   │                      │
│ Telegram│◄──│ ReportService        │
│ WhatsApp│   │  → Data aggregatie   │
│ Email   │   │  → HTML templating   │
│ NAS     │   │  → PDF generatie     │
└─────────┘   │  → Media Library     │
              └──────────────────────┘
```

---

## 3. Implementatieplan

### Fase A — nullclaw-rag: PDF Generatie Endpoint

**Pakket:** `barryvdh/laravel-dompdf` (puur PHP, geen externe deps, 0 binaries nodig)
- Alternatief: `spatie/laravel-pdf` (Chromium-based, mooier maar zwaardere dep)
- Aanbeveling: start met dompdf, upgrade later indien nodig

**Nieuw:**
- `POST /api/v1/reports` — genereer rapport
  - Input: `{ "type": "skill_performance|session_summary|model_comparison", "period": "7d|30d|custom", "filters": {} }`
  - Output: `{ "report_id": 123, "download_url": "/api/v1/reports/123/download", "filename": "performance-2026-03-13.pdf" }`
- `GET /api/v1/reports/{id}/download` — download PDF
- `ReportService` — data aggregatie uit `skill_performance_entries`, `session_digests`, etc.
- Blade templates voor rapporten (HTML → dompdf)
- Opslag via Media Library op Report model

**Rapporttypen:**
1. **Skill Performance** — per-skill scores, per-model breakdown, trends
2. **Session Summary** — digest aggregatie, voorkeuren, patronen
3. **Model Comparison** — model A vs B head-to-head per skill/taaktype
4. **Evolution Overview** — triggers, resoluties, verbetertrends

### Fase B — Nullclaw Zig: Media Delivery Pipeline ✅ KLAAR

**Stap 1: Bus media API exposen** ✅
- `bus.zig:223`: `makeOutboundWithMedia()` nu publiek

**Stap 2: Message tool attachment parsing** ✅
- `message.zig`: `extractMediaMarkers()` parsed `[DOCUMENT:]`, `[FILE:]`, `[IMAGE:]` markers
- Haalt paden eruit, stuurt via `makeOutboundWithMedia()`, rapporteert bijlage-count in result
- 5 tests (marker extractie, meerdere markers, geen markers, unclosed markers, execute met media)

**Stap 3: WhatsApp document support** ✅
- `whatsapp.zig`: `sendDocument()` via Cloud API `type: "document"` met `document.link` + caption
- `vtableSend` verwerkt media array: stuurt documenten eerst (caption ≤1024 chars), dan tekst als fallback

**Stap 4: E-mail bijlagen** ✅
- `email.zig`: `sendMessageWithMedia()` bouwt `multipart/mixed` met `multipart/alternative` body + base64 bijlagen
- `mimeTypeFromPath()` voor MIME type detectie (pdf, png, jpg, docx, xlsx, csv, etc.)
- `vtableSend` delegeert naar `sendMessageWithMedia()`
- 6 tests (MIME types, vtable verificatie)

**Stap 5: NAS delivery** ✅ Klaar (was al aanwezig)
- Skill `nas-documents` met `write_file` en `copy_from_workspace` commands
- NAS gemount op `/mnt/nas/donna/` met `rapporten/` subfolder

### Fase C — Report Generation Tool

**Nieuw Zig tool:** `report_generate`
- Parameters: `type`, `period`, `filters`, `delivery` (channel/nas/download)
- Flow:
  1. POST naar nullclaw-rag `/api/v1/reports`
  2. Download PDF naar temp pad
  3. Stuur via gekozen kanaal met `[DOCUMENT:]` marker
  4. Of: kopieer naar NAS pad

---

## 4. Prioritering

| Prio | Component | Status | Details |
|------|-----------|--------|---------|
| ~~1~~ | ~~Bus media API exposen~~ | ✅ Klaar | `makeOutboundWithMedia()` publiek |
| ~~2~~ | ~~Message tool attachment parsing~~ | ✅ Klaar | `extractMediaMarkers()` + 5 tests |
| ~~3~~ | ~~Telegram delivery~~ | ✅ Klaar | Werkte al |
| ~~4~~ | ~~WhatsApp document support~~ | ✅ Klaar | `sendDocument()` + vtableSend media |
| ~~5~~ | ~~E-mail bijlagen~~ | ✅ Klaar | `sendMessageWithMedia()` + MIME + 6 tests |
| ~~6~~ | ~~NAS delivery~~ | ✅ Klaar | `nas-documents` skill |
| **7** | **nullclaw-rag: report endpoint + dompdf** | 🔜 TODO | Maakt PDF generatie mogelijk |
| **8** | **report_generate Zig tool** | 🔜 TODO | Wacht op nullclaw-rag endpoint |

---

## 5. Overwegingen

### Beveiliging
- Rapporten kunnen gevoelige data bevatten → PII-redactie via bestaande `PiiRedactionService`
- Download URLs moeten authenticated zijn (Sanctum token)
- Temp PDF bestanden opruimen na delivery (TTL)

### Schaalbaarheid
- PDF generatie via Laravel queue job (async) — niet blokkeren
- Grote rapporten: pagination of samenvatting-first approach
- Cache recente rapporten (zelfde parameters → zelfde PDF)

### WhatsApp-specifiek
- WhatsApp Business API vereist publiek bereikbare media URL OF media upload
- Optie 1: serveer PDF via nullclaw-rag endpoint (tijdelijke signed URL)
- Optie 2: upload naar WhatsApp media endpoint eerst, dan stuur met media ID
- Max bestandsgrootte: 100 MB (ruim voldoende voor rapporten)

### NAS (al aanwezig)
- Synology NAS gemount op `/mnt/nas/donna/` — skill `nas-documents` is volledig operationeel
- `rapporten/` subfolder bestaat al als standaard rapportlocatie
- `copy_from_workspace` command voor workspace → NAS overdracht
- `write_file` command voor direct schrijven (tekst/markdown)
- Flow voor PDF: genereer in workspace → `copy_from_workspace` naar `rapporten/rapport-2026-03-13.pdf`
- Geen extra implementatie nodig
