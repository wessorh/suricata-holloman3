# suricata-holloman3 — Holloman3 EVE JSON output module for Suricata

Adds holloman3 perceptual fingerprinting of HTTP bodies to Suricata's EVE JSON log output.

## What it does

For each HTTP transaction, computes a 16-byte structural fingerprint of request and response bodies and adds a `"holloman3"` object to the EVE JSON output:

```json
{
  "timestamp": "2026-11-05T21:00:00.000000+0000",
  "event_type": "http",
  "holloman3": {
    "response_body": "o.6b718382030b717a0000060700000000"
  }
}
```

## Fingerprint format

`<c>.<32 hex>` where `<c>` is the order character derived from the buffer size. Bodies smaller than 256 bytes are skipped.

| Buffer size | Prefix |
|---|---|
| < 256 bytes | *skipped* |
| 256 – 511 | `e.` |
| 512 – 4095 | `f.` – `g.` |
| 4 KB – 64 KB | `g.` – `i.` |
| 64 KB – 1 MB | `i.` – `k.` |
| 1 MB – 16 MB | `k.` – `m.` |
| 16 MB+ | `m.` – `o.` |

## Installation

### 1. Copy files into Suricata source tree

```bash
cp src/output-json-holloman3.{c,h} /path/to/suricata/src/
```

### 2. Apply the output.c registration patch

In `src/output.c`, add:
```c
#include "output-json-holloman3.h"
```
and after `JsonHttpLogRegister();` add:
```c
JsonHolloman3LogRegister();
```

### 3. Apply the Makefile.am patch

In `src/Makefile.am`, add `output-json-holloman3.h` to the header list and `output-json-holloman3.c` to the source list.

### 4. Build Suricata with libholloman3

```bash
cd /path/to/suricata
./configure \
  CFLAGS="-I$(HOME)/work/ai/libholloman3/include" \
  LIBS="-L$(HOME)/work/ai/libholloman3 -lholloman3 -lm"
make
```

### 5. Configure

In `suricata.yaml`, under `outputs → eve-log → types → http`, add:

```yaml
- http:
    extended: yes
    # Holloman3 structural fingerprint of HTTP bodies
    holloman3-curve-order: 13   # optional, 8-16, default 13
```

## Requirements

- **Suricata** 7.0+ (tested with output module system)
- **libholloman3** — https://github.com/wessorh/libholloman3
  - Hilbert curve + Lanczos-3 + rotation + SIMD (AVX2/SSE4.1)
- **CPU**: x86-64 with SSE4.1 (2008+) or ARMv8+ with NEON

## Files

| File | Purpose |
|---|---|
| `src/output-json-holloman3.c` | EVE JSON output module (173 lines) |
| `src/output-json-holloman3.h` | Header with registration declaration |

## Architecture

```
Suricata HTTP transaction
    │
    ▼
JsonHolloman3Logger(tx)
    ├─ HtpTxUserData → request_body / response_body (HtpBody)
    ├─ StreamingBufferGetData() → contiguous body bytes
    ├─ holloman3_fingerprint_buffer() → 16-byte fp (≥ 256 bytes only)
    └─ EVE JSON: {"holloman3": {"response_body": "o.<32hex>"}}
```

## Related

- [libholloman3](https://github.com/wessorh/libholloman3) — Fingerprint library
- [arkime-holloman3](https://github.com/wessorh/arkime-holloman3) — Arkime capture plugin