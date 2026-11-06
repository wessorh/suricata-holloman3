# suricata-holloman3

Holloman3 perceptual fingerprinting for HTTP bodies in Suricata's EVE JSON log.

## Overview

This is an **output module** for Suricata that computes a 16-byte *structural* fingerprint of HTTP request and response bodies and emits it in the EVE JSON log. Unlike MD5/SHA256, holloman3 survives single-byte changes — files with similar binary structure produce similar fingerprints. This makes it ideal for:

- **Malware family clustering** — group variants by structural similarity
- **Poly/oligomorphic detection** — catch re-packaged malware that evades hash-based detection
- **Campaign tracking** — link samples across delivery mechanisms
- **Phishing clone detection** — identify cloned web pages even when text/links differ

## Fingerprint Format

Every fingerprint is a string `<c>.<32 lowercase hex>`, where `<c>` is an **order character** determined by the buffer size:

| Buffer size | Hilbert order | Grid | Prefix |
|---|---|---|---|
| < 256 bytes | — | — | *(skipped — no fingerprint)* |
| 256 – 511 | 4 | 16×16 | `e.` |
| 512 – 4095 | 5–6 | 32×32–64×64 | `f.` – `g.` |
| 4 KB – 64 KB | 6–8 | 64×64–256×256 | `g.` – `i.` |
| 64 KB – 1 MB | 8–10 | 256×256–1024×1024 | `i.` – `k.` |
| 1 MB – 16 MB | 10–12 | 1024×1024–4096×4096 | `k.` – `m.` |
| 16 MB+ | 12–14 | 4096×4096–16384×16384 | `m.` – `o.` |

The order character is **not fixed** — it reflects the actual Hilbert order computed for that specific buffer. The alphabet is `"  cdefghijkmnopqrstuvwxyz"` (skips `a`, `b`, and `l` to avoid confusion with `1`).

**Minimum body size**: 256 bytes. Smaller bodies return error code `-3` and are not fingerprinted.

## Example Output

A Suricata HTTP event with a fingerprinted response body:

```json
{
  "timestamp": "2026-11-05T21:00:00.000000+0000",
  "flow_id": 1234567890123456,
  "event_type": "http",
  "src_ip": "203.0.113.7",
  "dst_ip": "198.51.100.12",
  "holloman3": {
    "response_body": "o.6b718382030b717a0000060700000000"
  }
}
```

## Installation

### Prerequisites

- **Suricata** 7.0+ source tree
- **libholloman3** — clone and build from https://github.com/wessorh/libholloman3
- **CPU**: x86-64 with SSE4.1 (2008+) or ARMv8+ with NEON. AVX2 (2013+) for maximum throughput.

### Step 1: Build libholloman3

```bash
git clone https://github.com/wessorh/libholloman3
cd libholloman3
make                 # produces libholloman3.a + libholloman3.so
make ftest           # verify: 39/39 tests pass
```

### Step 2: Copy the module into the Suricata source tree

```bash
cd /path/to/suricata/src
cp /path/to/suricata-holloman3/src/output-json-holloman3.{c,h} .
```

### Step 3: Apply the registration patch

In `src/output.c`, add the include (near the other `output-json-*.h` includes):

```c
#include "output-json-holloman3.h"
```

And add the registration call (right after `JsonHttpLogRegister()`):

```c
/* holloman3 structural fingerprint */
JsonHolloman3LogRegister();
```

### Step 4: Add to the build system

In `src/Makefile.am`, add the new files to the two lists.

Header list:
```makefile
output-json-ftp.h \
output-json-holloman3.h \
```

Source list:
```makefile
output-json-ftp.c \
output-json-holloman3.c \
```

### Step 5: Configure and build Suricata

```bash
cd /path/to/suricata
./configure \
  CFLAGS="-I$(HOME)/work/ai/libholloman3/include" \
  LIBS="-L$(HOME)/work/ai/libholloman3 -lholloman3 -lm"
make
sudo make install
```

### Step 6: Configure

In `suricata.yaml`, under `outputs → eve-log → types → http`:

```yaml
outputs:
  - eve-log:
      types:
        - http:
            extended: yes
            # Holloman3 structural fingerprint of HTTP bodies
            # Bodies < 256 bytes are skipped.
            # holloman3-curve-order: 13   # Hilbert curve order 8-16, default 13
```

The `holloman3-curve-order` setting is optional and defaults to 13. It only sets the *maximum* supported order — the actual order per fingerprint is still computed from the buffer size.

## Usage Examples

### Find malware with a specific fingerprint

```bash
# Search EVE logs for a known fingerprint
jq 'select(.holloman3.response_body == "o.6b718382030b717a0000060700000000")' eve.json
```

### Cluster malware families by fingerprint similarity

```bash
# Extract all fingerprints and sort
jq -r '.holloman3.response_body // empty' eve.json | sort | uniq -c | sort -rn

# Compute Hamming distance between two fingerprints
python3 -c "
a = '6b718382030b717a0000060700000000'
b = '6b718382030b717b0000060700000000'
dist = sum(bin(int(x,16)^int(y,16)).count('1') for x,y in zip(a,b))
print(f'Hamming distance: {dist} bits')  # < 32 = likely same family
"
```

### Detect phishing clones

Compare fingerprints of suspicious web pages against legitimate sites. Matching fingerprints indicate the attacker copied the HTML structure directly.

## Architecture

```
Suricata HTTP transaction
    │
    ▼
JsonHolloman3Logger(tx)
    ├─ HtpTxUserData → request_body / response_body (HtpBody)
    ├─ StreamingBufferGetData() → contiguous body bytes
    ├─ holloman3_fingerprint_buffer() → 16-byte fp (≥ 256 bytes only)
    ├─ holloman3_fingerprint_string() → "<c>.<32 hex>"
    └─ EVE JSON: {"holloman3": {"response_body": "o.<32hex>"}}
```

The module uses `OutputRegisterTxSubModule` to hook into Suricata's output system with zero changes to core detection engine code.

## Configuration Reference

| Option | Type | Default | Description |
|---|---|---|---|
| `holloman3-curve-order` | integer | 13 | Maximum Hilbert curve order (8–16). Only affects cache pre-allocation; actual order is derived per-buffer from size. |

## Error Codes (from libholloman3)

| Code | Meaning |
|---|---|
| `0` | Success |
| `-1` | Invalid arguments |
| `-2` | Not initialised |
| `-3` | Buffer too small (< 256 bytes) |

## Files

| File | Purpose |
|---|---|
| `src/output-json-holloman3.c` | The EVE JSON output module (~170 lines) |
| `src/output-json-holloman3.h` | Header with registration declaration |

## Related Projects

- **[libholloman3](https://github.com/wessorh/libholloman3)** — the fingerprint library (Hilbert + Lanczos + rotation + SIMD)
- **[arkime-holloman3](https://github.com/wessorh/arkime-holloman3)** — the same fingerprinting for Arkime network capture

## License

GPL-2.0 (matches Suricata's license).

---

## Writing Matching Rules

### Suricata: Three approaches

The holloman3 module is an **output module** — it fires at log time, after the detection engine runs. You cannot write a native rule keyword like `holloman3_response_body:` without extending the detection engine. But there are three effective approaches.

#### A. Lua output script (inline alerts at log time)

Create `/etc/suricata/lua/holloman3-match.lua`:

```lua
-- Known malware fingerprints
local BAD_FINGERPRINTS = {
    ["o.6b718382030b717a0000060700000000"] = "Trojan.Agent2 variant",
    ["o.8481827e787d7b7a0f64120700070000"] = "SocGholish downloader",
    ["n.7e7d81827f82787784720d0761090000"] = "Emotet loader",
}

function init(args)
    local needs = {}
    needs["packet"]  = false
    needs["payload"] = false
    return needs
end

function log(args)
    local h3 = args["holloman3"]
    if not h3 then return end

    for _, label in pairs(BAD_FINGERPRINTS) do
        if h3["response_body"] == _ or h3["request_body"] == _ then
            SCLogInfo(string.format(
                "HOLLOMAN3 MATCH: %s (src=%s dst=%s)",
                label, args["src_ip"], args["dst_ip"]))
        end
    end
end
```

Enable in `suricata.yaml`:

```yaml
outputs:
  - lua:
      scripts:
        - /etc/suricata/lua/holloman3-match.lua
```

#### B. EVE JSON post-processing (offline matching)

```bash
# Exact match against a known fingerprint
jq 'select(.holloman3.response_body == "o.6b718382030b717a0000060700000000")' eve.json

# Match against a threat feed (fp|label)
while IFS='|' read -r fp label; do
    jq --arg fp "$fp" --arg label "$label" \
       'select(.holloman3.response_body == $fp) | . + {label: $label}' eve.json
done < threat-feed.txt

# Hamming-distance variant detection (catches re-packed malware)
python3 -c "
import json, sys
known = '6b718382030b717a0000060700000000'  # without order char

for line in sys.stdin:
    ev = json.loads(line)
    fp = ev.get('holloman3', {}).get('response_body', '')
    if not fp or '.' not in fp:
        continue
    hex_part = fp.split('.')[1]
    dist = sum(bin(int(x,16)^int(y,16)).count('1')
               for x,y in zip(hex_part, known))
    if dist < 16:
        print(f'VARIANT match (dist={dist}): {ev[\"src_ip\"]}')
" < eve.json
```

#### C. Native detection keyword (advanced — requires engine changes)

For wire-speed inline matching, you'd add a detection keyword to Suricata's engine:

1. Create `src/detect-http-holloman3.c` with keyword registration and match logic
2. Move holloman3 fingerprint computation into `app-layer-htp.c` during body append (not at output time)
3. Store the fingerprint string on the HtpState or HtpTxUserData
4. Register as a sticky buffer keyword

The resulting rules would look like:

```
alert http $HOME_NET any -> $EXTERNAL_NET any (
    msg:"Trojan.Agent2 — holloman3 structural match";
    holloman3_response_body:o.6b718382030b717a0000060700000000;
    sid:1000001; rev:1;)
```

This is ~500 lines of detection engine integration work. The output module approaches (A and B) cover most practical use cases.

### Arkime field queries

The Arkime plugin stores fingerprints as Elasticsearch fields. Match in the hunt/search interface:

```
# Exact fingerprint match
http.holloman3.dst == o.6b718382030b717a0000060700000000

# Has ANY fingerprint (body >= 256 bytes)
http.holloman3.dst == EXISTS!

# Match against a list
http.holloman3.dst == ["o.6b71...0000", "n.7e7d...0900"]

# Group by fingerprint in sessions view
# Sort by the "Body Holloman3" column to cluster similar files
```

**Important**: The order character prefix (`o.`, `n.`, `e.`, etc.) reflects the buffer size. Two byte-identical files of different sizes will have different prefix characters. When matching across different-size captures, strip the prefix and match on just the 32 hex characters, computing Hamming distance for variant detection.

### Hamming distance reference

| Distance | Interpretation |
|---|---|
| 0 bits | Byte-exact structural match |
| 1–8 bits | Same family, very minor variant |
| 8–32 bits | Same malware family, re-packed or slightly modified |
| 32–64 bits | Possibly related, different campaign/version |
| 64+ bits | Unrelated files |

Python utility:

```python
import sys

def hamming(a: str, b: str) -> int:
    """Hamming distance between two holloman3 hex strings."""
    if '.' in a: a = a.split('.')[1]
    if '.' in b: b = b.split('.')[1]
    return sum(bin(int(x,16)^int(y,16)).count('1') for x,y in zip(a,b))

if __name__ == '__main__':
    d = hamming(sys.argv[1], sys.argv[2])
    label = "same family" if d < 32 else "possibly related" if d < 64 else "unrelated"
    print(f"distance={d} bits ({label})")
```
