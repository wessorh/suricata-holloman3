# Build Integration

These are the minimal changes needed to integrate this module into a Suricata source tree.

## 1. `src/output.c` — add registration

Add include near line 54:
```c
#include "output-json-holloman3.h"
```

Add registration call near line 1095 (after `JsonHttpLogRegister()`):
```c
/* holloman3 structural fingerprint */
JsonHolloman3LogRegister();
```

## 2. `src/Makefile.am` — add source files

In the header list (around line 367):
```makefile
output-json-ftp.h \
output-json-holloman3.h \
```

In the source list (around line 940):
```makefile
output-json-ftp.c \
output-json-holloman3.c \
```

## 3. `suricata.yaml.in` — config template

In the eve-log types http section (around line 258):
```yaml
- http:
    extended: yes
    # Holloman3 perceptual fingerprint of HTTP bodies (requires libholloman3)
    # Bodies < 256 bytes are skipped. Fingerprints appear as
    # "<c>.<32 hex>" in the "holloman3" JSON object.
    # holloman3-curve-order: 13    # Hilbert curve order 8-16, default 13
```

## 4. Build

```bash
./configure \
  CFLAGS="-I$(HOME)/work/ai/libholloman3/include" \
  LIBS="-L$(HOME)/work/ai/libholloman3 -lholloman3 -lm"
make
```