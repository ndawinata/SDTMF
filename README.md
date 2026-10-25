# SDTMF v2

[![DOI](https://zenodo.org/badge/1432957615.svg)](https://doi.org/10.5281/zenodo.23637663)

Authenticated DTMF frames for Python, JavaScript (Node), C / Arduino, and Go.

A sender turns a short message (`0-9A-D`) into a tone string such as
`*01505D531#`. A receiver with the same key recovers the message and rejects
replays, wrong keys, and flipped digits.

The protocol is specified in [`SPEC.md`](SPEC.md). Every implementation in this
repo must pass [`test-vectors.json`](test-vectors.json).

This is a custom construction (PBKDF2 + HMAC-SHA256 + 14-symbol keystream). It
has not been formally audited. Persist `tx_ctr` / `rx_last` across restarts,
and never share one password between two senders.

## Frame format

```
start  counter  ciphertext  tag  end
  *       01       5D08    57C1CB  #      ->  *015D0857C1CB#
```

| Option | Meaning | Range | Default |
|---|---|---|---|
| `ctr_tx` | counter symbols sent per frame | 0–8 | 2 |
| `tag_len` | authentication tag symbols | 1–8 | 6 |
| `start` | start marker | `''` or one char outside `0-9A-D` | `*` |
| `end` | end marker | `''` or one char outside `0-9A-D`, ≠ `start` | `#` |

Frame length = `len(start) + ctr_tx + len(message) + tag_len + len(end)`.

**Sender and receiver must use the same options.** They are not sent in the
frame; a mismatch just makes every frame fail to decrypt.

## Configuration examples

All frames below are real output for password `secret-key`, message `"1234"`,
first frame from a fresh sender (also in `test-vectors.json`).

| Use case | `ctr_tx` | `tag_len` | `start` | `end` | Frame | Tones |
|---|---|---|---|---|---|---|
| **Default** — balanced | 2 | 6 | `*` | `#` | `*015D0857C1CB#` | 14 |
| High security | 2 | 8 | `*` | `#` | `*015D085B57C1CB#` | 16 |
| Long gaps between frames | 3 | 6 | `*` | `#` | `*0015D0857C1CB#` | 15 |
| Shorter, with lockout | 2 | 4 | `*` | `#` | `*015D08C1CB#` | 12 |
| Short, reliable link | 1 | 4 | `*` | `#` | `*15D08C1CB#` | 11 |
| Shortest, no loss tolerated | 0 | 4 | `*` | `#` | `*5D08C1CB#` | 10 |
| Minimum tag (testing only) | 2 | 3 | `*` | `#` | `*015D081CB#` | 11 |
| Swapped markers | 2 | 6 | `#` | `*` | `#015D0857C1CB*` | 14 |
| End by silence timeout | 1 | 4 | `*` | none | `*15D08C1CB` | 10 |
| No markers (fixed length) | 2 | 6 | none | none | `015D0857C1CB` | 12 |
| Text transport (non-DTMF) | 2 | 6 | `<` | `>` | `<015D0857C1CB>` | 14 |

### Frame length by message length

| Config | Overhead | 1 char | 4 chars | 10 chars | 20 chars |
|---|---|---|---|---|---|
| `ctr_tx=2, tag_len=6` (default) | 10 | 11 | 14 | 20 | 30 |
| `ctr_tx=2, tag_len=8` | 12 | 13 | 16 | 22 | 32 |
| `ctr_tx=2, tag_len=4` | 8 | 9 | 12 | 18 | 28 |
| `ctr_tx=1, tag_len=4` | 7 | 8 | 11 | 17 | 27 |
| `ctr_tx=1, tag_len=4`, no end | 6 | 7 | 10 | 16 | 26 |

### What the numbers mean

| `tag_len` | Chance a random forged frame is accepted |
|---|---|
| 3 | 1 in 2 744 |
| 4 | 1 in 38 416 |
| 6 (default) | 1 in 7.5 million |
| 8 | 1 in 1.5 billion |

| `ctr_tx` | Lost frames in a row the receiver can recover from |
|---|---|
| 0 | none |
| 1 | 13 |
| 2 (default) | 195 |
| 3 | 2 743 |

Rate-limit failed frames on the receiver, especially with `tag_len` ≤ 4.

On a DTMF channel only `*` and `#` are free to use as markers, so the practical
choices are `*…#`, `#…*`, one marker, or none. Without an end marker, the
receiver needs a silence timeout or a fixed message length to know when the
frame is complete.

## Usage

### Python

```python
from sdtmf import SecureDTMF

tx = SecureDTMF("secret-key")                       # defaults: 2 / 6 / '*' / '#'
print(tx.encrypt("12AB"))                           # *015D71A40B54#

custom = SecureDTMF("secret-key", ctr_tx=1, tag_len=4, start="#", end="*")
raw = SecureDTMF.from_keys(k_enc, k_mac, tag_len=8)  # 32-byte keys, no PBKDF2

custom.frame_len(4)        # 11
tx.get_state()             # {'tx_ctr': ..., 'rx_last': ...} — persist this
```

```bash
PYTHONPATH=python python3 -c "from sdtmf import SecureDTMF; print(SecureDTMF('secret-key').encrypt('1'))"
pip install sdtmf          # after publishing
```

`encrypt.py` at the repo root is a small demo that imports the same library.

### JavaScript (Node 14+)

```js
const { SecureDTMF } = require("sdtmf");

const tx = new SecureDTMF("secret-key");            // defaults
console.log(tx.encrypt("1"));                       // *01505D531#

const custom = new SecureDTMF("secret-key", { ctrTx: 1, tagLen: 4, start: "#", end: "*" });
const raw = SecureDTMF.fromKeys(kEnc, kMac, { tagLen: 8 });
const short = new SecureDTMF("secret-key", 1, 4);   // positional ctrTx, tagLen also works
```

```bash
node -e "const {SecureDTMF}=require('./js/sdtmf'); console.log(new SecureDTMF('secret-key').encrypt('1'))"
npm install sdtmf          # after publishing
```

### C / Arduino

```c
#include "sdtmf.h"

sdtmf_t tx;
char frame[48];

sdtmf_init(&tx, "secret-key", SDTMF_DEFAULT_CTR_TX, SDTMF_DEFAULT_TAG_LEN);  /* desktop / ESP32 */
/* sdtmf_init_keys(&tx, k_enc, k_mac, 2, 6);   — use this on AVR */

sdtmf_set_markers(&tx, '#', '*');               /* optional; SDTMF_NO_MARKER for none */
sdtmf_encrypt(&tx, "1234", frame, sizeof frame);
```

`sdtmf_init` / `sdtmf_init_keys` always reset the markers to `*` / `#`; call
`sdtmf_set_markers` afterwards. `sdtmf_frame_len(&tx, n)` gives the output size
(add 1 for the terminating NUL).

On AVR, skip `sdtmf_init` (100 000× PBKDF2 is too slow). Derive `k_enc`/`k_mac`
once on a PC and store the 64 bytes in flash. See `c/examples/EncryptDecrypt`.
Add `c/` as an Arduino library (it has `library.properties` + `src/`).

### Go 1.18+

```go
import "github.com/ndawinata/SDTMF/go/v2" // package sdtmf

tx, err := sdtmf.New("secret-key") // defaults: 2 / 6 / '*' / '#'
frame, err := tx.Encrypt("1")      // *01505D531#

custom, err := sdtmf.New("secret-key",
    sdtmf.WithCtrTx(1),
    sdtmf.WithTagLen(4),
    sdtmf.WithMarkers("#", "*"),
)
raw, err := sdtmf.FromKeys(kEnc, kMac, sdtmf.WithTagLen(8))
```

```bash
cd go && go test
# install
go get github.com/ndawinata/SDTMF/go/v2@latest
```

`TxCtr` and `RxLast` are exported so they can be persisted. Decrypt returns
`sdtmf.ErrRejected` on a bad frame.

## Test

```bash
make test
```

Or individually:

```bash
python3 python/test_sdtmf.py
node js/test.js
gcc -O2 -I c/src c/extras/test_sdtmf.c c/src/sdtmf.c c/src/sha256.c -o /tmp/test_sdtmf && /tmp/test_sdtmf
(cd go && go test)
```

## Publish

| Language | Directory | Registry | Command |
|---|---|---|---|
| Python | `python/` | PyPI | `python -m build && twine upload dist/*` |
| JavaScript | `js/` | npm | `npm publish` |
| Go | `go/` | pkg.go.dev | push tag `go/vX.Y.Z` alongside `vX.Y.Z` (`go get github.com/ndawinata/SDTMF/go/v2`) |
| C | `c/` | Arduino Library Manager, PlatformIO | tag a GitHub release, then submit `library.properties` |

Keep the package versions in lockstep with the spec version (`SDTMF-v2`).

## Citation

If you use SDTMF in your research, please cite it. The concept DOI
[10.5281/zenodo.23637663](https://doi.org/10.5281/zenodo.23637663) always
resolves to the latest release; v2.0.0 is
[10.5281/zenodo.23637664](https://doi.org/10.5281/zenodo.23637664).

```bibtex
@software{winata_sdtmf_2026,
  author    = {Winata, Nanda},
  title     = {{SDTMF}: Authenticated encryption for {DTMF} signaling},
  version   = {2.0.0},
  year      = {2026},
  publisher = {Zenodo},
  doi       = {10.5281/zenodo.23637664},
  url       = {https://github.com/ndawinata/SDTMF}
}
```

Citation metadata is also available in [`CITATION.cff`](CITATION.cff).
