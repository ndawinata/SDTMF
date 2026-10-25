# sdtmf

[![PyPI](https://img.shields.io/pypi/v/sdtmf)](https://pypi.org/project/sdtmf/)
[![DOI](https://zenodo.org/badge/1432957615.svg)](https://doi.org/10.5281/zenodo.23637663)

Authenticated, replay-protected encryption for DTMF tone frames (SDTMF v2).

A sender turns a short message (`0-9A-D`) into a tone string such as
`*015D0857C1CB#`. A receiver with the same key recovers the message and rejects
replays, wrong keys, and flipped digits. The output uses only standard DTMF
keys, so any tone generator or decoder (e.g. MT8870) can carry it.

Frames are byte-for-byte compatible with the JavaScript, C/Arduino, and Go
implementations in the [SDTMF repository](https://github.com/ndawinata/SDTMF).

## Install

```bash
pip install sdtmf
```

Python 3.8+, standard library only.

## Quick start

```python
from sdtmf import SecureDTMF

tx = SecureDTMF("secret-key")   # sender
rx = SecureDTMF("secret-key")   # receiver

frame = tx.encrypt("1234")      # '*015D0857C1CB#'
rx.decrypt(frame)               # '1234'
rx.decrypt(frame)               # None  (replay rejected)

nxt = tx.encrypt("1234")        # '*0275D6549036#'  (different every time)
rx.decrypt(nxt)                 # '1234'

SecureDTMF("wrong-key").decrypt(nxt)   # None  (wrong key)
```

`decrypt` returns `None` for any frame that is forged, modified, replayed,
malformed, or encrypted with a different key. `encrypt` raises `ValueError` if
the message contains characters outside `0-9 A-D`.

## Frame format

```
start  counter  ciphertext  tag     end
  *       01       5D08    57C1CB   #      ->  *015D0857C1CB#
```

Frame length = `start + ctr_tx + message length + tag_len + end`.

## Options

```python
custom = SecureDTMF(
    "secret-key",
    ctr_tx=1,     # counter symbols per frame, 0..8   (default 2)
    tag_len=4,    # tag symbols per frame, 1..8       (default 6)
    start="#",    # '' or one char outside 0-9 A-D    (default '*')
    end="*",      # '' or one char outside 0-9 A-D    (default '#')
)

custom.encrypt("1234")    # '#15D08C1CB*'
custom.frame_len(4)       # 11
```

**Sender and receiver must use the same options.** They are not sent in the
frame; a mismatch makes every frame fail to decrypt.

| `ctr_tx` / `tag_len` | Tones for a 4-char message | Forgery chance per attempt | Lost frames tolerated |
|---|---|---|---|
| 2 / 6 (default) | 14 | 1 in 7,529,536 | 195 |
| 2 / 8 | 16 | 1 in 1,475,789,056 | 195 |
| 2 / 4 | 12 | 1 in 38,416 | 195 |
| 1 / 4 | 11 | 1 in 38,416 | 13 |
| 0 / 4 | 10 | 1 in 38,416 | 0 |

## Persisting state

Each side keeps a counter. Save it after every `encrypt` / successful
`decrypt` and restore it on startup; otherwise old frames could be replayed
and the keystream would repeat.

```python
state = tx.get_state()        # {'tx_ctr': 2, 'rx_last': -1}
# ...store state, then after a restart:
tx.set_state(state["tx_ctr"], state["rx_last"])
```

## Raw keys

PBKDF2 (100,000 iterations) runs once in the constructor. To skip it, or to
share keys with a microcontroller, derive the two 32-byte keys once and reuse
them:

```python
from sdtmf import SecureDTMF, derive_keys

k_enc, k_mac = derive_keys("secret-key")
fast = SecureDTMF.from_keys(k_enc, k_mac, tag_len=8)
```

## API

| Member | Description |
|---|---|
| `SecureDTMF(key, ctr_tx=2, tag_len=6, start="*", end="#")` | Create from a password. |
| `SecureDTMF.from_keys(k_enc, k_mac, ...)` | Create from two 32-byte keys. |
| `encrypt(msg)` | Return the next frame for `msg`. |
| `decrypt(frame)` | Return the message, or `None` if the frame is rejected. |
| `frame_len(n)` | Frame length for an `n`-symbol message. |
| `get_state()` / `set_state(tx_ctr, rx_last)` | Read / restore the counters. |
| `derive_keys(password)` | Return `(k_enc, k_mac)`. |
| `ALPH`, `DEFAULT_*` | Payload alphabet and default options. |

## Security notes

- Built from standard primitives (PBKDF2-HMAC-SHA256, HMAC-SHA256, counter),
  but the construction has **not been independently audited**.
- Message length is visible from the frame length.
- Never share one key between two senders.
- Rate-limit failed frames on the receiver, especially with `tag_len` ≤ 4.
- Prefer a random 32-byte key over a short password.
- Encryption is not permitted on amateur radio bands.

## Links

- Specification: [SPEC.md](https://github.com/ndawinata/SDTMF/blob/main/SPEC.md)
- Test vectors: [test-vectors.json](https://github.com/ndawinata/SDTMF/blob/main/test-vectors.json)
- Other languages and full docs: [github.com/ndawinata/SDTMF](https://github.com/ndawinata/SDTMF)
- Cite: [10.5281/zenodo.23637663](https://doi.org/10.5281/zenodo.23637663)

## License

MIT
