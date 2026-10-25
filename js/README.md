# sdtmf

[![npm](https://img.shields.io/npm/v/sdtmf)](https://www.npmjs.com/package/sdtmf)
[![DOI](https://zenodo.org/badge/1432957615.svg)](https://doi.org/10.5281/zenodo.23637663)

Authenticated, replay-protected encryption for DTMF tone frames (SDTMF v2).

A sender turns a short message (`0-9A-D`) into a tone string such as
`*015D0857C1CB#`. A receiver with the same key recovers the message and rejects
replays, wrong keys, and flipped digits. The output uses only standard DTMF
keys, so any tone generator or decoder (e.g. MT8870) can carry it.

Frames are byte-for-byte compatible with the Python, C/Arduino, and Go
implementations in the [SDTMF repository](https://github.com/ndawinata/SDTMF).

## Install

```bash
npm install sdtmf
```

Node.js 14+, no dependencies. TypeScript definitions are included.

## Quick start

```js
const { SecureDTMF } = require("sdtmf");
// or: import { SecureDTMF } from "sdtmf";

const tx = new SecureDTMF("secret-key");   // sender
const rx = new SecureDTMF("secret-key");   // receiver

const frame = tx.encrypt("1234");          // "*015D0857C1CB#"
rx.decrypt(frame);                         // "1234"
rx.decrypt(frame);                         // null  (replay rejected)

const next = tx.encrypt("1234");           // "*0275D6549036#"  (different every time)
rx.decrypt(next);                          // "1234"

new SecureDTMF("wrong-key").decrypt(next); // null  (wrong key)
```

`decrypt` returns `null` for any frame that is forged, modified, replayed,
malformed, or encrypted with a different key. `encrypt` throws if the message
contains characters outside `0-9 A-D`.

## Frame format

```
start  counter  ciphertext  tag     end
  *       01       5D08    57C1CB   #      ->  *015D0857C1CB#
```

Frame length = `start + ctrTx + message length + tagLen + end`.

## Options

```js
const custom = new SecureDTMF("secret-key", {
  ctrTx: 1,     // counter symbols per frame, 0..8   (default 2)
  tagLen: 4,    // tag symbols per frame, 1..8       (default 6)
  start: "#",   // '' or one char outside 0-9 A-D    (default '*')
  end: "*",     // '' or one char outside 0-9 A-D    (default '#')
});

custom.encrypt("1234");   // "#15D08C1CB*"
custom.frameLen(4);       // 11
```

**Sender and receiver must use the same options.** They are not sent in the
frame; a mismatch makes every frame fail to decrypt.

| `ctrTx` / `tagLen` | Tones for a 4-char message | Forgery chance per attempt | Lost frames tolerated |
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

```js
const state = tx.getState();          // { txCtr: 2, rxLast: -1 }
// ...store state, then after a restart:
tx.setState(state.txCtr, state.rxLast);
```

## Raw keys

PBKDF2 (100,000 iterations) runs once in the constructor. To skip it, or to
share keys with a microcontroller, derive the two 32-byte keys once and reuse
them:

```js
const { SecureDTMF, deriveKeys } = require("sdtmf");

const { kEnc, kMac } = deriveKeys("secret-key");
const fast = SecureDTMF.fromKeys(kEnc, kMac, { tagLen: 8 });
```

## API

| Member | Description |
|---|---|
| `new SecureDTMF(password, options?)` | Create from a password. `new SecureDTMF(password, ctrTx, tagLen)` also works. |
| `SecureDTMF.fromKeys(kEnc, kMac, options?)` | Create from two 32-byte keys. |
| `encrypt(msg)` | Return the next frame for `msg`. |
| `decrypt(frame)` | Return the message, or `null` if the frame is rejected. |
| `frameLen(n)` | Frame length for an `n`-symbol message. |
| `getState()` / `setState(txCtr, rxLast)` | Read / restore the counters. |
| `deriveKeys(password)` | Return `{ kEnc, kMac }`. |
| `ALPH`, `DEFAULTS` | Payload alphabet and default options. |

## Security notes

- Built from standard primitives (PBKDF2-HMAC-SHA256, HMAC-SHA256, counter),
  but the construction has **not been independently audited**.
- Message length is visible from the frame length.
- Never share one key between two senders.
- Rate-limit failed frames on the receiver, especially with `tagLen` ≤ 4.
- Prefer a random 32-byte key over a short password.
- Encryption is not permitted on amateur radio bands.

## Links

- Specification: [SPEC.md](https://github.com/ndawinata/SDTMF/blob/main/SPEC.md)
- Test vectors: [test-vectors.json](https://github.com/ndawinata/SDTMF/blob/main/test-vectors.json)
- Other languages and full docs: [github.com/ndawinata/SDTMF](https://github.com/ndawinata/SDTMF)
- Cite: [10.5281/zenodo.23637663](https://doi.org/10.5281/zenodo.23637663)

## License

MIT
