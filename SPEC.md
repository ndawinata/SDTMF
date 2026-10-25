# SDTMF v2 — Secure DTMF Frames

Canonical specification for interoperable implementations. The machine-readable
test suite is [`test-vectors.json`](test-vectors.json). A correct implementation
MUST produce every `encrypt` and `configs` frame byte-for-byte, MUST reject
every `decrypt_reject` and `config_reject` case, and MUST refuse every
`invalid_configs` entry.

This is a custom construction built from PBKDF2-HMAC-SHA256, HMAC-SHA256, and
a bias-free counter keystream over a 14-symbol alphabet. It has not been
formally audited. Do not use a single password/key for more than one sender:
reused counters leak the keystream.

Reference implementations in this repository: Python (`python/`), JavaScript
(`js/`), C / Arduino (`c/`), and Go (`go/`).

## 1. Alphabet, frame, and parameters

```
ALPH  = "0123456789ABCD"     # 14 symbols, index 0..13
B     = 14
```

```
frame = START  ||  CTR  ||  CT  ||  TAG  ||  END
```

| Field | Width | Content |
|---|---|---|
| START | 0 or 1 char | frame start marker (default `*`) |
| CTR | `ctr_tx` symbols | `c mod B^ctr_tx` encoded in base-`B`, left-padded with `'0'` |
| CT | `n` symbols | ciphertext, same length as the plaintext |
| TAG | `tag_len` symbols | truncated HMAC over the full counter and CT |
| END | 0 or 1 char | frame end marker (default `#`) |

### Parameters

| Parameter | Range | Default |
|---|---|---|
| `ctr_tx` | `0..8` | `2` |
| `tag_len` | `1..8` | `6` |
| `start` | empty, or one character not in `ALPH` | `*` |
| `end` | empty, or one character not in `ALPH`, different from `start` | `#` |

Implementations MUST reject out-of-range parameters at construction time.
Parameters are **not** transmitted; both ends of a conversation MUST be
configured identically. A mismatch is indistinguishable from a wrong key: every
frame is rejected.

Markers are framing only. They are not covered by the tag, so they carry no
security weight. On a pure DTMF channel the only non-`ALPH` keys are `*` and
`#`, so the useful choices there are `*…#` (default), `#…*`, one marker, or
none. Other characters (for example `<` and `>`) are allowed for non-audio
transports.

With an empty `end`, the receiver must find the frame boundary another way:
a fixed message length or a silence timeout.

Frame length:

```
len(frame) = len(start) + ctr_tx + n + tag_len + len(end)
```

## 2. Integer encoding

`to_sym(n, w)` writes the integer `n` as exactly `w` symbols of `ALPH`, most
significant symbol first (left-padded with `'0'`). `w = 0` yields the empty
string.

`to_int(s)` reads a base-`B` integer from symbols in `ALPH`. The empty string
is `0`.

All multi-byte integers fed to HMAC are **big-endian**:

- `uint64_BE(c)` — 8 bytes
- `uint16_BE(blk)` — 2 bytes

## 3. Key schedule

Password is UTF-8. Salt is the 8 ASCII bytes `SDTMF-v2`.

```
master = PBKDF2-HMAC-SHA256(password, salt="SDTMF-v2", iters=100000, dkLen=32)
k_enc  = HMAC-SHA256(master, "enc")     # 3 ASCII bytes, no NUL
k_mac  = HMAC-SHA256(master, "mac")     # 3 ASCII bytes, no NUL
```

An implementation MAY skip PBKDF2 and accept `k_enc` / `k_mac` directly
(recommended on 8-bit AVR, where 100 000 iterations are impractical). The
32+32 raw bytes are equivalent to the password mode.

## 4. Keystream

`KS(c, n)` produces `n` integers in `0..13` from the **full** 64-bit counter
`c`, without modular bias:

```
out = []
blk = 0
while len(out) < n:
    d = HMAC-SHA256(k_enc, uint64_BE(c) || uint16_BE(blk))   # 32 bytes
    for each byte b in d:
        if b < 252:                 # 252 = 18 * 14
            out.append(b mod 14)
    blk = blk + 1
return out[:n]
```

## 5. Tag

```
d = HMAC-SHA256(k_mac, uint64_BE(c) || CT_ascii)
t = (d as 256-bit big-endian integer)  mod  B^tag_len
TAG = to_sym(t, tag_len)
```

On platforms without 256-bit integers, reduce one byte at a time (this is
congruent to the big-integer form):

```
r = 0
for b in d:                         # d[0] is the most significant byte
    r = (r * 256 + b) mod B^tag_len
```

A consequence of this construction: a shorter tag is the low-order suffix of a
longer one for the same counter and ciphertext (`tag_len=3` → `1CB`,
`tag_len=6` → `57C1CB`). This is expected.

## 6. Encrypt

Input: plaintext `M` of length `n ≥ 1`, every symbol in `ALPH`.

```
tx_ctr = tx_ctr + 1                 # stored permanently (EEPROM / file)
c      = tx_ctr
K      = KS(c, n)
CT[i]  = ALPH[ (IDX[M[i]] + K[i]) mod 14 ]
frame  = START || to_sym(c mod B^ctr_tx, ctr_tx) || CT || TAG(c, CT) || END
```

`tx_ctr` starts at `0`, so the first frame uses `c = 1`. Counter `0` is never
sent. Reject empty messages and any symbol outside `ALPH`.

## 7. Decrypt

Input: a candidate frame. Output: plaintext, or reject.

1. Reject unless the frame begins with `START` and ends with `END`
   (an empty marker always matches) and is at least `len(START)+len(END)` long.
2. Let `s` be the frame without the markers. Reject if any character of `s`
   is outside `ALPH`, or if `len(s) ≤ ctr_tx + tag_len` (empty ciphertext).
3. `low = to_int(s[:ctr_tx])`
4. `CT  = s[ctr_tx : -tag_len]`
5. `TAG = s[-tag_len:]`
6. Reconstruct the full counter. Let

   ```
   base = max(rx_last + 1, 1)
   mod  = B^ctr_tx
   c    = base + ((low - base) mod mod)
   ```

   The modulo is the **mathematical** non-negative remainder
   (`(-195) mod 196 = 1`). `rx_last` starts at `-1`. The `max(…, 1)` makes
   `ctr_tx = 0` work (the first frame is `c = 1`).
7. Compute `TAG' = TAG(c, CT)`. Compare with `TAG` in constant time.
   Reject on mismatch (wrong key, bit flip, wrong parameters, or replay).
8. `rx_last = c` (store permanently).
9. `M[i] = ALPH[ (IDX[CT[i]] - KS(c, n)[i]) mod 14 ]`

A rejected frame MUST leave `rx_last` unchanged.

## 8. Persistent state

`tx_ctr` and `rx_last` are part of the cryptographic state. Reloading a process
or MCU with both values reset reuses keystream and disables replay protection.
Implementations MUST expose load/store of this pair.

One password MUST NOT be shared by two independent senders.

## 9. Choosing parameters

| `tag_len` | Forgery chance per guess |
|---|---|
| 3 | 1 / 2 744 |
| 4 | 1 / 38 416 |
| 5 | 1 / 537 824 |
| 6 (default) | 1 / 7 529 536 |
| 8 | 1 / 1 475 789 056 |

| `ctr_tx` | Lost frames in a row the receiver can skip |
|---|---|
| 0 | 0 — any lost frame desynchronises the receiver |
| 1 | 13 |
| 2 (default) | 195 |
| 3 | 2 743 |

Rate-limit failed tags on the receiver regardless of `tag_len`. Frame length
reveals plaintext length.

## 10. Official test vectors

Password `secret-key` (UTF-8), defaults `ctr_tx=2`, `tag_len=6`, `start='*'`,
`end='#'`.

```
master = a09254a780126ad91ed1c6b3cbe80812a4180e2ed4feac9d35f7cdacf45fad70
k_enc  = 3dbd84b492f20d876117a7fb104d882ca4cb0287cf52dec365a0103858309c8e
k_mac  = 7412b7af5f0a104565db40baa142ad586db1654042ebddcfcc487e80d5442189

KS(1, 10) = [4, 11, 11, 4, 10, 5, 8, 13, 3, 12]

encrypt("1")              -> *01505D531#
encrypt("12AB")           -> *02756DCB16BD#
encrypt("0123456789ABCD") -> *0347DAB1CC3B814D5113B5#

tx_ctr pre-set to 195, encrypt("A") -> *00030C76C#
  (full c = 196, 196 mod 196 = 0 → CTR "00")
```

A receiver with `rx_last = 195` MUST decrypt `*00030C76C#` to `"A"` and set
`rx_last = 196`. A receiver with `rx_last = 196` MUST reject it (replay).

### Parameter matrix

First frame (`c = 1`) for message `"1234"` from a fresh sender:

| `ctr_tx` | `tag_len` | `start` | `end` | Frame | Length |
|---|---|---|---|---|---|
| 2 | 6 | `*` | `#` | `*015D0857C1CB#` | 14 |
| 2 | 3 | `*` | `#` | `*015D081CB#` | 11 |
| 2 | 4 | `*` | `#` | `*015D08C1CB#` | 12 |
| 1 | 4 | `*` | `#` | `*15D08C1CB#` | 11 |
| 0 | 4 | `*` | `#` | `*5D08C1CB#` | 10 |
| 2 | 8 | `*` | `#` | `*015D085B57C1CB#` | 16 |
| 3 | 6 | `*` | `#` | `*0015D0857C1CB#` | 15 |
| 2 | 6 | `#` | `*` | `#015D0857C1CB*` | 14 |
| 2 | 6 | (none) | (none) | `015D0857C1CB` | 12 |
| 1 | 4 | `*` | (none) | `*15D08C1CB` | 10 |
| 2 | 6 | `<` | `>` | `<015D0857C1CB>` | 14 |

The second frame (`c = 2`) for each row is in `test-vectors.json` as `frame2`.

## 11. Versioning

The salt `SDTMF-v2` is the protocol identifier. Changing `ctr_tx`, `tag_len`,
or markers does not change the protocol version. A future incompatible change
to the key schedule, keystream, or tag MUST bump the version (new salt, new
test vectors).
