"""SDTMF v2 — Secure DTMF frames. See SPEC.md."""

from __future__ import annotations

import hmac
import hashlib
from typing import Optional

ALPH = "0123456789ABCD"
B = len(ALPH)
IDX = {c: i for i, c in enumerate(ALPH)}
SALT = b"SDTMF-v2"
ITERS = 100_000

DEFAULT_CTR_TX = 2
DEFAULT_TAG_LEN = 6
DEFAULT_START = "*"
DEFAULT_END = "#"

__all__ = [
    "ALPH",
    "DEFAULT_CTR_TX",
    "DEFAULT_TAG_LEN",
    "DEFAULT_START",
    "DEFAULT_END",
    "derive_keys",
    "SecureDTMF",
]


def _to_sym(n: int, w: int) -> str:
    if w == 0:
        return ""
    chars = ["0"] * w
    for i in range(w - 1, -1, -1):
        n, r = divmod(n, B)
        chars[i] = ALPH[r]
    return "".join(chars)


def _to_int(s: str) -> int:
    n = 0
    for c in s:
        n = n * B + IDX[c]
    return n


def _check_marker(m: str, name: str) -> None:
    if not isinstance(m, str) or len(m) > 1 or (m and m in IDX):
        raise ValueError(f"{name} must be '' or one character outside 0-9 A-D")


def derive_keys(password: str) -> tuple[bytes, bytes]:
    master = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), SALT, ITERS)
    k_enc = hmac.new(master, b"enc", hashlib.sha256).digest()
    k_mac = hmac.new(master, b"mac", hashlib.sha256).digest()
    return k_enc, k_mac


class SecureDTMF:
    """
    Frame:  start  [ctr_tx]  [ciphertext]  [tag]  end
    tx_ctr and rx_last MUST be persisted across restarts.
    """

    def __init__(
        self,
        key: Optional[str] = None,
        ctr_tx: int = DEFAULT_CTR_TX,
        tag_len: int = DEFAULT_TAG_LEN,
        k_enc: Optional[bytes] = None,
        k_mac: Optional[bytes] = None,
        start: str = DEFAULT_START,
        end: str = DEFAULT_END,
    ):
        if not (0 <= ctr_tx <= 8 and 1 <= tag_len <= 8):
            raise ValueError("ctr_tx must be 0..8 and tag_len 1..8")
        _check_marker(start, "start")
        _check_marker(end, "end")
        if start and start == end:
            raise ValueError("start and end must differ")
        if k_enc is not None and k_mac is not None:
            if len(k_enc) != 32 or len(k_mac) != 32:
                raise ValueError("k_enc and k_mac must be 32 bytes")
            self.k_enc, self.k_mac = k_enc, k_mac
        elif key is not None:
            self.k_enc, self.k_mac = derive_keys(key)
        else:
            raise ValueError("provide key= or k_enc= and k_mac=")
        self.ctr_tx = ctr_tx
        self.tag_len = tag_len
        self.start = start
        self.end = end
        self.mod = B ** ctr_tx
        self.tag_mod = B ** tag_len
        self.tx_ctr = 0
        self.rx_last = -1

    @classmethod
    def from_keys(
        cls,
        k_enc: bytes,
        k_mac: bytes,
        ctr_tx: int = DEFAULT_CTR_TX,
        tag_len: int = DEFAULT_TAG_LEN,
        start: str = DEFAULT_START,
        end: str = DEFAULT_END,
    ) -> "SecureDTMF":
        return cls(
            k_enc=k_enc, k_mac=k_mac, ctr_tx=ctr_tx, tag_len=tag_len, start=start, end=end
        )

    def frame_len(self, msg_len: int) -> int:
        return len(self.start) + self.ctr_tx + msg_len + self.tag_len + len(self.end)

    def get_state(self) -> dict:
        return {"tx_ctr": self.tx_ctr, "rx_last": self.rx_last}

    def set_state(self, tx_ctr: int, rx_last: int) -> None:
        self.tx_ctr = int(tx_ctr)
        self.rx_last = int(rx_last)

    def _ks(self, ctr: int, n: int) -> list[int]:
        out: list[int] = []
        blk = 0
        while len(out) < n:
            d = hmac.new(
                self.k_enc,
                ctr.to_bytes(8, "big") + blk.to_bytes(2, "big"),
                hashlib.sha256,
            ).digest()
            out += [b % B for b in d if b < 252]
            blk += 1
        return out[:n]

    def _tag(self, ctr: int, ct: str) -> str:
        d = hmac.new(
            self.k_mac, ctr.to_bytes(8, "big") + ct.encode("ascii"), hashlib.sha256
        ).digest()
        r = 0
        m = self.tag_mod
        for b in d:
            r = (r * 256 + b) % m
        return _to_sym(r, self.tag_len)

    def encrypt(self, msg: str) -> str:
        if not msg or any(c not in IDX for c in msg):
            raise ValueError("message must be 1+ symbols from 0-9 A-D")
        self.tx_ctr += 1
        c = self.tx_ctr
        ct = "".join(
            ALPH[(IDX[m] + k) % B] for m, k in zip(msg, self._ks(c, len(msg)))
        )
        return (
            self.start
            + _to_sym(c % self.mod, self.ctr_tx)
            + ct
            + self._tag(c, ct)
            + self.end
        )

    def decrypt(self, frame: str) -> Optional[str]:
        ls, le = len(self.start), len(self.end)
        if (
            len(frame) < ls + le
            or not frame.startswith(self.start)
            or not frame.endswith(self.end)
        ):
            return None
        s = frame[ls : len(frame) - le]
        if any(ch not in IDX for ch in s) or len(s) <= self.ctr_tx + self.tag_len:
            return None
        low = _to_int(s[: self.ctr_tx])
        ct, tag = s[self.ctr_tx : -self.tag_len], s[-self.tag_len :]
        base = max(self.rx_last + 1, 1)
        c = base + ((low - base) % self.mod)
        if not hmac.compare_digest(tag, self._tag(c, ct)):
            return None
        self.rx_last = c
        return "".join(
            ALPH[(IDX[x] - k) % B] for x, k in zip(ct, self._ks(c, len(ct)))
        )
