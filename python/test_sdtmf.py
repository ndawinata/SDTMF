#!/usr/bin/env python3
"""Run official SDTMF v2 vectors against the Python reference."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from sdtmf import SecureDTMF, derive_keys

ROOT = Path(__file__).resolve().parent.parent
VEC = json.loads((ROOT / "test-vectors.json").read_text())
PW = VEC["password"]
D = VEC["defaults"]


def _eq(got, exp, label):
    if got != exp:
        print(f"FAIL {label}\n  got  {got!r}\n  exp  {exp!r}", file=sys.stderr)
        sys.exit(1)


def _cfg(row, key=PW):
    return SecureDTMF(
        key,
        ctr_tx=row["ctr_tx"],
        tag_len=row["tag_len"],
        start=row["start"],
        end=row["end"],
    )


def main() -> None:
    k_enc, k_mac = derive_keys(PW)
    _eq(k_enc.hex(), VEC["k_enc"], "k_enc")
    _eq(k_mac.hex(), VEC["k_mac"], "k_mac")

    ctx = SecureDTMF(PW)
    _eq((ctx.ctr_tx, ctx.tag_len, ctx.start, ctx.end),
        (D["ctr_tx"], D["tag_len"], D["start"], D["end"]), "defaults")
    _eq(ctx._ks(1, 10), VEC["keystream"]["ctr1_len10"], "KS(1,10)")
    _eq(ctx._ks(2, 10), VEC["keystream"]["ctr2_len10"], "KS(2,10)")
    _eq(ctx._ks(3, 16), VEC["keystream"]["ctr3_len16"], "KS(3,16)")

    tx = SecureDTMF(PW)
    for row in VEC["encrypt"]:
        _eq(tx.encrypt(row["msg"]), row["frame"], f"encrypt({row['msg']!r})")
        _eq(tx.tx_ctr, row["ctr"], f"tx_ctr after {row['msg']!r}")

    raw = SecureDTMF.from_keys(k_enc, k_mac)
    _eq(raw.encrypt(VEC["encrypt"][0]["msg"]), VEC["encrypt"][0]["frame"], "from_keys")

    rx = SecureDTMF(PW)
    for row in VEC["decrypt_ok"]:
        rx.rx_last = row["start_rx_last"]
        _eq(rx.decrypt(row["frame"]), row["msg"], f"decrypt {row['frame']}")
        _eq(rx.rx_last, row["end_rx_last"], f"rx_last after {row['frame']}")

    for row in VEC["decrypt_reject"]:
        rx = SecureDTMF(PW)
        rx.rx_last = row["start_rx_last"]
        _eq(rx.decrypt(row["frame"]), None, f"reject {row['reason']}")
        _eq(rx.rx_last, row["start_rx_last"], f"rx_last unchanged ({row['reason']})")

    wrong = SecureDTMF(VEC["wrong_password"])
    _eq(wrong.decrypt(VEC["wrong_password_reject_frame"]), None, "wrong password")

    wrap = VEC["counter_wrap"]
    tx = SecureDTMF(PW)
    tx.tx_ctr = wrap["start_tx_ctr"]
    _eq(tx.encrypt(wrap["msg"]), wrap["frame"], "wrap encrypt")
    _eq(tx.tx_ctr, wrap["end_tx_ctr"], "wrap tx_ctr")
    rx = SecureDTMF(PW)
    rx.rx_last = wrap["start_rx_last"]
    _eq(rx.decrypt(wrap["frame"]), wrap["msg"], "wrap decrypt")
    _eq(rx.rx_last, wrap["end_rx_last"], "wrap rx_last")

    for row in VEC["configs"]:
        label = f"config ctr_tx={row['ctr_tx']} tag_len={row['tag_len']} start={row['start']!r} end={row['end']!r}"
        tx = _cfg(row)
        _eq(tx.encrypt(row["msg"]), row["frame"], f"{label} frame")
        _eq(tx.encrypt(row["msg"]), row["frame2"], f"{label} frame2")
        _eq(tx.frame_len(len(row["msg"])), len(row["frame"]), f"{label} frame_len")
        rx = _cfg(row)
        _eq(rx.decrypt(row["frame"]), row["msg"], f"{label} decrypt")
        _eq(rx.decrypt(row["frame2"]), row["msg"], f"{label} decrypt2")
        _eq(rx.decrypt(row["frame"]), None, f"{label} replay")

    for row in VEC["config_reject"]:
        _eq(_cfg(row).decrypt(row["frame"]), None, f"config reject {row['reason']}")

    for row in VEC["invalid_configs"]:
        try:
            _cfg(row)
        except ValueError:
            continue
        _eq("accepted", "ValueError", f"invalid config {row['reason']}")

    print("python: all official vectors passed")


if __name__ == "__main__":
    main()
