#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const { SecureDTMF, deriveKeys } = require("./sdtmf");

const VEC = JSON.parse(
  fs.readFileSync(path.join(__dirname, "..", "test-vectors.json"), "utf8")
);
const PW = VEC.password;
const D = VEC.defaults;

function eq(got, exp, label) {
  const g = JSON.stringify(got);
  const e = JSON.stringify(exp);
  if (g !== e) {
    console.error(`FAIL ${label}\n  got  ${g}\n  exp  ${e}`);
    process.exit(1);
  }
}

function cfg(row, pw = PW) {
  return new SecureDTMF(pw, {
    ctrTx: row.ctr_tx,
    tagLen: row.tag_len,
    start: row.start,
    end: row.end,
  });
}

const { kEnc, kMac } = deriveKeys(PW);
eq(kEnc.toString("hex"), VEC.k_enc, "k_enc");
eq(kMac.toString("hex"), VEC.k_mac, "k_mac");

const ctx = new SecureDTMF(PW);
eq([ctx.ctrTx, ctx.tagLen, ctx.start, ctx.end], [D.ctr_tx, D.tag_len, D.start, D.end], "defaults");
eq(ctx._ks(1, 10), VEC.keystream.ctr1_len10, "KS(1,10)");
eq(ctx._ks(2, 10), VEC.keystream.ctr2_len10, "KS(2,10)");
eq(ctx._ks(3, 16), VEC.keystream.ctr3_len16, "KS(3,16)");

let tx = new SecureDTMF(PW);
for (const row of VEC.encrypt) {
  eq(tx.encrypt(row.msg), row.frame, `encrypt(${row.msg})`);
  eq(tx.txCtr, row.ctr, `tx_ctr after ${row.msg}`);
}

eq(SecureDTMF.fromKeys(kEnc, kMac).encrypt(VEC.encrypt[0].msg), VEC.encrypt[0].frame, "from_keys");

let rx = new SecureDTMF(PW);
for (const row of VEC.decrypt_ok) {
  rx.rxLast = row.start_rx_last;
  eq(rx.decrypt(row.frame), row.msg, `decrypt ${row.frame}`);
  eq(rx.rxLast, row.end_rx_last, `rx_last after ${row.frame}`);
}

for (const row of VEC.decrypt_reject) {
  rx = new SecureDTMF(PW);
  rx.rxLast = row.start_rx_last;
  eq(rx.decrypt(row.frame), null, `reject ${row.reason}`);
  eq(rx.rxLast, row.start_rx_last, `rx_last unchanged (${row.reason})`);
}

eq(new SecureDTMF(VEC.wrong_password).decrypt(VEC.wrong_password_reject_frame), null, "wrong password");

const wrap = VEC.counter_wrap;
tx = new SecureDTMF(PW);
tx.txCtr = wrap.start_tx_ctr;
eq(tx.encrypt(wrap.msg), wrap.frame, "wrap encrypt");
eq(tx.txCtr, wrap.end_tx_ctr, "wrap tx_ctr");
rx = new SecureDTMF(PW);
rx.rxLast = wrap.start_rx_last;
eq(rx.decrypt(wrap.frame), wrap.msg, "wrap decrypt");
eq(rx.rxLast, wrap.end_rx_last, "wrap rx_last");

for (const row of VEC.configs) {
  const label = `config ctr_tx=${row.ctr_tx} tag_len=${row.tag_len} start=${JSON.stringify(row.start)} end=${JSON.stringify(row.end)}`;
  tx = cfg(row);
  eq(tx.encrypt(row.msg), row.frame, `${label} frame`);
  eq(tx.encrypt(row.msg), row.frame2, `${label} frame2`);
  eq(tx.frameLen(row.msg.length), row.frame.length, `${label} frameLen`);
  rx = cfg(row);
  eq(rx.decrypt(row.frame), row.msg, `${label} decrypt`);
  eq(rx.decrypt(row.frame2), row.msg, `${label} decrypt2`);
  eq(rx.decrypt(row.frame), null, `${label} replay`);
}

const positional = new SecureDTMF(PW, 1, 4);
eq(positional.encrypt("1234"), VEC.configs[3].frame, "positional ctrTx/tagLen");

for (const row of VEC.config_reject) {
  eq(cfg(row).decrypt(row.frame), null, `config reject ${row.reason}`);
}

for (const row of VEC.invalid_configs) {
  let threw = false;
  try {
    cfg(row);
  } catch (_) {
    threw = true;
  }
  eq(threw, true, `invalid config ${row.reason}`);
}

console.log("javascript: all official vectors passed");
