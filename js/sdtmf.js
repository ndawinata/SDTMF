"use strict";

const crypto = require("crypto");

const ALPH = "0123456789ABCD";
const B = ALPH.length;
const IDX = Object.fromEntries([...ALPH].map((c, i) => [c, i]));
const SALT = Buffer.from("SDTMF-v2", "ascii");
const ITERS = 100000;

const DEFAULTS = Object.freeze({ ctrTx: 2, tagLen: 6, start: "*", end: "#" });

function toSym(n, w) {
  let s = "";
  n = Number(n);
  for (let i = 0; i < w; i++) {
    s = ALPH[n % B] + s;
    n = Math.floor(n / B);
  }
  return s;
}

function toInt(s) {
  let n = 0;
  for (const c of s) n = n * B + IDX[c];
  return n;
}

function writeCtrBlk(buf, ctr, blk) {
  buf.writeBigUInt64BE(BigInt(ctr), 0);
  buf.writeUInt16BE(blk, 8);
}

function invalidMsg(msg) {
  if (!msg) return true;
  for (let i = 0; i < msg.length; i++) if (!(msg[i] in IDX)) return true;
  return false;
}

function checkMarker(m, name) {
  if (typeof m !== "string" || m.length > 1 || (m && m in IDX)) {
    throw new Error(`${name} must be '' or one character outside 0-9 A-D`);
  }
}

function deriveKeys(password) {
  const master = crypto.pbkdf2Sync(password, SALT, ITERS, 32, "sha256");
  const kEnc = crypto.createHmac("sha256", master).update("enc", "ascii").digest();
  const kMac = crypto.createHmac("sha256", master).update("mac", "ascii").digest();
  return { kEnc, kMac };
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a, "ascii"), Buffer.from(b, "ascii"));
}

function normalizeOptions(a, b, c) {
  if (typeof a === "number") {
    return { ctrTx: a, tagLen: b === undefined ? DEFAULTS.tagLen : b, ...(c || {}) };
  }
  return { ...(a || {}) };
}

class SecureDTMF {
  /**
   * new SecureDTMF(password, { ctrTx, tagLen, start, end })
   * new SecureDTMF(null, { kEnc, kMac, ... })
   * new SecureDTMF(password, ctrTx, tagLen)   // positional form
   */
  constructor(password, a, b, c) {
    const o = { ...DEFAULTS, ...normalizeOptions(a, b, c) };
    const { ctrTx, tagLen, start, end } = o;
    if (!(Number.isInteger(ctrTx) && ctrTx >= 0 && ctrTx <= 8 &&
          Number.isInteger(tagLen) && tagLen >= 1 && tagLen <= 8)) {
      throw new Error("ctr_tx must be 0..8 and tag_len 1..8");
    }
    checkMarker(start, "start");
    checkMarker(end, "end");
    if (start && start === end) throw new Error("start and end must differ");

    if (o.kEnc && o.kMac) {
      this.kEnc = Buffer.from(o.kEnc);
      this.kMac = Buffer.from(o.kMac);
      if (this.kEnc.length !== 32 || this.kMac.length !== 32) {
        throw new Error("k_enc and k_mac must be 32 bytes");
      }
    } else if (typeof password === "string") {
      const k = deriveKeys(password);
      this.kEnc = k.kEnc;
      this.kMac = k.kMac;
    } else {
      throw new Error("provide password or kEnc/kMac");
    }
    this.ctrTx = ctrTx;
    this.tagLen = tagLen;
    this.start = start;
    this.end = end;
    this.mod = B ** ctrTx;
    this.tagMod = 14n ** BigInt(tagLen);
    this._ctrBlk = Buffer.alloc(10);
    this.txCtr = 0;
    this.rxLast = -1;
  }

  static fromKeys(kEnc, kMac, a, b) {
    return new SecureDTMF(null, { ...normalizeOptions(a, b), kEnc, kMac });
  }

  frameLen(msgLen) {
    return this.start.length + this.ctrTx + msgLen + this.tagLen + this.end.length;
  }

  getState() {
    return { txCtr: this.txCtr, rxLast: this.rxLast };
  }

  setState(txCtr, rxLast) {
    this.txCtr = Number(txCtr);
    this.rxLast = Number(rxLast);
  }

  _ks(ctr, n) {
    const out = new Array(n);
    let have = 0;
    let blk = 0;
    const buf = this._ctrBlk;
    while (have < n) {
      writeCtrBlk(buf, ctr, blk);
      const d = crypto.createHmac("sha256", this.kEnc).update(buf).digest();
      for (let i = 0; i < 32 && have < n; i++) {
        if (d[i] < 252) out[have++] = d[i] % B;
      }
      blk += 1;
    }
    return out;
  }

  _tag(ctr, ct) {
    writeCtrBlk(this._ctrBlk, ctr, 0);
    const d = crypto
      .createHmac("sha256", this.kMac)
      .update(this._ctrBlk.subarray(0, 8))
      .update(ct, "ascii")
      .digest();
    let r = 0n;
    for (let i = 0; i < 32; i++) r = (r * 256n + BigInt(d[i])) % this.tagMod;
    return toSym(r, this.tagLen);
  }

  encrypt(msg) {
    if (invalidMsg(msg)) {
      throw new Error("message must be 1+ symbols from 0-9 A-D");
    }
    this.txCtr += 1;
    const c = this.txCtr;
    const ks = this._ks(c, msg.length);
    let ct = "";
    for (let i = 0; i < msg.length; i++) {
      ct += ALPH[(IDX[msg[i]] + ks[i]) % B];
    }
    return this.start + toSym(c % this.mod, this.ctrTx) + ct + this._tag(c, ct) + this.end;
  }

  decrypt(frame) {
    const ls = this.start.length;
    const le = this.end.length;
    if (typeof frame !== "string" || frame.length < ls + le ||
        !frame.startsWith(this.start) || !frame.endsWith(this.end)) {
      return null;
    }
    const s = frame.slice(ls, frame.length - le);
    if (s.length <= this.ctrTx + this.tagLen || invalidMsg(s)) {
      return null;
    }
    const low = toInt(s.slice(0, this.ctrTx));
    const ct = s.slice(this.ctrTx, s.length - this.tagLen);
    const tag = s.slice(s.length - this.tagLen);
    const base = Math.max(this.rxLast + 1, 1);
    let rem = (low - base) % this.mod;
    if (rem < 0) rem += this.mod;
    const c = base + rem;
    if (!safeEqual(tag, this._tag(c, ct))) return null;
    this.rxLast = c;
    const ks = this._ks(c, ct.length);
    let msg = "";
    for (let i = 0; i < ct.length; i++) {
      msg += ALPH[(IDX[ct[i]] - ks[i] + B) % B];
    }
    return msg;
  }
}

module.exports = { SecureDTMF, deriveKeys, ALPH, DEFAULTS };
