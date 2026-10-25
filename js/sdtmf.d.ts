export const ALPH: string;

export const DEFAULTS: Readonly<{
  ctrTx: 2;
  tagLen: 6;
  start: "*";
  end: "#";
}>;

export interface SecureDTMFOptions {
  /** Counter symbols sent per frame, 0..8. Default 2. */
  ctrTx?: number;
  /** Tag symbols per frame, 1..8. Default 6. */
  tagLen?: number;
  /** Frame start marker: '' or one char outside 0-9 A-D. Default '*'. */
  start?: string;
  /** Frame end marker: '' or one char outside 0-9 A-D. Default '#'. */
  end?: string;
  kEnc?: Buffer | Uint8Array;
  kMac?: Buffer | Uint8Array;
}

export function deriveKeys(password: string): { kEnc: Buffer; kMac: Buffer };

export class SecureDTMF {
  readonly kEnc: Buffer;
  readonly kMac: Buffer;
  readonly ctrTx: number;
  readonly tagLen: number;
  readonly start: string;
  readonly end: string;
  readonly mod: number;
  txCtr: number;
  rxLast: number;

  constructor(password: string | null, options?: SecureDTMFOptions);
  constructor(password: string | null, ctrTx: number, tagLen?: number, options?: SecureDTMFOptions);

  static fromKeys(
    kEnc: Buffer | Uint8Array,
    kMac: Buffer | Uint8Array,
    options?: Omit<SecureDTMFOptions, "kEnc" | "kMac">
  ): SecureDTMF;
  static fromKeys(
    kEnc: Buffer | Uint8Array,
    kMac: Buffer | Uint8Array,
    ctrTx: number,
    tagLen?: number
  ): SecureDTMF;

  frameLen(msgLen: number): number;
  getState(): { txCtr: number; rxLast: number };
  setState(txCtr: number, rxLast: number): void;
  encrypt(msg: string): string;
  decrypt(frame: string): string | null;
}
