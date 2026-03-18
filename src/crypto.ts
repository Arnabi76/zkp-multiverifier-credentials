import {
  generateBls12381G2KeyPair,
  blsSign, blsVerify,
  blsCreateProof, blsVerifyProof,
} from '@mattrglobal/bbs-signatures';
import { createHash, createHmac, randomBytes } from 'crypto';
import { bls12_381 } from '@noble/curves/bls12-381.js';

const { ml_dsa65 } = require('@noble/post-quantum/ml-dsa.js');

const CURVE_ORDER = bls12_381.fields.Fr.ORDER;

export async function generateBbsKeyPair() {
  const kp = await generateBls12381G2KeyPair();
  return { publicKey: kp.publicKey, secretKey: kp.secretKey };
}

export function generateDilithiumKeyPair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const seed = randomBytes(32);
  const kp = ml_dsa65.keygen(seed);
  return { publicKey: kp.publicKey, secretKey: kp.secretKey };
}

export function encodeAttributesToMessages(attrs: {
  attr_1: string; attr_2: number; attr_3: number;
  attr_4: boolean; attr_5: string; credentialId: string;
  issuanceDate: string; revocationIndex: number;
  pseudonymKeyCommitment: string;
}): Uint8Array[] {
  const enc = new TextEncoder();
  return [
    enc.encode(`attr_1:${attrs.attr_1}`),
    enc.encode(`attr_2:${attrs.attr_2}`),
    enc.encode(`attr_3:${attrs.attr_3}`),
    enc.encode(`attr_4:${attrs.attr_4}`),
    enc.encode(`attr_5:${attrs.attr_5}`),
    enc.encode(`credentialId:${attrs.credentialId}`),
    enc.encode(`issuanceDate:${attrs.issuanceDate}`),
    enc.encode(`revocationIndex:${attrs.revocationIndex}`),
    enc.encode(`pseudonymKeyCommitment:${attrs.pseudonymKeyCommitment}`),
  ];
}

export const ATTRIBUTE_INDEX: Record<string, number> = {
  attr_1: 0, attr_2: 1, attr_3: 2, attr_4: 3,
  attr_5: 4, credentialId: 5, issuanceDate: 6,
  revocationIndex: 7, pseudonymKeyCommitment: 8,
};
export const TOTAL_MESSAGE_COUNT = 9;

export function computeCredentialRoot(messages: Uint8Array[]): string {
  const hash = createHash('sha256');
  for (const msg of messages) hash.update(msg);
  return hash.digest('hex');
}

export function computeDilithiumBinding(
  bbsPublicKey: Uint8Array,
  issuerDid: string,
  credentialRoot: string,
  issuanceDate: string
): Uint8Array {
  return new Uint8Array(
    createHash('sha256')
      .update(bbsPublicKey)
      .update(issuerDid)
      .update(credentialRoot)
      .update(issuanceDate)
      .digest()
  );
}

export function deriveNonce(
  revocationIndex: string,
  requestedAttributes: string[],
  predicates: { attribute: string; operation: string; threshold: string | number | boolean }[],
  verifierId: string,
  timestamp: string,
  proofSalt: string
): string {
  return createHash('sha256')
    .update(revocationIndex)
    .update(requestedAttributes.slice().sort().join(','))
    .update(predicates.map(p => `${p.attribute}${p.operation}${p.threshold}`).sort().join(','))
    .update(verifierId)
    .update(timestamp)
    .update(proofSalt)
    .digest('hex');
}

function bufferToScalar(keyBuf: Buffer): bigint {
  const k = BigInt('0x' + keyBuf.toString('hex')) % CURVE_ORDER;
  return k === 0n ? 1n : k;
}

export function derivePseudonymKeyCommitment(holderPseudonymKey: Buffer): string {
  const k = bufferToScalar(holderPseudonymKey);
  const C = bls12_381.G1.Point.BASE.multiply(k);
  return Buffer.from(C.toBytes(true)).toString('hex');
}

export function derivePseudonym(holderPseudonymKey: Buffer, verifierId: string): string {
  return createHmac('sha256', holderPseudonymKey).update(verifierId).digest('hex');
}


export function generatePseudonymProof(
  holderPseudonymKey: Buffer,
  verifierId: string,
  pseudonym: string,
  pseudonymKeyCommitment: string,
  nonce: string
): Uint8Array {
  const G = bls12_381.G1.Point.BASE;
  const Fr = bls12_381.fields.Fr;

  const k = bufferToScalar(holderPseudonymKey);

  let r = Fr.create(0n);
  while (r === 0n) {
    r = Fr.create(BigInt('0x' + randomBytes(32).toString('hex')));
  }

  const R = G.multiply(r);
  const R_bytes = R.toBytes(true);

  const eHash = createHash('sha256')
    .update(R_bytes)
    .update(Buffer.from(pseudonymKeyCommitment, 'hex'))
    .update(pseudonym)
    .update(nonce)
    .update(verifierId)
    .digest();
  const e = Fr.create(BigInt('0x' + eHash.toString('hex')));

  const kScalar = Fr.create(k);
  const s = Fr.add(r, Fr.mul(e, kScalar));

  const s_bytes = Buffer.from(s.toString(16).padStart(64, '0'), 'hex');

  return new Uint8Array(Buffer.concat([Buffer.from(R_bytes), s_bytes]));
}

export function verifyPseudonymProof(
  pseudonym: string,
  pseudonymKeyCommitment: string,
  verifierId: string,
  proof: Uint8Array,
  nonce: string
): boolean {
  if (proof.length !== 80) return false;

  try {
    const G = bls12_381.G1.Point;
    const Fr = bls12_381.fields.Fr;

    const R_bytes = proof.slice(0, 48);
    const s_bytes = proof.slice(48, 80);

    const R = G.fromHex(Buffer.from(R_bytes).toString('hex'));
    const C = G.fromHex(pseudonymKeyCommitment);

    const s = Fr.create(BigInt('0x' + Buffer.from(s_bytes).toString('hex')));

    const eHash = createHash('sha256')
      .update(R_bytes)
      .update(Buffer.from(pseudonymKeyCommitment, 'hex'))
      .update(pseudonym)
      .update(nonce)
      .update(verifierId)
      .digest();
    const e = Fr.create(BigInt('0x' + eHash.toString('hex')));

    if (s === 0n || e === 0n) return false;
    const lhs = G.BASE.multiply(s);
    const rhs = R.add(C.multiply(e));

    return lhs.equals(rhs);
  } catch {
    return false;
  }
}


export async function bbsSign(
  messages: Uint8Array[], secretKey: Uint8Array, publicKey: Uint8Array
): Promise<Uint8Array> {
  return blsSign({ keyPair: { secretKey, publicKey }, messages });
}

export async function bbsVerifySignature(
  messages: Uint8Array[], signature: Uint8Array, publicKey: Uint8Array
): Promise<boolean> {
  const r = await blsVerify({ publicKey, messages, signature });
  return r.verified;
}

export function dilithiumSign(message: string | Uint8Array, secretKey: Uint8Array): Uint8Array {
  const msg = typeof message === 'string' ? new TextEncoder().encode(message) : message;
  return ml_dsa65.sign(msg, secretKey);
}

export function dilithiumVerify(
  message: string | Uint8Array, signature: Uint8Array, publicKey: Uint8Array
): boolean {
  const msg = typeof message === 'string' ? new TextEncoder().encode(message) : message;
  try { return ml_dsa65.verify(signature, msg, publicKey); }
  catch { return false; }
}

export async function createSelectiveDisclosureProof(
  signature: Uint8Array, messages: Uint8Array[],
  revealedIndices: number[], publicKey: Uint8Array, nonce: string
): Promise<Uint8Array> {
  return blsCreateProof({
    signature, publicKey, messages,
    nonce: new TextEncoder().encode(nonce),
    revealed: revealedIndices,
  });
}

export async function verifySelectiveDisclosureProof(
  proof: Uint8Array,
  revealedMessages: { index: number; value: Uint8Array }[],
  publicKey: Uint8Array, nonce: string
): Promise<boolean> {
  const r = await blsVerifyProof({
    proof, publicKey,
    messages: revealedMessages.map(m => m.value),
    nonce: new TextEncoder().encode(nonce),
  });
  return r.verified;
}

const RANGE_BITS = 32;

const RANGE_H = bls12_381.G1.hashToCurve(
  Buffer.from('zkp-range-proof-H-generator-bls12381-v1')
);

function _safeG1Mul(P: any, s: bigint): any {
  if (s === 0n) return bls12_381.G1.Point.ZERO;
  return P.multiply(bls12_381.fields.Fr.create(s));
}

function _pedersenCommit(v: bigint, r: bigint) {
  return _safeG1Mul(bls12_381.G1.Point.BASE, v).add(_safeG1Mul(RANGE_H, r));
}

function _pointToHex(P: any): string {
  return Buffer.from(P.toBytes(true)).toString('hex');
}

function _fsHash(ctx: string, ...hexPoints: string[]): bigint {
  const Fr = bls12_381.fields.Fr;
  const h = createHash('sha256').update(ctx);
  for (const p of hexPoints) h.update(Buffer.from(p, 'hex'));
  return Fr.create(BigInt('0x' + h.digest('hex')));
}

function _rndFr(): bigint {
  return bls12_381.fields.Fr.create(BigInt('0x' + randomBytes(32).toString('hex')));
}

export interface BitProof {
  C: string;   
  c0: string;  
  c1: string;  
  s0: string;  
  s1: string;  
}

export interface RangeProof {
  C_witness: string;   
  bitProofs: BitProof[];
  operation: string;
  threshold: number;
}

function _scalarToHex(s: bigint): string 
{
  return s.toString(16).padStart(64, '0');
}

function _hexToScalar(h: string): bigint 
{
  return bls12_381.fields.Fr.create(BigInt('0x' + h));
}

/** Generate a ZK OR-proof that bit b ∈ {0, 1} for Pedersen commitment C_i = b·G + r·H */
function _proveOneBit(bit: bigint, r: bigint, ctx: string): BitProof {
  const Fr = bls12_381.fields.Fr;
  const G = bls12_381.G1.Point.BASE;

  const Ci = _pedersenCommit(bit, r);
  const CiHex = _pointToHex(Ci);
  const CiMinusG = Ci.add(G.negate());

  if (bit === 0n) {
    const t = _rndFr();
    const R0 = _safeG1Mul(RANGE_H, t);
    const c1 = _rndFr(), s1 = _rndFr();
    const R1 = _safeG1Mul(RANGE_H, s1).add(_safeG1Mul(CiMinusG, Fr.neg(c1)));
    const c = _fsHash(ctx, CiHex, _pointToHex(R0), _pointToHex(R1));
    const c0 = Fr.sub(c, c1);
    const s0 = Fr.add(t, Fr.mul(c0, r));
    return { C: CiHex, c0: _scalarToHex(c0), c1: _scalarToHex(c1), s0: _scalarToHex(s0), s1: _scalarToHex(s1) };
  } else {
    const t = _rndFr();
    const R1 = _safeG1Mul(RANGE_H, t);
    const c0 = _rndFr(), s0 = _rndFr();
    const R0 = _safeG1Mul(RANGE_H, s0).add(_safeG1Mul(Ci, Fr.neg(c0)));
    const c = _fsHash(ctx, CiHex, _pointToHex(R0), _pointToHex(R1));
    const c1 = Fr.sub(c, c0);
    const s1 = Fr.add(t, Fr.mul(c1, r));
    return { C: CiHex, c0: _scalarToHex(c0), c1: _scalarToHex(c1), s0: _scalarToHex(s0), s1: _scalarToHex(s1) };
  }
}

function _verifyOneBit(proof: BitProof, ctx: string): boolean {
  try {
    const Fr = bls12_381.fields.Fr;
    const G = bls12_381.G1.Point;
    const Ci = G.fromHex(proof.C);
    const CiMinusG = Ci.add(bls12_381.G1.Point.BASE.negate());
    const c0 = _hexToScalar(proof.c0);
    const c1 = _hexToScalar(proof.c1);
    const s0 = _hexToScalar(proof.s0);
    const s1 = _hexToScalar(proof.s1);
    const R0 = _safeG1Mul(RANGE_H, s0).add(_safeG1Mul(Ci, Fr.neg(c0)));
    const R1 = _safeG1Mul(RANGE_H, s1).add(_safeG1Mul(CiMinusG, Fr.neg(c1)));
    const c = _fsHash(ctx, proof.C, _pointToHex(R0), _pointToHex(R1));
    return Fr.add(c0, c1) === c;
  } catch { return false; }
}


export function generateRangeProof(
  v: number,
  operation: '>' | '>=' | '<' | '<=' | '==' | '!=',
  threshold: number,
  nonce: string
): RangeProof | null {
  const Fr = bls12_381.fields.Fr;
  const vBig = BigInt(v);
  const tBig = BigInt(threshold);

  let witness: bigint;
  if      (operation === '>' ) witness = vBig - tBig - 1n;
  else if (operation === '>=') witness = vBig - tBig;
  else if (operation === '<' ) witness = tBig - vBig - 1n;
  else if (operation === '<=') witness = tBig - vBig;
  else return null; 

  if (witness < 0n || witness >= (1n << BigInt(RANGE_BITS))) return null; 

  const r_witness = _rndFr();
  const C_witness = _pedersenCommit(witness, r_witness);

  const bits: bigint[] = Array.from({ length: RANGE_BITS }, (_, i) => (witness >> BigInt(i)) & 1n);

  const bitBlinds: bigint[] = Array.from({ length: RANGE_BITS - 1 }, () => _rndFr());
  const wPartial = bitBlinds.reduce((acc, r, i) => Fr.add(acc, Fr.mul(r, 1n << BigInt(i))), 0n);
  const lastBlind = Fr.mul(
    Fr.sub(r_witness, wPartial),
    Fr.inv(Fr.create(1n << BigInt(RANGE_BITS - 1)))
  );
  bitBlinds.push(lastBlind);


  const ctx = createHash('sha256')
    .update(nonce).update(operation).update(threshold.toString()).digest('hex');

  const bitProofs = bits.map((b, i) => _proveOneBit(b, bitBlinds[i], ctx + i.toString(16)));

  return {
    C_witness: _pointToHex(C_witness),
    bitProofs,
    operation,
    threshold,
  };
}

export function verifyRangeProof(proof: RangeProof, nonce: string): boolean {
  try {
    if (proof.bitProofs.length !== RANGE_BITS) return false;

    const ctx = createHash('sha256')
      .update(nonce).update(proof.operation).update(proof.threshold.toString()).digest('hex');

    for (let i = 0; i < RANGE_BITS; i++) {
      if (!_verifyOneBit(proof.bitProofs[i], ctx + i.toString(16))) return false;
    }

    let recon = bls12_381.G1.Point.ZERO;
    for (let i = 0; i < RANGE_BITS; i++) 
    {
      const Ci = bls12_381.G1.Point.fromHex(proof.bitProofs[i].C);
      recon = recon.add(_safeG1Mul(Ci, 1n << BigInt(i)));
    }
    return recon.equals(bls12_381.G1.Point.fromHex(proof.C_witness));
  } catch { return false; }
}

export function generateNonce(): string { return randomBytes(32).toString('hex'); }
export function generateId(): string { return randomBytes(16).toString('hex'); }
export function nowISO(): string { return new Date().toISOString(); }
export function futureISO(days: number): string {
  const d = new Date(); d.setDate(d.getDate() + days); return d.toISOString();
}
export function toHex(b: Uint8Array): string { return Buffer.from(b).toString('hex'); }
export function fromHex(h: string): Uint8Array { return new Uint8Array(Buffer.from(h, 'hex')); }
