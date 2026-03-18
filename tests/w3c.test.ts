import { createIssuer } from '../src/issuer/issuer';
import { createHolder } from '../src/holder/holder';
import { generateId } from '../src/utils/crypto';
import { SignedCredential } from '../src/utils/types';
import {
  toW3CVC, fromW3CVC, validateW3CVC, w3cVcToJson, w3cVcFromJson, W3CVC,
} from '../src/w3c/vc-wrapper';

jest.setTimeout(30000);

let credential: SignedCredential;

beforeAll(async () => {
  const issuer = await createIssuer('issuer-w3c', 'W3C Test Issuer');
  const holder = await createHolder('holder-w3c');
  const credentialId = generateId();
  const commitment = holder.preparePseudonymCommitment(credentialId);
  credential = await issuer.issueCredential({
    attr_1: 'Alice',
    attr_2: 30,
    attr_3: 75000,
    attr_4: true,
    attr_5: 'Engineering',
    credentialId,
  }, commitment);
});

describe('W3C VC 2.0 Wrapper', () => {
  it('toW3CVC produces valid JSON-LD structure (validateW3CVC returns valid:true)', () => {
    const vc = toW3CVC(credential);
    const result = validateW3CVC(vc);
    expect(result.errors).toEqual([]);
    expect(result.valid).toBe(true);
  });

  it('toW3CVC includes both proof entries (BBS+ and Dilithium)', () => {
    const vc = toW3CVC(credential);
    expect(vc.proof).toHaveLength(2);
    expect(vc.proof[0].type).toBe('BbsBlsSignature2020');
    expect(vc.proof[1].type).toBe('MlDsa65Signature2026');
    expect(vc.proof[1].securityLevel).toBe('NIST-FIPS-204-ML-DSA-65');
    expect(vc.proof[1].signedData).toBe('dilithiumBinding');
  });

  it('toW3CVC does NOT include raw attribute values in credentialSubject', () => {
    const vc = toW3CVC(credential);
    const subject = vc.credentialSubject as any;
    expect(subject.attr_1).toBeUndefined();
    expect(subject.attr_2).toBeUndefined();
    expect(subject.attr_3).toBeUndefined();
    expect(subject.attr_4).toBeUndefined();
    expect(subject.attr_5).toBeUndefined();
  });

  it('toW3CVC includes SHA-256 commitments for all 5 attributes', () => {
    const vc = toW3CVC(credential);
    const { commitments } = vc.credentialSubject;
    expect(commitments.attr_1).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(commitments.attr_2).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(commitments.attr_3).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(commitments.attr_4).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(commitments.attr_5).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('fromW3CVC recovers credentialRoot correctly', () => {
    const vc = toW3CVC(credential);
    const recovered = fromW3CVC(vc);
    expect(recovered.credentialRoot).toBe(credential.credentialRoot);
  });

  it('fromW3CVC recovers bbsSignature correctly (byte-for-byte after base64url round-trip)', () => {
    const vc = toW3CVC(credential);
    const recovered = fromW3CVC(vc);
    expect(recovered.bbsSignature).toBeDefined();
    expect(Buffer.from(recovered.bbsSignature!).toString('hex'))
      .toBe(Buffer.from(credential.bbsSignature).toString('hex'));
  });

  it('JSON serialize/deserialize round-trip is lossless', () => {
    const vc = toW3CVC(credential);
    const json = w3cVcToJson(vc);
    const restored = w3cVcFromJson(json);
    expect(restored).toEqual(vc);
    expect(validateW3CVC(restored).valid).toBe(true);
  });

  it('validateW3CVC rejects document with wrong @context', () => {
    const vc = toW3CVC(credential);
    const bad: W3CVC = { ...vc, '@context': ['https://wrong.example.com/context'] };
    const result = validateW3CVC(bad);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('@context'))).toBe(true);
  });

  it('validateW3CVC rejects document with missing proof', () => {
    const vc = toW3CVC(credential);
    const bad: W3CVC = { ...vc, proof: [] };
    const result = validateW3CVC(bad);
    expect(result.valid).toBe(false);
    expect(result.errors.some(e => e.includes('proof'))).toBe(true);
  });
});
