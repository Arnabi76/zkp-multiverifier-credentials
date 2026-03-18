import { Issuer, createIssuer } from '../src/issuer/issuer';
import { generateId, derivePseudonymKeyCommitment } from '../src/utils/crypto';
import { randomBytes } from 'crypto';
import { CredentialAttributes } from '../src/utils/types';

function makeAttrs(overrides: Partial<CredentialAttributes> = {}): CredentialAttributes {
  return {
    attr_1: 'H-test-001',
    attr_2: 28,
    attr_3: 75000,
    attr_4: true,
    attr_5: 'category-A',
    credentialId: generateId(),
    ...overrides,
  };
}

function makePseudonymCommitment(): string {
  return derivePseudonymKeyCommitment(randomBytes(32));
}

describe('Issuer I: Initialization', () => {
  test('generates BBS+ public key of correct size (96 bytes)', async () => {
    const issuer = await createIssuer('I-001', 'Issuer I');
    expect(issuer.getBbsPublicKey().length).toBe(96);
  });

  test('generates Dilithium public key of correct size (1952 bytes = ML-DSA-65)', async () => {
    const issuer = await createIssuer('I-002', 'Issuer I');
    expect(issuer.getDilithiumPublicKey().length).toBe(1952);
  });

  test('has correct DID format', async () => {
    const issuer = await createIssuer('I-003', 'Issuer I');
    expect(issuer.getDid()).toBe('did:example:issuer-I-003');
  });

  test('throws if issuing before initialize()', async () => {
    const issuer = new Issuer('uninit', 'Test');
    await expect(issuer.issueCredential(makeAttrs(), makePseudonymCommitment())).rejects.toThrow('Not initialized');
  });
});

describe('Issuer I: Credential Issuance', () => {
  let issuer: Issuer;
  beforeAll(async () => { issuer = await createIssuer('I-004', 'Issuer I'); });

  test('issues credential with all required fields', async () => {
    const attrs = makeAttrs();
    const cred = await issuer.issueCredential(attrs, makePseudonymCommitment());
    expect(cred.id).toBe(attrs.credentialId);
    expect(cred.issuerDid).toBe('did:example:issuer-I-004');
    expect(cred.bbsSignature).toBeDefined();
    expect(cred.dilithiumSignature).toBeDefined();
    expect(cred.credentialRoot).toBeDefined();
    expect(typeof cred.revocationIndex).toBe('number');
    expect(cred.revocationIndex).toBeGreaterThanOrEqual(0);
    expect(cred.revocationIndex).toBeLessThan(2 ** 31);
  });

  test('credential root is a 64-char hex string (SHA-256)', async () => {
    const cred = await issuer.issueCredential(makeAttrs(), makePseudonymCommitment());
    expect(cred.credentialRoot).toMatch(/^[0-9a-f]{64}$/);
  });

  test('BBS+ signature is 112 bytes', async () => {
    const cred = await issuer.issueCredential(makeAttrs(), makePseudonymCommitment());
    expect(cred.bbsSignature.length).toBe(112);
  });

  test('Dilithium signature is 3309 bytes (ML-DSA-65)', async () => {
    const cred = await issuer.issueCredential(makeAttrs(), makePseudonymCommitment());
    expect(cred.dilithiumSignature.length).toBe(3309);
  });

  test('revocation slots are unique per credential', async () => {
    const c1 = await issuer.issueCredential(makeAttrs(), makePseudonymCommitment());
    const c2 = await issuer.issueCredential(makeAttrs(), makePseudonymCommitment());
    expect(c1.revocationIndex).not.toBe(c2.revocationIndex);
  });
});

describe('Issuer I: Dual Signature Verification', () => {
  let issuer: Issuer;
  beforeAll(async () => { issuer = await createIssuer('I-005', 'Issuer I'); });

  test('BBS+ signature verifies correctly', async () => {
    const cred = await issuer.issueCredential(makeAttrs(), makePseudonymCommitment());
    expect(await issuer.verifyBbsSignature(cred)).toBe(true);
  });

  test('Dilithium signature verifies correctly (PQC layer)', async () => {
    const cred = await issuer.issueCredential(makeAttrs(), makePseudonymCommitment());
    expect(await issuer.verifyDilithiumSignature(cred)).toBe(true);
  });

  test('BBS+ detects tampered attribute', async () => {
    const cred = await issuer.issueCredential(makeAttrs(), makePseudonymCommitment());
    const tampered = { ...cred, attributes: { ...cred.attributes, attr_3: 999999 } };
    expect(await issuer.verifyBbsSignature(tampered)).toBe(false);
  });

  test('Dilithium detects tampered credential root', async () => {
    const { encodeAttributesToMessages, computeCredentialRoot } = require('../src/utils/crypto');
    const psk = makePseudonymCommitment();
    const cred = await issuer.issueCredential(makeAttrs(), psk);
    const tamperedAttrs = { ...cred.attributes, attr_3: 999999 };
    const tamperedMsgs = encodeAttributesToMessages({
      ...tamperedAttrs,
      issuanceDate: cred.issuanceDate,
      revocationIndex: cred.revocationIndex,
      pseudonymKeyCommitment: psk,
    });
    const tamperedRoot = computeCredentialRoot(tamperedMsgs);
    const tampered = { ...cred, credentialRoot: tamperedRoot };
    expect(await issuer.verifyDilithiumSignature(tampered)).toBe(false);
  });

  test('two credentials have different roots (root is credential-specific)', async () => {
    const c1 = await issuer.issueCredential(makeAttrs({ attr_3: 50000 }), makePseudonymCommitment());
    const c2 = await issuer.issueCredential(makeAttrs({ attr_3: 90000 }), makePseudonymCommitment());
    expect(c1.credentialRoot).not.toBe(c2.credentialRoot);
  });
});

describe('Issuer I: Input Validation', () => {
  let issuer: Issuer;
  beforeAll(async () => { issuer = await createIssuer('I-006', 'Issuer I'); });

  test('rejects empty attr_1', async () => {
    await expect(issuer.issueCredential(makeAttrs({ attr_1: '' }), makePseudonymCommitment())).rejects.toThrow('attr_1');
  });

  test('rejects negative attr_3', async () => {
    await expect(issuer.issueCredential(makeAttrs({ attr_3: -1 }), makePseudonymCommitment())).rejects.toThrow('attr_3');
  });

  test('rejects out-of-range attr_2', async () => {
    await expect(issuer.issueCredential(makeAttrs({ attr_2: 200 }), makePseudonymCommitment())).rejects.toThrow('attr_2');
  });
});

describe('Issuer I: Revocation', () => {
  let issuer: Issuer;
  beforeAll(async () => { issuer = await createIssuer('I-007', 'Issuer I'); });

  test('fresh credential is not revoked', async () => {
    const cred = await issuer.issueCredential(makeAttrs(), makePseudonymCommitment());
    expect(issuer.isRevoked(cred.id)).toBe(false);
  });

  test('revocation marks credential correctly', async () => {
    const cred = await issuer.issueCredential(makeAttrs(), makePseudonymCommitment());
    issuer.revokeCredential(cred.id);
    expect(issuer.isRevoked(cred.id)).toBe(true);
  });

  test('revocation by index works', async () => {
    const cred = await issuer.issueCredential(makeAttrs(), makePseudonymCommitment());
    expect(issuer.isIndexRevoked(cred.revocationIndex)).toBe(false);
    issuer.revokeCredential(cred.id);
    expect(issuer.isIndexRevoked(cred.revocationIndex)).toBe(true);
  });

  test('status list reflects revocations accurately', async () => {
    const c1 = await issuer.issueCredential(makeAttrs(), makePseudonymCommitment());
    const c2 = await issuer.issueCredential(makeAttrs(), makePseudonymCommitment());
    const c3 = await issuer.issueCredential(makeAttrs(), makePseudonymCommitment());
    issuer.revokeCredential(c2.id);
    const list = issuer.getRevocationStatusList();
    expect(list.revokedIndices).toContain(c2.revocationIndex);
    expect(list.revokedIndices).not.toContain(c1.revocationIndex);
    expect(list.revokedIndices).not.toContain(c3.revocationIndex);
  });
});
