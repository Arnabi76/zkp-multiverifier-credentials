import { createIssuer } from '../src/issuer/issuer';
import { createHolder } from '../src/holder/holder';
import { createVerifierA, createVerifierB, createVerifierC } from '../src/verifier/verifier';
import { generateId } from '../src/utils/crypto';
import { SignedCredential } from '../src/utils/types';

jest.setTimeout(60000);

async function setup() {
  const revokedSet = new Set<number>();
  const isRevoked = (idx: number) => revokedSet.has(idx);

  const issuer = await createIssuer('issuer1', 'Test Issuer');
  const holder = await createHolder('holder-1');
  const verifierA = await createVerifierA(isRevoked);
  const verifierB = await createVerifierB(isRevoked);
  const verifierC = await createVerifierC(isRevoked);

  const credentialId = generateId();
  const commitment = holder.preparePseudonymCommitment(credentialId);
  const credential = await issuer.issueCredential({
    attr_1: 'Alice',
    attr_2: 30,
    attr_3: 75000,
    attr_4: true,
    attr_5: 'Engineering',
    credentialId,
  }, commitment);
  holder.storeCredential(credential);

  return { issuer, holder, verifierA, verifierB, verifierC, credential, revokedSet };
}

describe('Verifier A: Challenge Issuance', () => {
  it('issueChallenge returns a challenge with correct verifierId', async () => {
    const { verifierA } = await setup();
    const challenge = verifierA.issueChallenge();
    expect(challenge.verifierId).toBe('V-A');
  });

  it('challenge has a valid issuedAt timestamp', async () => {
    const { verifierA } = await setup();
    const challenge = verifierA.issueChallenge();
    expect(typeof challenge.issuedAt).toBe('string');
    expect(() => new Date(challenge.issuedAt)).not.toThrow();
  });

  it('challenge has correct requestedAttributes for Verifier A', async () => {
    const { verifierA } = await setup();
    const challenge = verifierA.issueChallenge();
    expect(challenge.requestedAttributes).toEqual(['attr_2', 'attr_5']);
  });
});

describe('Verifier A: Proof Verification - Happy Path', () => {
  it('full end-to-end: issue challenge THEN holder generates proof THEN verifier accepts', async () => {
    const { holder, verifierA, credential } = await setup();
    const challenge = verifierA.issueChallenge();
    const proof = await holder.generateProof(credential.id, challenge);
    const result = await verifierA.verifyProof(proof);
    expect(result.verified).toBe(true);
  });

  it('result.bbsVerified === true', async () => {
    const { holder, verifierA, credential } = await setup();
    const challenge = verifierA.issueChallenge();
    const proof = await holder.generateProof(credential.id, challenge);
    const result = await verifierA.verifyProof(proof);
    expect(result.bbsVerified).toBe(true);
  });

  it('result.dilithiumVerified === true', async () => {
    const { holder, verifierA, credential } = await setup();
    const challenge = verifierA.issueChallenge();
    const proof = await holder.generateProof(credential.id, challenge);
    const result = await verifierA.verifyProof(proof);
    expect(result.dilithiumVerified).toBe(true);
  });

  it('auditDilithium returns true for valid proof', async () => {
    const { holder, verifierA, credential } = await setup();
    const challenge = verifierA.issueChallenge();
    const proof = await holder.generateProof(credential.id, challenge);
    expect(await verifierA.auditDilithium(proof, credential.credentialRoot)).toBe(true);
  });

  it('result.isRevoked === false', async () => {
    const { holder, verifierA, credential } = await setup();
    const challenge = verifierA.issueChallenge();
    const proof = await holder.generateProof(credential.id, challenge);
    const result = await verifierA.verifyProof(proof);
    expect(result.isRevoked).toBe(false);
  });

  it('disclosedAttributes contains only what was requested (attr_2, attr_5)', async () => {
    const { holder, verifierA, credential } = await setup();
    const challenge = verifierA.issueChallenge();
    const proof = await holder.generateProof(credential.id, challenge);
    const result = await verifierA.verifyProof(proof);
    expect(result.disclosedAttributes.attr_2).toBe(30);
    expect(result.disclosedAttributes.attr_5).toBe('Engineering');
  });

  it('disclosedAttributes does NOT contain attr_1 or attr_3', async () => {
    const { holder, verifierA, credential } = await setup();
    const challenge = verifierA.issueChallenge();
    const proof = await holder.generateProof(credential.id, challenge);
    const result = await verifierA.verifyProof(proof);
    expect(result.disclosedAttributes.attr_1).toBeUndefined();
    expect(result.disclosedAttributes.attr_3).toBeUndefined();
  });
});

describe('Verifier A: Rejection Cases', () => {
  it('rejects replayed proof via seenProofs', async () => {
    const { holder, verifierA, credential } = await setup();
    const challenge = verifierA.issueChallenge();
    const proof = await holder.generateProof(credential.id, challenge);
    await verifierA.verifyProof(proof);
    const result = await verifierA.verifyProof(proof);
    expect(result.verified).toBe(false);
  });

  it('rejects proof where bbsProof is tampered', async () => {
    const { holder, verifierA, credential } = await setup();
    const challenge = verifierA.issueChallenge();
    const proof = await holder.generateProof(credential.id, challenge);
    const tampered = new Uint8Array(proof.bbsProof);
    tampered[0] ^= 0xff;
    const tamperedProof = { ...proof, bbsProof: tampered };
    const result = await verifierA.verifyProof(tamperedProof);
    expect(result.verified).toBe(false);
    expect(result.bbsVerified).toBe(false);
  });

  it('rejects proof where dilithiumSignature is tampered', async () => {
    const { holder, verifierA, credential } = await setup();
    const challenge = verifierA.issueChallenge();
    const proof = await holder.generateProof(credential.id, challenge);
    const tampered = new Uint8Array(proof.dilithiumSignature);
    tampered[0] ^= 0xff;
    const tamperedProof = { ...proof, proofId: proof.proofId + '-dil', dilithiumSignature: tampered };
    const result = await verifierA.verifyProof(tamperedProof);
    expect(result.verified).toBe(false);
    expect(result.dilithiumVerified).toBe(false);
  });

  it('auditDilithium returns false for tampered dilithiumSignature', async () => {
    const { holder, verifierA, credential } = await setup();
    const challenge = verifierA.issueChallenge();
    const proof = await holder.generateProof(credential.id, challenge);
    const tampered = new Uint8Array(proof.dilithiumSignature);
    tampered[0] ^= 0xff;
    const tamperedProof = { ...proof, dilithiumSignature: tampered };
    expect(await verifierA.auditDilithium(tamperedProof, credential.credentialRoot)).toBe(false);
  });

  it('rejects proof for revoked credential', async () => {
    const { holder, verifierA, credential, revokedSet } = await setup();
    revokedSet.add(credential.revocationIndex);  
    const challenge = verifierA.issueChallenge();
    const proof = await holder.generateProof(credential.id, challenge);
    const result = await verifierA.verifyProof(proof);
    expect(result.verified).toBe(false);
    expect(result.isRevoked).toBe(true);
  });
});

describe('Verifier B: Different Predicate', () => {
  it('Verifier B accepts a valid proof checking attr_2 >= 18 and disclosing attr_4', async () => {
    const { holder, verifierB, credential } = await setup();
    const challenge = verifierB.issueChallenge();
    const proof = await holder.generateProof(credential.id, challenge);
    const result = await verifierB.verifyProof(proof);
    expect(result.verified).toBe(true);
    expect(result.disclosedAttributes.attr_4).toBe(true);
  });

  it('Verifier A and Verifier B get different disclosures from same credential', async () => {
    const { holder, verifierA, verifierB, credential } = await setup();

    const challengeA = verifierA.issueChallenge();
    const proofA = await holder.generateProof(credential.id, challengeA);
    const resultA = await verifierA.verifyProof(proofA);

    const challengeB = verifierB.issueChallenge();
    const proofB = await holder.generateProof(credential.id, challengeB);
    const resultB = await verifierB.verifyProof(proofB);

    expect(Object.keys(resultA.disclosedAttributes)).toContain('attr_2');
    expect(Object.keys(resultA.disclosedAttributes)).toContain('attr_5');
    expect(Object.keys(resultA.disclosedAttributes)).not.toContain('attr_4');

    expect(Object.keys(resultB.disclosedAttributes)).toContain('attr_4');
    expect(Object.keys(resultB.disclosedAttributes)).not.toContain('attr_2');
    expect(Object.keys(resultB.disclosedAttributes)).not.toContain('attr_5');
  });
});

describe('Verifier C: Challenge Issuance', () => {
  it('issueChallenge returns a challenge with correct verifierId', async () => {
    const { verifierC } = await setup();
    const challenge = verifierC.issueChallenge();
    expect(challenge.verifierId).toBe('V-C');
  });

  it('challenge has a valid issuedAt timestamp', async () => {
    const { verifierC } = await setup();
    const challenge = verifierC.issueChallenge();
    expect(typeof challenge.issuedAt).toBe('string');
    expect(() => new Date(challenge.issuedAt)).not.toThrow();
  });

  it('challenge has correct requestedAttributes for Verifier C', async () => {
    const { verifierC } = await setup();
    const challenge = verifierC.issueChallenge();
    expect(challenge.requestedAttributes).toEqual(['attr_1', 'attr_5']);
  });
});

describe('Verifier C: Proof Verification - Happy Path', () => {
  it('full end-to-end: issue challenge THEN holder generates proof THEN verifier accepts', async () => {
    const { holder, verifierC, credential } = await setup();
    const challenge = verifierC.issueChallenge();
    const proof = await holder.generateProof(credential.id, challenge);
    const result = await verifierC.verifyProof(proof);
    expect(result.verified).toBe(true);
  });

  it('result.bbsVerified === true', async () => {
    const { holder, verifierC, credential } = await setup();
    const challenge = verifierC.issueChallenge();
    const proof = await holder.generateProof(credential.id, challenge);
    const result = await verifierC.verifyProof(proof);
    expect(result.bbsVerified).toBe(true);
  });

  it('result.dilithiumVerified === true', async () => {
    const { holder, verifierC, credential } = await setup();
    const challenge = verifierC.issueChallenge();
    const proof = await holder.generateProof(credential.id, challenge);
    const result = await verifierC.verifyProof(proof);
    expect(result.dilithiumVerified).toBe(true);
  });

  it('auditDilithium returns true for valid proof', async () => {
    const { holder, verifierC, credential } = await setup();
    const challenge = verifierC.issueChallenge();
    const proof = await holder.generateProof(credential.id, challenge);
    expect(await verifierC.auditDilithium(proof, credential.credentialRoot)).toBe(true);
  });

  it('result.isRevoked === false', async () => {
    const { holder, verifierC, credential } = await setup();
    const challenge = verifierC.issueChallenge();
    const proof = await holder.generateProof(credential.id, challenge);
    const result = await verifierC.verifyProof(proof);
    expect(result.isRevoked).toBe(false);
  });

  it('disclosedAttributes contains only what was requested (attr_1, attr_5)', async () => {
    const { holder, verifierC, credential } = await setup();
    const challenge = verifierC.issueChallenge();
    const proof = await holder.generateProof(credential.id, challenge);
    const result = await verifierC.verifyProof(proof);
    expect(result.disclosedAttributes.attr_1).toBe('Alice');
    expect(result.disclosedAttributes.attr_5).toBe('Engineering');
  });

  it('disclosedAttributes does NOT contain attr_2, attr_3, or attr_4', async () => {
    const { holder, verifierC, credential } = await setup();
    const challenge = verifierC.issueChallenge();
    const proof = await holder.generateProof(credential.id, challenge);
    const result = await verifierC.verifyProof(proof);
    expect(result.disclosedAttributes.attr_2).toBeUndefined();
    expect(result.disclosedAttributes.attr_3).toBeUndefined();
    expect(result.disclosedAttributes.attr_4).toBeUndefined();
  });

  it('predicate attr_2 < 50 is satisfied (attr_2 is 30)', async () => {
    const { holder, verifierC, credential } = await setup();
    const challenge = verifierC.issueChallenge();
    const proof = await holder.generateProof(credential.id, challenge);
    const result = await verifierC.verifyProof(proof);
    expect(result.predicateResults[0].satisfied).toBe(true);
    expect(result.predicateResults[0].predicate).toBe('attr_2 < 50');
  });
});

describe('Verifier C: Rejection Cases', () => {
  it('rejects replayed proof via seenProofs', async () => {
    const { holder, verifierC, credential } = await setup();
    const challenge = verifierC.issueChallenge();
    const proof = await holder.generateProof(credential.id, challenge);
    await verifierC.verifyProof(proof);
    const result = await verifierC.verifyProof(proof);
    expect(result.verified).toBe(false);
  });

  it('rejects proof where bbsProof is tampered', async () => {
    const { holder, verifierC, credential } = await setup();
    const challenge = verifierC.issueChallenge();
    const proof = await holder.generateProof(credential.id, challenge);
    const tampered = new Uint8Array(proof.bbsProof);
    tampered[0] ^= 0xff;
    const tamperedProof = { ...proof, bbsProof: tampered };
    const result = await verifierC.verifyProof(tamperedProof);
    expect(result.verified).toBe(false);
    expect(result.bbsVerified).toBe(false);
  });

  it('auditDilithium returns false for tampered dilithiumSignature', async () => {
    const { holder, verifierC, credential } = await setup();
    const challenge = verifierC.issueChallenge();
    const proof = await holder.generateProof(credential.id, challenge);
    const tampered = new Uint8Array(proof.dilithiumSignature);
    tampered[0] ^= 0xff;
    const tamperedProof = { ...proof, dilithiumSignature: tampered };
    expect(await verifierC.auditDilithium(tamperedProof, credential.credentialRoot)).toBe(false);
  });

  it('rejects proof for revoked credential', async () => {
    const { holder, verifierC, credential, revokedSet } = await setup();
    revokedSet.add(credential.revocationIndex); 
    const challenge = verifierC.issueChallenge();
    const proof = await holder.generateProof(credential.id, challenge);
    const result = await verifierC.verifyProof(proof);
    expect(result.verified).toBe(false);
    expect(result.isRevoked).toBe(true);
  });
});

describe('Cross-Verifier: All Three Verifiers Get Different Disclosures', () => {
  it('A, B, and C each receive a different attribute set from the same credential', async () => {
    const { holder, verifierA, verifierB, verifierC, credential } = await setup();

    const challengeA = verifierA.issueChallenge();
    const proofA = await holder.generateProof(credential.id, challengeA);
    const resultA = await verifierA.verifyProof(proofA);

    const challengeB = verifierB.issueChallenge();
    const proofB = await holder.generateProof(credential.id, challengeB);
    const resultB = await verifierB.verifyProof(proofB);

    const challengeC = verifierC.issueChallenge();
    const proofC = await holder.generateProof(credential.id, challengeC);
    const resultC = await verifierC.verifyProof(proofC);

    expect(Object.keys(resultA.disclosedAttributes)).toContain('attr_2');
    expect(Object.keys(resultA.disclosedAttributes)).toContain('attr_5');
    expect(Object.keys(resultA.disclosedAttributes)).not.toContain('attr_1');
    expect(Object.keys(resultA.disclosedAttributes)).not.toContain('attr_4');

    expect(Object.keys(resultB.disclosedAttributes)).toContain('attr_4');
    expect(Object.keys(resultB.disclosedAttributes)).not.toContain('attr_1');
    expect(Object.keys(resultB.disclosedAttributes)).not.toContain('attr_2');

    expect(Object.keys(resultC.disclosedAttributes)).toContain('attr_1');
    expect(Object.keys(resultC.disclosedAttributes)).toContain('attr_5');
    expect(Object.keys(resultC.disclosedAttributes)).not.toContain('attr_2');
    expect(Object.keys(resultC.disclosedAttributes)).not.toContain('attr_4');

    expect(resultA.verified).toBe(true);
    expect(resultB.verified).toBe(true);
    expect(resultC.verified).toBe(true);
  });
});

describe('ZK Range Proofs: L2 Resolution', () => {
  it('proof predicates contain rangeProof object, not revealedValue', async () => {
    const { holder, verifierA, credential } = await setup();
    const challenge = verifierA.issueChallenge();
    const proof = await holder.generateProof(credential.id, challenge);
    const pred = proof.predicates[0];
    expect(pred.satisfied).toBe(true);
    expect(pred.rangeProof).not.toBeNull();
    expect((pred as any).revealedValue).toBeUndefined();
    expect((pred as any).blind).toBeUndefined();
  });

  it('verifyRangeProof passes for satisfied predicate', async () => {
    const { generateRangeProof, verifyRangeProof } = await import('../src/utils/crypto');
    const proof = generateRangeProof(75000, '>', 50000, 'test-nonce');
    expect(proof).not.toBeNull();
    expect(verifyRangeProof(proof!, 'test-nonce')).toBe(true);
  });

  it('verifyRangeProof fails for wrong nonce (proof is session-bound)', async () => {
    const { generateRangeProof, verifyRangeProof } = await import('../src/utils/crypto');
    const proof = generateRangeProof(75000, '>', 50000, 'nonce-A');
    expect(verifyRangeProof(proof!, 'nonce-B')).toBe(false);
  });

  it('generateRangeProof returns null for unsatisfied predicate (no false proof generated)', async () => {
    const { generateRangeProof } = await import('../src/utils/crypto');
    expect(generateRangeProof(30, '>', 50000, 'nonce')).toBeNull();
    expect(generateRangeProof(75000, '<', 50000, 'nonce')).toBeNull();
    expect(generateRangeProof(30, '>=', 31, 'nonce')).toBeNull();
  });

  it('verifyProof rejects when range proof is tampered (bit proof corrupted)', async () => {
    const { holder, verifierA, credential } = await setup();
    const challenge = verifierA.issueChallenge();
    const proof = await holder.generateProof(credential.id, challenge);
    const tampered = JSON.parse(JSON.stringify(proof));
    tampered.predicates[0].rangeProof.bitProofs[0].s0 = 'ff'.repeat(32);
    tampered.proofId = proof.proofId + '-rp-tamper';
    const result = await verifierA.verifyProof(tampered);
    expect(result.verified).toBe(false);
  });

  it('verifyProof rejects when rangeProof is stripped from satisfied predicate', async () => {
    const { holder, verifierA, credential } = await setup();
    const challenge = verifierA.issueChallenge();
    const proof = await holder.generateProof(credential.id, challenge);
    const tampered = JSON.parse(JSON.stringify(proof));
    tampered.predicates[0].rangeProof = null;
    tampered.proofId = proof.proofId + '-rp-strip';
    const result = await verifierA.verifyProof(tampered);
    expect(result.verified).toBe(false);
  });

  it('all four range operators (>, >=, <, <=) produce valid ZK proofs', async () => {
    const { generateRangeProof, verifyRangeProof } = await import('../src/utils/crypto');
    const nonce = 'ops-test-nonce';
    expect(verifyRangeProof(generateRangeProof(30, '>', 18, nonce)!, nonce)).toBe(true);
    expect(verifyRangeProof(generateRangeProof(30, '>=', 30, nonce)!, nonce)).toBe(true);
    expect(verifyRangeProof(generateRangeProof(30, '<', 50, nonce)!, nonce)).toBe(true);
    expect(verifyRangeProof(generateRangeProof(30, '<=', 30, nonce)!, nonce)).toBe(true);
  });
});

describe('ZK Range Proofs: Predicate Binding (M3)', () => {

  it('verifyProof rejects when predicate operation is tampered (> changed to >=)', async () => {
    const { holder, verifierA, credential } = await setup();
    const challenge = verifierA.issueChallenge(); 
    const proof = await holder.generateProof(credential.id, challenge);
    const tampered = JSON.parse(JSON.stringify(proof));
    tampered.predicates[0].operation = '>=';
    tampered.proofId = proof.proofId + '-op-tamper';
    const result = await verifierA.verifyProof(tampered);
    expect(result.verified).toBe(false);
  });

  it('verifyProof rejects when predicate threshold is tampered (50000 changed to 10000)', async () => {
    const { holder, verifierA, credential } = await setup();
    const challenge = verifierA.issueChallenge(); 
    const proof = await holder.generateProof(credential.id, challenge);
    const tampered = JSON.parse(JSON.stringify(proof));
    tampered.predicates[0].threshold = 10000;
    tampered.proofId = proof.proofId + '-thresh-tamper';
    const result = await verifierA.verifyProof(tampered);
    expect(result.verified).toBe(false);
  });
});
