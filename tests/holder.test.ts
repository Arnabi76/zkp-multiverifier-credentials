import { createIssuer } from '../src/issuer/issuer';
import { createHolder } from '../src/holder/holder';
import { generateId } from '../src/utils/crypto';
import { VerifierChallenge, SignedCredential } from '../src/utils/types';

jest.setTimeout(30000);

function pastISO(hours: number): string {
  return new Date(Date.now() - hours * 3600 * 1000).toISOString();
}

function makeChallenge(verifierId: string, overrides: Partial<VerifierChallenge> = {}): VerifierChallenge {
  return {
    issuedAt: new Date().toISOString(),
    linkable: false,
    verifierId,
    requestedAttributes: ['attr_2', 'attr_5'],
    requestedPredicates: [
      { attribute: 'attr_3', operation: '>', threshold: 50000 }
    ],
    ...overrides,
  };
}

async function issueCredential() {
  const issuer = await createIssuer('issuer1', 'Test Issuer');
  const holder = await createHolder('holder-issue');
  const attrs = {
    attr_1: 'Alice',
    attr_2: 30,
    attr_3: 75000,
    attr_4: true,
    attr_5: 'Engineering',
    credentialId: generateId(),
  };
  const commitment = holder.preparePseudonymCommitment(attrs.credentialId);
  const credential = await issuer.issueCredential(attrs, commitment);
  holder.storeCredential(credential);
  return { issuer, credential, holder };
}

describe('Holder H: Credential Storage', () => {
  let credential: SignedCredential;

  beforeAll(async () => {
    const result = await issueCredential();
    credential = result.credential;
  });

  it('stores credential and retrieves it via listCredentials', async () => {
    const holder = await createHolder('holder-1');
    holder.storeCredential(credential);
    const list = holder.listCredentials();
    expect(list).toHaveLength(1);
    expect(list[0].id).toBe(credential.id);
  });

  it('listCredentials returns correct summary fields', async () => {
    const holder = await createHolder('holder-1');
    holder.storeCredential(credential);
    const list = holder.listCredentials();
    expect(list[0]).toMatchObject({
      id: credential.id,
      issuerDid: credential.issuerDid,
      expiryDate: credential.expiryDate,
    });
  });

  it('throws when generating proof for unknown credentialId', async () => {
    const holder = await createHolder('holder-1');
    const challenge = makeChallenge('verifier-x');
    await expect(holder.generateProof('nonexistent-id', challenge)).rejects.toThrow();
  });
});


describe('Holder H: Proof Generation', () => {
  let credential: SignedCredential;

  beforeAll(async () => {
    const result = await issueCredential();
    credential = result.credential;
  });

  async function getHolderWithCred() {
    const { holder } = await issueCredential();
    return holder;
  }

  it('generates a proof without throwing', async () => {
    const holder = await getHolderWithCred();
    const list = holder.listCredentials();
    const proof = await holder.generateProof(list[0].id, makeChallenge('verifier-1'));
    expect(proof).toBeDefined();
  });

  it('proof contains a non-empty bbsProof Uint8Array', async () => {
    const holder = await getHolderWithCred();
    const list = holder.listCredentials();
    const proof = await holder.generateProof(list[0].id, makeChallenge('verifier-1'));
    expect(proof.bbsProof).toBeInstanceOf(Uint8Array);
    expect(proof.bbsProof.length).toBeGreaterThan(0);
  });

  it('proof does not expose credentialId (L12)', async () => {
    const holder = await getHolderWithCred();
    const list = holder.listCredentials();
    const proof = await holder.generateProof(list[0].id, makeChallenge('verifier-1'));
    expect((proof as any).credentialId).toBeUndefined();
  });

  it('proof verifierId matches the challenge verifierId', async () => {
    const holder = await getHolderWithCred();
    const list = holder.listCredentials();
    const proof = await holder.generateProof(list[0].id, makeChallenge('verifier-ABC'));
    expect(proof.verifierId).toBe('verifier-ABC');
  });

  it('proof only discloses requested attributes, not all attributes', async () => {
    const holder = await getHolderWithCred();
    const list = holder.listCredentials();
    const proof = await holder.generateProof(list[0].id, makeChallenge('verifier-1', {
      requestedAttributes: ['attr_2'],
    }));
    expect(Object.keys(proof.disclosedAttributes)).toEqual(['attr_2']);
    expect(proof.disclosedAttributes.attr_1).toBeUndefined();
    expect(proof.disclosedAttributes.attr_5).toBeUndefined();
  });

  it('proof includes correct predicates with satisfied=true for passing predicate', async () => {
    const holder = await getHolderWithCred();
    const list = holder.listCredentials();
    const proof = await holder.generateProof(list[0].id, makeChallenge('verifier-1'));
    expect(proof.predicates).toHaveLength(1);
    expect(proof.predicates[0].satisfied).toBe(true);
    expect(proof.predicates[0].attribute).toBe('attr_3');
    expect(proof.predicates[0].rangeProof).not.toBeNull();
  });

  it('proof includes correct predicates with satisfied=false for failing predicate', async () => {
    const holder = await getHolderWithCred();
    const list = holder.listCredentials();
    const proof = await holder.generateProof(list[0].id, makeChallenge('verifier-1', {
      requestedPredicates: [{ attribute: 'attr_3', operation: '>', threshold: 100000 }],
    }));
    expect(proof.predicates[0].satisfied).toBe(false);
  });
});

describe('Holder H: Unlinkability', () => {
  it('two proofs from same credential for same verifier produce different bbsProof bytes', async () => {
    const { holder, credential } = await issueCredential();
    const proof1 = await holder.generateProof(credential.id, makeChallenge('verifier-1'));
    await new Promise(r => setTimeout(r, 2));
    const proof2 = await holder.generateProof(credential.id, makeChallenge('verifier-1'));
    expect(Buffer.from(proof1.bbsProof).toString('hex')).not.toBe(
      Buffer.from(proof2.bbsProof).toString('hex')
    );
  });

  it('two proofs for different verifiers produce different proofIds', async () => {
    const { holder, credential } = await issueCredential();
    const proof1 = await holder.generateProof(credential.id, makeChallenge('verifier-A'));
    const proof2 = await holder.generateProof(credential.id, makeChallenge('verifier-B'));
    expect(proof1.proofId).not.toBe(proof2.proofId);
    expect(proof1.verifierId).toBe('verifier-A');
    expect(proof2.verifierId).toBe('verifier-B');
  });

  it('proofs do not expose hidden attributes in disclosedAttributes', async () => {
    const { holder, credential } = await issueCredential();
    const proof = await holder.generateProof(credential.id, makeChallenge('verifier-1', {
      requestedAttributes: ['attr_2'],
      requestedPredicates: [{ attribute: 'attr_3', operation: '>', threshold: 50000 }],
    }));
    expect(proof.disclosedAttributes.attr_3).toBeUndefined();
    expect(proof.disclosedAttributes.attr_1).toBeUndefined();
    expect(proof.disclosedAttributes.attr_4).toBeUndefined();
  });
});

describe('Holder H: Expiry', () => {
  it('rejects expired credential', async () => {
    const { credential } = await issueCredential();
    const expiredCredential: SignedCredential = {
      ...credential,
      expiryDate: pastISO(24),
    };
    const holder = await createHolder('holder-expiry');
    holder.storeCredential(expiredCredential);
    const challenge = makeChallenge('verifier-expiry');
    await expect(holder.generateProof(expiredCredential.id, challenge)).rejects.toThrow('Credential expired');
  });
});

describe('Holder H: Pseudonym Proof (L12)', () => {
  it('linkable challenge triggers pseudonymProof on the proof', async () => {
    const { holder, credential } = await issueCredential();
    const proof = await holder.generateProof(
      credential.id,
      makeChallenge('V-B', { linkable: true })
    );
    expect(typeof proof.pseudonym).toBe('string');
    expect(proof.pseudonymProof).toBeInstanceOf(Uint8Array);
    expect(proof.pseudonymProof!.length).toBe(80);
    expect(typeof proof.pseudonymKeyCommitment).toBe('string');
  });

  it('non-linkable challenge does NOT produce pseudonymProof', async () => {
    const { holder, credential } = await issueCredential();
    const proof = await holder.generateProof(
      credential.id,
      makeChallenge('V-A', { linkable: false })
    );
    expect(proof.pseudonym).toBeUndefined();
    expect(proof.pseudonymProof).toBeUndefined();
  });

  it('same credential to same verifier produces same pseudonym across sessions (linkable)', async () => {
    const { holder, credential } = await issueCredential();
    const p1 = await holder.generateProof(credential.id, makeChallenge('V-B', { linkable: true }));
    await new Promise(r => setTimeout(r, 2));
    const p2 = await holder.generateProof(credential.id, makeChallenge('V-B', { linkable: true }));
    expect(p1.pseudonym).toBe(p2.pseudonym);
  });

  it('same credential to different verifiers produces different pseudonyms (unlinkable)', async () => {
    const { holder, credential } = await issueCredential();
    const pB = await holder.generateProof(credential.id, makeChallenge('V-B', { linkable: true }));
    const pX = await holder.generateProof(credential.id, makeChallenge('V-X', { linkable: true }));
    expect(pB.pseudonym).not.toBe(pX.pseudonym);
  });

  it('throws if pseudonymKey missing for linkable challenge (preparePseudonymCommitment not called)', async () => {
    const { credential } = await issueCredential();
    const freshHolder = await createHolder('holder-no-key');
    freshHolder.storeCredential(credential);
    await expect(
      freshHolder.generateProof(credential.id, makeChallenge('V-B', { linkable: true }))
    ).rejects.toThrow('pseudonym key');
  });
});
