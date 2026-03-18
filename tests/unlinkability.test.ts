import { createIssuer } from '../src/issuer/issuer';
import { createHolder } from '../src/holder/holder';
import { createVerifierA, createVerifierB, createVerifierC } from '../src/verifier/verifier';
import { generateId } from '../src/utils/crypto';
import { SignedCredential } from '../src/utils/types';

jest.setTimeout(60000);

const notRevoked = (_idx: number) => false;

async function setupAll() {
  const issuer = await createIssuer('issuer-unlink', 'Unlink Issuer');
  const holder = await createHolder('holder-unlink');
  const verifierA = await createVerifierA(notRevoked);
  const verifierB = await createVerifierB(notRevoked);
  const verifierC = await createVerifierC(notRevoked);

  const credentialId = generateId();
  const commitment = holder.preparePseudonymCommitment(credentialId);
  const credential: SignedCredential = await issuer.issueCredential({
    attr_1: 'Bob',
    attr_2: 25,
    attr_3: 80000,
    attr_4: true,
    attr_5: 'Finance',
    credentialId,
  }, commitment);
  holder.storeCredential(credential);

  return { holder, verifierA, verifierB, verifierC, credential };
}

function toHex(b: Uint8Array): string {
  return Buffer.from(b).toString('hex');
}

describe('Unlinkability: Session-Level', () => {

  it('Test 1 — Same credential, same verifier: two proofs are byte-different', async () => {
    const { holder, verifierA, credential } = await setupAll();
    const challenge1 = verifierA.issueChallenge();
    await new Promise(r => setTimeout(r, 2)); 
    const challenge2 = verifierA.issueChallenge();
    const proof1 = await holder.generateProof(credential.id, challenge1);
    const proof2 = await holder.generateProof(credential.id, challenge2);
    expect(toHex(proof1.bbsProof)).not.toBe(toHex(proof2.bbsProof));
  });

  it('Test 2 — Same credential, all three verifiers: all proofs are byte-different', async () => {
    const { holder, verifierA, verifierB, verifierC, credential } = await setupAll();
    const challengeA = verifierA.issueChallenge();
    const challengeB = verifierB.issueChallenge();
    const challengeC = verifierC.issueChallenge();
    const proofA = await holder.generateProof(credential.id, challengeA);
    const proofB = await holder.generateProof(credential.id, challengeB);
    const proofC = await holder.generateProof(credential.id, challengeC);
    expect(toHex(proofA.bbsProof)).not.toBe(toHex(proofB.bbsProof));
    expect(toHex(proofA.bbsProof)).not.toBe(toHex(proofC.bbsProof));
    expect(toHex(proofB.bbsProof)).not.toBe(toHex(proofC.bbsProof));
    expect(proofA.proofId).not.toBe(proofB.proofId);
    expect(proofA.proofId).not.toBe(proofC.proofId);
    expect(proofB.proofId).not.toBe(proofC.proofId);
    expect(proofA.verifierId).not.toBe(proofB.verifierId);
    expect(proofA.verifierId).not.toBe(proofC.verifierId);
    expect(proofB.verifierId).not.toBe(proofC.verifierId);
  });

  it('Test 3 — Colluding verifiers cannot correlate: blindedRoot differs across proofs (L3 fixed)', async () => {
    const { holder, verifierA, verifierB, verifierC, credential } = await setupAll();
    const challengeA = verifierA.issueChallenge();
    const challengeB = verifierB.issueChallenge();
    const challengeC = verifierC.issueChallenge();
    const proofA = await holder.generateProof(credential.id, challengeA);
    const proofB = await holder.generateProof(credential.id, challengeB);
    const proofC = await holder.generateProof(credential.id, challengeC);

    expect(toHex(proofA.bbsProof)).not.toBe(toHex(proofB.bbsProof));
    expect(toHex(proofA.bbsProof)).not.toBe(toHex(proofC.bbsProof));
    expect(toHex(proofB.bbsProof)).not.toBe(toHex(proofC.bbsProof));

    expect(proofA.blindedRoot).not.toBe(proofB.blindedRoot);
    expect(proofA.blindedRoot).not.toBe(proofC.blindedRoot);
    expect(proofB.blindedRoot).not.toBe(proofC.blindedRoot);

    expect(Object.keys(proofA.disclosedAttributes)).not.toEqual(
      Object.keys(proofB.disclosedAttributes)
    );
    expect(Object.keys(proofA.disclosedAttributes)).not.toEqual(
      Object.keys(proofC.disclosedAttributes)
    );
    expect(Object.keys(proofB.disclosedAttributes)).not.toEqual(
      Object.keys(proofC.disclosedAttributes)
    );
  });

  it('Test 4 — Replay attack prevented: same proof cannot be submitted twice', async () => {
    const { holder, verifierA, credential } = await setupAll();
    const challenge = verifierA.issueChallenge();
    const proof = await holder.generateProof(credential.id, challenge);
    const result1 = await verifierA.verifyProof(proof);
    expect(result1.verified).toBe(true);
    const result2 = await verifierA.verifyProof(proof);
    expect(result2.verified).toBe(false);
  });

  it('Test 5 — Replay attack prevented across all three verifiers', async () => {
    const { holder, verifierB, verifierC, credential } = await setupAll();
    const challengeB = verifierB.issueChallenge();
    const challengeC = verifierC.issueChallenge();
    const proofB = await holder.generateProof(credential.id, challengeB);
    const proofC = await holder.generateProof(credential.id, challengeC);
    const result1B = await verifierB.verifyProof(proofB);
    const result1C = await verifierC.verifyProof(proofC);
    expect(result1B.verified).toBe(true);
    expect(result1C.verified).toBe(true);
    const result2B = await verifierB.verifyProof(proofB);
    const result2C = await verifierC.verifyProof(proofC);
    expect(result2B.verified).toBe(false);
    expect(result2C.verified).toBe(false);
  });

  it('Test 6 — Cross-verifier proof submission rejected: proof for A cannot be submitted to B or C', async () => {
    const { holder, verifierA, verifierB, verifierC, credential } = await setupAll();
    const challengeA = verifierA.issueChallenge();
    const proofA = await holder.generateProof(credential.id, challengeA);
    const resultB = await verifierB.verifyProof(proofA);
    const resultC = await verifierC.verifyProof(proofA);
    expect(resultB.verified).toBe(false);
    expect(resultC.verified).toBe(false);
  });

  it('Test 7 — auditDilithium confirms binding offline with known credentialRoot', async () => {
    const { holder, verifierA, credential } = await setupAll();
    const challenge = verifierA.issueChallenge();
    const proof = await holder.generateProof(credential.id, challenge);
    expect(await verifierA.auditDilithium(proof, credential.credentialRoot)).toBe(true);
  });

  it('Test 8 — linkable:false proof contains no pseudonym field', async () => {
    const { holder, verifierA, credential } = await setupAll();
    const proof = await holder.generateProof(credential.id, verifierA.issueChallenge());
    expect((proof as any).pseudonym).toBeUndefined();
  });

  it('Test 9 — linkable:true (Verifier B) proof contains a pseudonym', async () => {
    const { holder, verifierB, credential } = await setupAll();
    const proof = await holder.generateProof(credential.id, verifierB.issueChallenge());
    expect(typeof proof.pseudonym).toBe('string');
    expect(proof.pseudonym!.length).toBeGreaterThan(0);
  });

  it('Test 10 — same credential, Verifier B, two sessions: pseudonyms identical', async () => {
    const { holder, verifierB, credential } = await setupAll();
    const p1 = await holder.generateProof(credential.id, verifierB.issueChallenge());
    await new Promise(r => setTimeout(r, 2));
    const p2 = await holder.generateProof(credential.id, verifierB.issueChallenge());
    expect(p1.pseudonym).toBe(p2.pseudonym);
  });

  it('Test 11 — credentialId absent from all proof objects', async () => {
    const { holder, verifierA, verifierB, verifierC, credential } = await setupAll();
    const pA = await holder.generateProof(credential.id, verifierA.issueChallenge());
    const pB = await holder.generateProof(credential.id, verifierB.issueChallenge());
    const pC = await holder.generateProof(credential.id, verifierC.issueChallenge());
    expect((pA as any).credentialId).toBeUndefined();
    expect((pB as any).credentialId).toBeUndefined();
    expect((pC as any).credentialId).toBeUndefined();
  });

});
