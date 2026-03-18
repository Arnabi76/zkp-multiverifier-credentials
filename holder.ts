import { createHash, randomBytes } from 'crypto';
import {
  encodeAttributesToMessages,
  createSelectiveDisclosureProof,
  generateNonce,
  generateId,
  nowISO,
  deriveNonce,
  derivePseudonymKeyCommitment,
  derivePseudonym,
  generatePseudonymProof,
  generateRangeProof,
  ATTRIBUTE_INDEX,
  TOTAL_MESSAGE_COUNT,
} from '../utils/crypto';
import {
  SignedCredential, SelectiveDisclosureProof, VerifierChallenge,
  ProofPredicate, CredentialAttributes,
} from '../utils/types';

export class Holder {
  private holderId: string;
  private credentials: Map<string, SignedCredential>;
  private pseudonymKeys: Map<string, Buffer>; 

  constructor(holderId: string) {
    this.holderId = holderId;
    this.credentials = new Map();
    this.pseudonymKeys = new Map();
  }

  preparePseudonymCommitment(credentialId: string): string {
    const key = randomBytes(32);
    this.pseudonymKeys.set(credentialId, key);
    return derivePseudonymKeyCommitment(key);
  }

  storeCredential(credential: SignedCredential): void {
    this.credentials.set(credential.id, credential);
    console.log(`[Holder H] Credential stored: ${credential.id.slice(0, 8)}...`);
  }

  async generateProof(
    credentialId: string,
    challenge: VerifierChallenge
  ): Promise<SelectiveDisclosureProof> {
    const credential = this.credentials.get(credentialId);
    if (!credential) throw new Error(`Credential not found: ${credentialId}`);
    if (credential.expiryDate < new Date().toISOString()) throw new Error('Credential expired');

    const messages = encodeAttributesToMessages({
      ...credential.attributes,
      issuanceDate: credential.issuanceDate,
      revocationIndex: credential.revocationIndex,
      pseudonymKeyCommitment: credential.pseudonymKeyCommitment,
    });

    const ALWAYS_HIDDEN = new Set([5, 6, 7]);
    const hiddenIndices = challenge.linkable ? ALWAYS_HIDDEN : new Set([...ALWAYS_HIDDEN, 8]);
    const requestedIndices = challenge.requestedAttributes
      .map((attr) => ATTRIBUTE_INDEX[attr as keyof typeof ATTRIBUTE_INDEX])
      .filter((idx) => idx !== undefined && !hiddenIndices.has(idx));
    const baseIndices = challenge.linkable ? [ATTRIBUTE_INDEX['pseudonymKeyCommitment']] : [];
    const revealedIndices = Array.from(new Set([...baseIndices, ...requestedIndices])).sort((a, b) => a - b);

    const disclosedAttributes: Partial<CredentialAttributes> = {};
    for (const attr of challenge.requestedAttributes) {
      if (attr in credential.attributes) {
        (disclosedAttributes as any)[attr] = (credential.attributes as any)[attr];
      }
    }

    const proofTimestamp = nowISO();
    const proofSalt = generateNonce().slice(0, 32);
    const nonce = deriveNonce(
      credential.revocationIndex.toString(),
      challenge.requestedAttributes as string[],
      challenge.requestedPredicates,
      challenge.verifierId,
      proofTimestamp,
      proofSalt
    );

    const bbsProof = await createSelectiveDisclosureProof(
      credential.bbsSignature,
      messages,
      revealedIndices,
      credential.issuerBbsPublicKey,
      nonce
    );

    const predicates: ProofPredicate[] = challenge.requestedPredicates.map((pred) => {
      const actualValue = (credential.attributes as any)[pred.attribute];
      let satisfied = false;
      switch (pred.operation) {
        case '>':  satisfied = actualValue > pred.threshold; break;
        case '>=': satisfied = actualValue >= pred.threshold; break;
        case '<':  satisfied = actualValue < pred.threshold; break;
        case '<=': satisfied = actualValue <= pred.threshold; break;
        case '==': satisfied = actualValue == pred.threshold; break;
        case '!=': satisfied = actualValue != pred.threshold; break;
      }

      const rangeProof = satisfied
        ? generateRangeProof(
            Number(actualValue),
            pred.operation as '>' | '>=' | '<' | '<=' | '==' | '!=',
            Number(pred.threshold),
            nonce
          )
        : null;

      return {
        attribute: pred.attribute,
        operation: pred.operation,
        threshold: pred.threshold,
        satisfied,
        rangeProof,
      };
    });

    const rootBlind = generateNonce();
    const blindedRoot = createHash('sha256')
      .update(credential.credentialRoot)
      .update(rootBlind)
      .digest('hex');

    const proof: SelectiveDisclosureProof = {
      proofId: generateId(),
      revocationIndex: credential.revocationIndex,
      verifierId: challenge.verifierId,
      verifierChallenge: nonce,
      proofSalt,
      disclosedAttributes,
      bbsProof,
      blindedRoot,
      rootBlind,
      credentialRoot: credential.credentialRoot,
      dilithiumSignature: credential.dilithiumSignature,
      dilithiumBinding: credential.dilithiumBinding,
      issuerDid: credential.issuerDid,
      issuanceDate: credential.issuanceDate,
      issuerDilithiumPublicKey: credential.issuerDilithiumPublicKey,
      issuerBbsPublicKey: credential.issuerBbsPublicKey,
      predicates,
      totalMessageCount: TOTAL_MESSAGE_COUNT,
      timestamp: proofTimestamp,
    };

    if (challenge.linkable) {
      const holderKey = this.pseudonymKeys.get(credentialId);
      if (!holderKey) throw new Error(
        `No pseudonym key for credential ${credentialId} — call preparePseudonymCommitment first`
      );
      const pseudonym = derivePseudonym(holderKey, challenge.verifierId);
      const pseudonymProof = generatePseudonymProof(
        holderKey, challenge.verifierId, pseudonym,
        credential.pseudonymKeyCommitment, nonce
      );
      proof.pseudonym = pseudonym;
      proof.pseudonymProof = pseudonymProof;
      proof.pseudonymKeyCommitment = credential.pseudonymKeyCommitment;
    }

    console.log(
      `[Holder H] Proof generated for Verifier ${challenge.verifierId}, disclosed: ${Object.keys(disclosedAttributes).join(', ')}`
    );
    return proof;
  }

  listCredentials(): { id: string; issuerDid: string; expiryDate: string }[] {
    return Array.from(this.credentials.values()).map((c) => ({
      id: c.id,
      issuerDid: c.issuerDid,
      expiryDate: c.expiryDate,
    }));
  }
}

export async function createHolder(holderId: string): Promise<Holder> {
  return new Holder(holderId);
}
