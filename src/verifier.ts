import { createHash } from 'crypto';
import {
  verifySelectiveDisclosureProof,
  computeDilithiumBinding,
  dilithiumVerify,
  verifyPseudonymProof,
  deriveNonce,
  nowISO,
  ATTRIBUTE_INDEX,
  verifyRangeProof,
} from '../utils/crypto';
import {
  SelectiveDisclosureProof,
  VerifierChallenge,
  VerificationResult,
  CredentialAttributes,
} from '../utils/types';

export interface VerifierConfig {
  requiredAttributes: (keyof CredentialAttributes)[];
  requiredPredicates: {
    attribute: keyof CredentialAttributes;
    operation: '>' | '>=' | '<' | '<=' | '==' | '!=';
    threshold: number | string | boolean;
  }[];
  isRevoked: (revocationIndex: number) => boolean;  
  linkable: boolean;                                
}

export class Verifier {
  readonly verifierId: string;
  private verifierName: string;
  private config: VerifierConfig;
  private seenProofs: Map<string, number> = new Map();
  private verificationLog: VerificationResult[];
  private static readonly SEEN_PROOF_TTL_MS = 10 * 60 * 1000;

  constructor(verifierId: string, verifierName: string, config: VerifierConfig) {
    this.verifierId = verifierId;
    this.verifierName = verifierName;
    this.config = config;
    this.verificationLog = [];
  }

  issueChallenge(): VerifierChallenge {
    return {
      verifierId: this.verifierId,
      requestedAttributes: this.config.requiredAttributes,
      requestedPredicates: this.config.requiredPredicates,
      issuedAt: new Date().toISOString(),
      linkable: this.config.linkable ?? false,
    };
  }

  async verifyProof(proof: SelectiveDisclosureProof): Promise<VerificationResult> {
    const startTime = Date.now();

    const buildResult = (
      verified: boolean,
      bbsVerified: boolean,
      dilithiumVerified: boolean,
      isRevoked: boolean,
      predicateResults: { predicate: string; satisfied: boolean }[]
    ): VerificationResult => ({
      verified,
      verifierId: this.verifierId,
      proofId: proof.proofId,
      bbsVerified,
      dilithiumVerified,
      disclosedAttributes: proof.disclosedAttributes,
      predicateResults,
      isRevoked,
      timestamp: nowISO(),
      timingMs: Date.now() - startTime,
    });

    const now = Date.now();
    for (const [id, expiry] of this.seenProofs) {
      if (expiry < now) this.seenProofs.delete(id);
    }

    if (this.seenProofs.has(proof.proofId)) {
      console.log(`[Verifier ${this.verifierName}] Proof REJECTED | Replayed proofId`);
      const r = buildResult(false, false, false, false, []);
      this.verificationLog.push(r); return r;
    }
    this.seenProofs.set(proof.proofId, now + Verifier.SEEN_PROOF_TTL_MS);

    if (Date.now() - new Date(proof.timestamp).getTime() > 5 * 60 * 1000) {
      console.log(`[Verifier ${this.verifierName}] Proof REJECTED | Stale timestamp`);
      const r = buildResult(false, false, false, false, []);
      this.verificationLog.push(r); return r;
    }

    const expectedNonce = deriveNonce(
      proof.revocationIndex.toString(),
      this.config.requiredAttributes as string[],
      this.config.requiredPredicates,
      this.verifierId,
      proof.timestamp,
      proof.proofSalt
    );
    if (expectedNonce !== proof.verifierChallenge) {
      console.log(`[Verifier ${this.verifierName}] Proof REJECTED | Bad Fiat-Shamir nonce`);
      const r = buildResult(false, false, false, false, []);
      this.verificationLog.push(r); return r;
    }

    if (this.config.linkable) {
      if (!proof.pseudonym || !proof.pseudonymProof || !proof.pseudonymKeyCommitment) {
        console.log(`[Verifier ${this.verifierName}] Proof REJECTED | Missing pseudonym fields`);
        const r = buildResult(false, false, false, false, []);
        this.verificationLog.push(r); return r;
      }
      const pseudonymOk = verifyPseudonymProof(
        proof.pseudonym, proof.pseudonymKeyCommitment,
        this.verifierId, proof.pseudonymProof, proof.verifierChallenge
      );
      if (!pseudonymOk) {
        console.log(`[Verifier ${this.verifierName}] Proof REJECTED | Invalid pseudonym proof`);
        const r = buildResult(false, false, false, false, []);
        this.verificationLog.push(r); return r;
      }
    } else {
      if (proof.pseudonym !== undefined) {
        console.log(`[Verifier ${this.verifierName}] Proof REJECTED | Unexpected pseudonym on non-linkable verifier`);
        const r = buildResult(false, false, false, false, []);
        this.verificationLog.push(r); return r;
      }
    }

    const encoder = new TextEncoder();
    const revealedMessages: { index: number; value: Uint8Array }[] = [];
    for (const key of Object.keys(proof.disclosedAttributes) as (keyof CredentialAttributes)[]) {
      const idx = ATTRIBUTE_INDEX[key];
      if (idx !== undefined) {
        revealedMessages.push({
          index: idx,
          value: encoder.encode(`${key}:${proof.disclosedAttributes[key]}`),
        });
      }
    }
    if (this.config.linkable && proof.pseudonymKeyCommitment) {
      revealedMessages.push({
        index: ATTRIBUTE_INDEX['pseudonymKeyCommitment'],
        value: encoder.encode(`pseudonymKeyCommitment:${proof.pseudonymKeyCommitment}`),
      });
    }
    revealedMessages.sort((a, b) => a.index - b.index);

    let bbsVerified = false;
    try {
      bbsVerified = await verifySelectiveDisclosureProof(
        proof.bbsProof,
        revealedMessages,
        proof.issuerBbsPublicKey,
        proof.verifierChallenge
      );
    } catch { bbsVerified = false; }

    const isRevoked = this.config.isRevoked(proof.revocationIndex);

    const predicateResults: { predicate: string; satisfied: boolean }[] = [];
    let predicatesOk = true;

    if (proof.predicates.length !== this.config.requiredPredicates.length) {
      console.log(`[Verifier ${this.verifierName}] Proof REJECTED | Predicate count mismatch (got ${proof.predicates.length}, need ${this.config.requiredPredicates.length})`);
      const r = buildResult(false, bbsVerified, false, isRevoked, []);
      this.verificationLog.push(r); return r;
    }
    for (let i = 0; i < this.config.requiredPredicates.length; i++) {
      const req = this.config.requiredPredicates[i];
      const got = proof.predicates[i];
      if (got.attribute !== req.attribute || got.operation !== req.operation ||
          String(got.threshold) !== String(req.threshold)) {
        console.log(`[Verifier ${this.verifierName}] Proof REJECTED | Predicate mismatch at index ${i}`);
        const r = buildResult(false, bbsVerified, false, isRevoked, []);
        this.verificationLog.push(r); return r;
      }
    }

    for (const p of proof.predicates) {
      const label = `${p.attribute} ${p.operation} ${p.threshold}`;

      if (!p.satisfied) {
        predicateResults.push({ predicate: label, satisfied: false });
        predicatesOk = false;
        continue;
      }

      if (['>', '>=', '<', '<='].includes(p.operation)) {
        if (!p.rangeProof) {
          console.log(`[Verifier ${this.verifierName}] Predicate FAILED | Missing range proof for ${label}`);
          predicateResults.push({ predicate: label, satisfied: false });
          predicatesOk = false;
          continue;
        }
        const proofValid = verifyRangeProof(p.rangeProof, proof.verifierChallenge);
        if (!proofValid) {
          console.log(`[Verifier ${this.verifierName}] Predicate FAILED | Invalid ZK range proof for ${label}`);
          predicateResults.push({ predicate: label, satisfied: false });
          predicatesOk = false;
          continue;
        }
      }
      if (p.operation === '==' || p.operation === '!=') {
        const attrKey = p.attribute as keyof typeof proof.disclosedAttributes;
        const disclosedVal = proof.disclosedAttributes[attrKey];
        if (disclosedVal === undefined) {
          console.log(`[Verifier ${this.verifierName}] Predicate FAILED | ${p.operation} predicate requires attribute '${p.attribute}' to be disclosed`);
          predicateResults.push({ predicate: label, satisfied: false });
          predicatesOk = false;
          continue;
        }
        const actualSatisfied =
          p.operation === '==' ? String(disclosedVal) === String(p.threshold)
                               : String(disclosedVal) !== String(p.threshold);
        if (!actualSatisfied) {
          predicateResults.push({ predicate: label, satisfied: false });
          predicatesOk = false;
          continue;
        }
        predicateResults.push({ predicate: label, satisfied: true });
        continue;
      }

      const knownOps = ['>', '>=', '<', '<=', '==', '!='];
      if (!knownOps.includes(p.operation)) {
        console.log(`[Verifier ${this.verifierName}] Predicate FAILED | Unknown operation '${p.operation}'`);
        predicateResults.push({ predicate: label, satisfied: false });
        predicatesOk = false;
        continue;
      }

      predicateResults.push({ predicate: label, satisfied: true });
    }

    let dilithiumVerified = false;
    try {
      const recomputedBinding = computeDilithiumBinding(
        proof.issuerBbsPublicKey,
        proof.issuerDid,
        proof.credentialRoot,       
        proof.issuanceDate
      );
      const bindingMatches =
        Buffer.from(recomputedBinding).toString('hex') === proof.dilithiumBinding;

      if (bindingMatches) {
        dilithiumVerified = dilithiumVerify(
          recomputedBinding,
          proof.dilithiumSignature,
          proof.issuerDilithiumPublicKey
        );
      }
    } catch {
      dilithiumVerified = false;
    }

    if (!dilithiumVerified) {
      console.log(`[Verifier ${this.verifierName}] Proof REJECTED | Dilithium ML-DSA-65 verification failed`);
    }

    const verified = bbsVerified && dilithiumVerified && !isRevoked && predicatesOk;
    const result = buildResult(verified, bbsVerified, dilithiumVerified, isRevoked, predicateResults);

    console.log(
      `[Verifier ${this.verifierName}] Proof ${verified ? 'ACCEPTED' : 'REJECTED'} | ` +
      `BBS+:${bbsVerified} DIL(ML-DSA-65):${dilithiumVerified} REV:${isRevoked} PRED:${predicatesOk} | ${result.timingMs}ms`
    );
    this.verificationLog.push(result);
    return result;
  }

  async auditDilithium(proof: SelectiveDisclosureProof, originalCredentialRoot: string): Promise<boolean> {
    const expected = createHash('sha256')
      .update(originalCredentialRoot)
      .update(proof.rootBlind)
      .digest('hex');
    if (expected !== proof.blindedRoot) return false;
    const binding = computeDilithiumBinding(
      proof.issuerBbsPublicKey, proof.issuerDid, originalCredentialRoot, proof.issuanceDate
    );
    return dilithiumVerify(binding, proof.dilithiumSignature, proof.issuerDilithiumPublicKey);
  }

  getLog(): VerificationResult[] { return this.verificationLog; }
}

export async function createVerifierA(isRevoked: (idx: number) => boolean): Promise<Verifier> {
  return new Verifier('V-A', 'Verifier A', {
    requiredAttributes: ['attr_2', 'attr_5'],
    requiredPredicates: [{ attribute: 'attr_3', operation: '>', threshold: 50000 }],
    isRevoked,
    linkable: false,
  });
}

export async function createVerifierB(isRevoked: (idx: number) => boolean): Promise<Verifier> {
  return new Verifier('V-B', 'Verifier B', {
    requiredAttributes: ['attr_4'],
    requiredPredicates: [{ attribute: 'attr_2', operation: '>=', threshold: 18 }],
    isRevoked,
    linkable: true,   
  });
}

export async function createVerifierC(isRevoked: (idx: number) => boolean): Promise<Verifier> {
  return new Verifier('V-C', 'Verifier C', {
    requiredAttributes: ['attr_1', 'attr_5'],
    requiredPredicates: [{ attribute: 'attr_2', operation: '<', threshold: 50 }],
    isRevoked,
    linkable: false,
  });
}
