import { randomInt } from 'crypto';
import {
  generateBbsKeyPair,
  generateDilithiumKeyPair,
  encodeAttributesToMessages,
  computeCredentialRoot,
  computeDilithiumBinding,
  bbsSign,
  bbsVerifySignature,
  dilithiumSign,
  dilithiumVerify,
  nowISO, futureISO, generateId, toHex,
  TOTAL_MESSAGE_COUNT,
} from '../utils/crypto';

import {
  CredentialAttributes, SignedCredential,
  IssuerKeyPair, AttributeSchema, DEFAULT_SCHEMA,
} from '../utils/types';

interface RevocationEntry {
  index: number;
  revoked: boolean;
}

export class Issuer {
  private keyPair: IssuerKeyPair | null = null;
  private readonly issuerId: string;
  private readonly issuerName: string;
  private revocationRegistry: Map<string, RevocationEntry> = new Map();
  private usedIndices: Set<number> = new Set();          
  private issuedCredentials: Map<string, SignedCredential> = new Map();

  constructor(issuerId: string, issuerName: string) {
    this.issuerId = issuerId;
    this.issuerName = issuerName;
  }

  async initialize(): Promise<void> {
    console.log(`\n[Issuer I: ${this.issuerName}] Initializing dual key pair...`);
    const [bbs, dil] = await Promise.all([generateBbsKeyPair(), generateDilithiumKeyPair()]);
    this.keyPair = {
      bbsPublicKey:       bbs.publicKey,
      bbsSecretKey:       bbs.secretKey,
      dilithiumPublicKey: dil.publicKey,
      dilithiumSecretKey: dil.secretKey,
    };
    console.log(`[Issuer I] BBS+ public key      (${bbs.publicKey.length}B): ${toHex(bbs.publicKey).slice(0,24)}...`);
    console.log(`[Issuer I] Dilithium public key (${dil.publicKey.length}B): ${toHex(dil.publicKey).slice(0,24)}...`);
    console.log(`[Issuer I] Both secret keys secured.`);
  }

  getBbsPublicKey(): Uint8Array { this.ensureInit(); return this.keyPair!.bbsPublicKey; }
  getDilithiumPublicKey(): Uint8Array { this.ensureInit(); return this.keyPair!.dilithiumPublicKey; }
  getDid(): string { return `did:example:issuer-${this.issuerId}`; }

  async issueCredential(
    attributes: CredentialAttributes,
    pseudonymKeyCommitment: string,          
    schema: AttributeSchema = DEFAULT_SCHEMA
  ): Promise<SignedCredential> {
    this.ensureInit();
    console.log(`\n[Issuer I] Issuing credential to Holder H (id: ${attributes.credentialId.slice(0,8)}...)`);
    this.validateAttributes(attributes);

    const revocationIndex = this.assignRevocationSlot(attributes.credentialId);
    const issuanceDate = nowISO();
    const expiryDate = futureISO(365);

    const messages = encodeAttributesToMessages({
      ...attributes,
      issuanceDate,
      revocationIndex,
      pseudonymKeyCommitment,
    });

    console.log(`[Issuer I] Encoding ${messages.length} attribute messages for BBS+ signing...`);
    const credentialRoot = computeCredentialRoot(messages);
    console.log(`[Issuer I] Credential root (SHA-256): ${credentialRoot.slice(0, 32)}...`);

    const dilithiumBindingBytes = computeDilithiumBinding(
      this.keyPair!.bbsPublicKey, this.getDid(), credentialRoot, issuanceDate
    );
    const dilithiumBindingHex = Buffer.from(dilithiumBindingBytes).toString('hex');

    console.log(`[Issuer I] BBS+ signing ${messages.length} messages (classical layer)...`);
    const bbsSignature = await bbsSign(messages, this.keyPair!.bbsSecretKey, this.keyPair!.bbsPublicKey);
    console.log(`[Issuer I] BBS+ signature: ${bbsSignature.length}B`);

    console.log(`[Issuer I] Dilithium ML-DSA-65 signing dilithiumBinding (PQC layer)...`);
    const dilithiumSignature = dilithiumSign(dilithiumBindingBytes, this.keyPair!.dilithiumSecretKey);
    console.log(`[Issuer I] Dilithium signature: ${dilithiumSignature.length}B (NIST FIPS 204)`);

    const credential: SignedCredential = {
      id: attributes.credentialId,
      issuerDid: this.getDid(),
      issuanceDate,
      expiryDate,
      attributes,
      schema,
      bbsSignature,
      dilithiumSignature,
      credentialRoot,
      dilithiumBinding: dilithiumBindingHex,
      pseudonymKeyCommitment,
      issuerBbsPublicKey: this.keyPair!.bbsPublicKey,
      issuerDilithiumPublicKey: this.keyPair!.dilithiumPublicKey,
      revocationIndex,
    };

    this.issuedCredentials.set(attributes.credentialId, credential);
    console.log(`[Issuer I] Dual-signed credential issued. Revocation slot: ${revocationIndex}`);
    return credential;
  }

  async verifyBbsSignature(credential: SignedCredential): Promise<boolean> {
    this.ensureInit();
    const messages = encodeAttributesToMessages({
      ...credential.attributes,
      issuanceDate: credential.issuanceDate,
      revocationIndex: credential.revocationIndex,
      pseudonymKeyCommitment: credential.pseudonymKeyCommitment,
    });
    return bbsVerifySignature(messages, credential.bbsSignature, credential.issuerBbsPublicKey);
  }

  async verifyDilithiumSignature(credential: SignedCredential): Promise<boolean> {
    const binding = computeDilithiumBinding(
      credential.issuerBbsPublicKey,
      credential.issuerDid,
      credential.credentialRoot,
      credential.issuanceDate
    );
    return dilithiumVerify(binding, credential.dilithiumSignature, credential.issuerDilithiumPublicKey);
  }

  revokeCredential(credentialId: string): void {
    const entry = this.revocationRegistry.get(credentialId);
    if (!entry) throw new Error(`Credential ${credentialId} not found`);
    entry.revoked = true;
    console.log(`[Issuer I]  Credential ${credentialId.slice(0,8)}... REVOKED (slot ${entry.index})`);
  }

  isRevoked(credentialId: string): boolean {
    return this.revocationRegistry.get(credentialId)?.revoked ?? false;
  }

  isIndexRevoked(index: number): boolean {
    for (const e of this.revocationRegistry.values()) {
      if (e.index === index) return e.revoked;
    }
    return false;
  }

  getRevocationStatusList(): { size: number; revokedIndices: number[] } {
    const revokedIndices: number[] = [];
    for (const e of this.revocationRegistry.values()) {
      if (e.revoked) revokedIndices.push(e.index);
    }
    return { size: this.usedIndices.size, revokedIndices };  
  }

  printSummary(): void {
    console.log(`\n[Issuer I: ${this.issuerName}] Summary:`);
    console.log(`  Total credentials issued: ${this.issuedCredentials.size}`);
    for (const [id, cred] of this.issuedCredentials) {
      const e = this.revocationRegistry.get(id);
      const status = e?.revoked ? ' REVOKED' : ' VALID';
      console.log(`  Slot ${e?.index}: ${id.slice(0,12)}... | ${status}`);
    }
  }

  private ensureInit(): void {
    if (!this.keyPair) throw new Error('[Issuer I] Not initialized. Call initialize() first.');
  }

  private validateAttributes(a: CredentialAttributes): void {
    if (!a.attr_1?.trim()) throw new Error('attr_1 (string) is required');
    if (typeof a.attr_2 !== 'number' || a.attr_2 < 0 || a.attr_2 > 150)
      throw new Error(`attr_2 (numeric) out of range: ${a.attr_2}`);
    if (typeof a.attr_3 !== 'number' || a.attr_3 < 0)
      throw new Error(`attr_3 (numeric) cannot be negative`);
    if (!a.credentialId?.trim()) throw new Error('credentialId is required');
  }

  private assignRevocationSlot(credentialId: string): number {
    let index: number;
    do { index = randomInt(0, 2 ** 31); } while (this.usedIndices.has(index));
    this.usedIndices.add(index);
    this.revocationRegistry.set(credentialId, { index, revoked: false });
    return index;
  }
}

export async function createIssuer(id: string, name: string): Promise<Issuer> {
  const issuer = new Issuer(id, name);
  await issuer.initialize();
  return issuer;
}
