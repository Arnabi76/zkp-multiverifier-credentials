import { createHash } from 'crypto';
import { SignedCredential } from '../utils/types';

export interface W3CVCProof {
  type: string;
  created: string;
  verificationMethod: string;
  proofPurpose: string;
  proofValue: string;
  securityLevel?: string;
  signedData?: string;
}

export interface W3CVCCredentialStatus {
  id: string;
  type: string;
  statusListIndex: string;
  statusListCredential: string;
}

export interface W3CVCCredentialSubject {
  id: string;
  schema: Record<string, string>;
  commitments: {
    attr_1: string;
    attr_2: string;
    attr_3: string;
    attr_4: string;
    attr_5: string;
  };
  credentialRoot: string;
  revocationIndex: number;
}

export interface W3CVC {
  '@context': string[];
  id: string;
  type: string[];
  issuer: { id: string; name: string };
  validFrom: string;
  validUntil: string;
  credentialSubject: W3CVCCredentialSubject;
  proof: W3CVCProof[];
  credentialStatus: W3CVCCredentialStatus;
}

function sha256Commitment(value: string | number | boolean): string {
  return 'sha256:' + createHash('sha256').update(String(value)).digest('hex');
}

function toBase64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

function fromBase64url(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, 'base64url'));
}

export function toW3CVC(credential: SignedCredential): W3CVC {
  const { id, issuerDid, issuanceDate, expiryDate, attributes, schema,
          bbsSignature, dilithiumSignature, credentialRoot, revocationIndex } = credential;

  return {
    '@context': [
      'https://www.w3.org/ns/credentials/v2',
      'https://www.w3.org/ns/credentials/examples/v2',
    ],
    id: `urn:uuid:${id}`,
    type: ['VerifiableCredential', 'ZKPAttributeCredential'],
    issuer: { id: issuerDid, name: 'Issuer I' },
    validFrom: issuanceDate,
    validUntil: expiryDate,
    credentialSubject: {
      id: `urn:holder:${id}`,
      schema: { ...schema },
      commitments: {
        attr_1: sha256Commitment(attributes.attr_1),
        attr_2: sha256Commitment(attributes.attr_2),
        attr_3: sha256Commitment(attributes.attr_3),
        attr_4: sha256Commitment(attributes.attr_4),
        attr_5: sha256Commitment(attributes.attr_5),
      },
      credentialRoot,
      revocationIndex,
    },
    proof: [
      {
        type: 'BbsBlsSignature2020',
        created: issuanceDate,
        verificationMethod: `${issuerDid}#bbs-key-1`,
        proofPurpose: 'assertionMethod',
        proofValue: toBase64url(bbsSignature),
      },
      {
        type: 'MlDsa65Signature2026',
        created: issuanceDate,
        verificationMethod: `${issuerDid}#dilithium-key-1`,
        proofPurpose: 'assertionMethod',
        proofValue: toBase64url(dilithiumSignature),
        securityLevel: 'NIST-FIPS-204-ML-DSA-65',
        signedData: 'dilithiumBinding',
      },
    ],
    credentialStatus: {
      id: `${issuerDid}/revocation/${revocationIndex}`,
      type: 'StatusList2021Entry',
      statusListIndex: String(revocationIndex),
      statusListCredential: `${issuerDid}/revocation-list`,
    },
  };
}


export function fromW3CVC(vc: W3CVC): Partial<SignedCredential> {
  const bbsProof = vc.proof.find(p => p.type === 'BbsBlsSignature2020');
  const dilProof = vc.proof.find(p => p.type === 'MlDsa65Signature2026');

  return {
    id: vc.id.replace('urn:uuid:', ''),
    issuerDid: vc.issuer.id,
    issuanceDate: vc.validFrom,
    expiryDate: vc.validUntil,
    credentialRoot: vc.credentialSubject.credentialRoot,
    revocationIndex: vc.credentialSubject.revocationIndex,
    bbsSignature: bbsProof ? fromBase64url(bbsProof.proofValue) : undefined,
    dilithiumSignature: dilProof ? fromBase64url(dilProof.proofValue) : undefined,
  };
}

export function validateW3CVC(vc: W3CVC): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (!Array.isArray(vc['@context']) ||
      !vc['@context'].includes('https://www.w3.org/ns/credentials/v2')) {
    errors.push('@context must include "https://www.w3.org/ns/credentials/v2"');
  }

  if (!Array.isArray(vc.type) || !vc.type.includes('VerifiableCredential')) {
    errors.push('type must include "VerifiableCredential"');
  }

  if (!vc.id || !vc.id.startsWith('urn:')) {
    errors.push('id must start with "urn:"');
  }

  if (!vc.validFrom || isNaN(Date.parse(vc.validFrom))) {
    errors.push('validFrom must be a valid ISO date string');
  }

  if (!vc.credentialSubject?.credentialRoot ||
      !/^[0-9a-f]{64}$/.test(vc.credentialSubject.credentialRoot)) {
    errors.push('credentialSubject.credentialRoot must be a 64-char hex string');
  }

  if (!Array.isArray(vc.proof) || vc.proof.length !== 2) {
    errors.push('proof must be an array with exactly 2 entries');
  } else {
    if (vc.proof[0].type !== 'BbsBlsSignature2020') {
      errors.push('proof[0].type must be "BbsBlsSignature2020"');
    }
    if (vc.proof[1].type !== 'MlDsa65Signature2026') {
      errors.push('proof[1].type must be "MlDsa65Signature2026"');
    }
    if (!vc.proof[0].proofValue) {
      errors.push('proof[0].proofValue must be non-empty');
    }
    if (!vc.proof[1].proofValue) {
      errors.push('proof[1].proofValue must be non-empty');
    }
  }

  return { valid: errors.length === 0, errors };
}



export function w3cVcToJson(vc: W3CVC): string {
  return JSON.stringify(vc, null, 2);
}

export function w3cVcFromJson(json: string): W3CVC {
  return JSON.parse(json) as W3CVC;
}
