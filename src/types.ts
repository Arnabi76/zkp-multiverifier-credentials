export interface CredentialAttributes 
{
  attr_1: string;
  attr_2: number;
  attr_3: number;
  attr_4: boolean;
  attr_5: string;
  credentialId: string;
}

export interface AttributeSchema 
{
  attr_1: string;
  attr_2: string;
  attr_3: string;
  attr_4: string;
  attr_5: string;
}

export const DEFAULT_SCHEMA: AttributeSchema = {
  attr_1: 'identifier',
  attr_2: 'age',
  attr_3: 'score',
  attr_4: 'status',
  attr_5: 'category',
};

export interface IssuerKeyPair {
  bbsPublicKey: Uint8Array;
  bbsSecretKey: Uint8Array;
  dilithiumPublicKey: Uint8Array;
  dilithiumSecretKey: Uint8Array;
}

export interface SignedCredential {
  id: string;
  issuerDid: string;
  issuanceDate: string;
  expiryDate: string;
  attributes: CredentialAttributes;
  schema: AttributeSchema;
  bbsSignature: Uint8Array;
  dilithiumSignature: Uint8Array;
  credentialRoot: string;
  dilithiumBinding: string;        
  pseudonymKeyCommitment: string;  
  issuerBbsPublicKey: Uint8Array;
  issuerDilithiumPublicKey: Uint8Array;
  revocationIndex: number;
}

export interface SelectiveDisclosureProof {
  proofId: string;
  revocationIndex: number;
  verifierId: string;
  verifierChallenge: string;       
  proofSalt: string;               
  disclosedAttributes: Partial<CredentialAttributes>;
  bbsProof: Uint8Array;
  blindedRoot: string;             
  rootBlind: string;               
  credentialRoot: string;          
  dilithiumSignature: Uint8Array;
  dilithiumBinding: string;        
  issuerDid: string;               
  issuanceDate: string;            
  issuerDilithiumPublicKey: Uint8Array;
  issuerBbsPublicKey: Uint8Array;
  predicates: ProofPredicate[];
  totalMessageCount: number;
  timestamp: string;
  pseudonym?: string;
  pseudonymProof?: Uint8Array;
  pseudonymKeyCommitment?: string;
}

export interface ProofPredicate {
  attribute: keyof CredentialAttributes;
  operation: '>' | '>=' | '<' | '<=' | '==' | '!=';
  threshold: number | string | boolean;
  satisfied: boolean;
  rangeProof: import('./crypto').RangeProof | null;
}

export interface VerifierChallenge {
  issuedAt: string;
  linkable: boolean;               
  verifierId: string;
  requestedAttributes: (keyof CredentialAttributes)[];
  requestedPredicates: {
    attribute: keyof CredentialAttributes;
    operation: '>' | '>=' | '<' | '<=' | '==' | '!=';
    threshold: number | string | boolean;
  }[];
}

export interface VerificationResult {
  verified: boolean;
  verifierId: string;
  proofId: string;
  bbsVerified: boolean;
  dilithiumVerified: boolean;  
  disclosedAttributes: Partial<CredentialAttributes>;
  predicateResults: { predicate: string; satisfied: boolean }[];
  isRevoked: boolean;
  timestamp: string;
  timingMs: number;
}

export interface BenchmarkResult {
  operation: string;
  proverTimeMs: number;
  verifierTimeMs: number;
  proofSizeBytes: number;
  endToEndMs: number;
  bbsProofBytes: number;
  dilithiumSigBytes: number;
}
