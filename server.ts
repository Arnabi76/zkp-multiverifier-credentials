import express, { Request, Response } from 'express';
import cors from 'cors';
import { createIssuer, Issuer } from '../src/issuer/issuer';
import { createHolder, Holder } from '../src/holder/holder';
import { createVerifierA, createVerifierB, createVerifierC, Verifier } from '../src/verifier/verifier';
import { toW3CVC } from '../src/w3c/vc-wrapper';
import { generateId } from '../src/utils/crypto';
import {
  SignedCredential,
  SelectiveDisclosureProof,
  VerificationResult,
} from '../src/utils/types';

const app = express();
const PORT = 3001;

app.use(cors({ origin: '*' }));
app.use(express.json());

let issuer: Issuer;
let holder: Holder;
let verifierA: Verifier;
let verifierB: Verifier;
let verifierC: Verifier;

const PROOF_TTL_MS = 10 * 60 * 1000; 
const proofStore = new Map<string, { proof: SelectiveDisclosureProof; verifierId: string; expiresAt: number }>();

function pruneExpiredProofs() {
  const now = Date.now();
  for (const [id, entry] of proofStore) {
    if (entry.expiresAt < now) proofStore.delete(id);
  }
}

function getVerifier(verifierId: string): Verifier | null {
  if (verifierId === 'V-A') return verifierA;
  if (verifierId === 'V-B') return verifierB;
  if (verifierId === 'V-C') return verifierC;
  return null;
}

async function init() {
  console.log('Initializing ZKP System...');
  issuer = await createIssuer('demo', 'Issuer I');
  holder = await createHolder('holder-demo');

  verifierA = await createVerifierA((idx) => issuer.isIndexRevoked(idx));
  verifierB = await createVerifierB((idx) => issuer.isIndexRevoked(idx));
  verifierC = await createVerifierC((idx) => issuer.isIndexRevoked(idx));
  console.log('ZKP System initialized with Verifiers A, B, and C');
}

app.post('/api/issue', async (req: Request, res: Response) => {
  try {
    const { attr_1, attr_2, attr_3, attr_4, attr_5 } = req.body;
    const credentialId = generateId();

    const numAttr2 = Number(attr_2);
    const numAttr3 = Number(attr_3);
    if (!String(attr_1)?.trim()) return res.status(400).json({ success: false, error: 'attr_1 is required' });
    if (isNaN(numAttr2)) return res.status(400).json({ success: false, error: 'attr_2 must be a number' });
    if (isNaN(numAttr3)) return res.status(400).json({ success: false, error: 'attr_3 must be a number' });
    if (!String(attr_5)?.trim()) return res.status(400).json({ success: false, error: 'attr_5 is required' });


    const pseudonymKeyCommitment = holder.preparePseudonymCommitment(credentialId);

    const credential: SignedCredential = await issuer.issueCredential({
      attr_1: String(attr_1),
      attr_2: numAttr2,
      attr_3: numAttr3,
      attr_4: attr_4 === true || attr_4 === 'true', 
      attr_5: String(attr_5),
      credentialId,
    }, pseudonymKeyCommitment);

    holder.storeCredential(credential);
    const w3cVC = toW3CVC(credential);

    res.json({
      success: true,
      credentialId,
      w3cVC,
      bbsSignatureSize: credential.bbsSignature.length,
      dilithiumSignatureSize: credential.dilithiumSignature.length,
      credentialRoot: credential.credentialRoot,
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/challenge/:verifierId', (req: Request, res: Response) => {
  try {
    const verifierId = String(req.params.verifierId);
    const verifier = getVerifier(verifierId);

    if (!verifier) {
      return res.status(400).json({
        success: false,
        error: `Unknown verifierId: ${verifierId}. Must be V-A, V-B, or V-C.`,
      });
    }

    const challenge = verifier.issueChallenge();
    res.json({ challenge });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/prove', async (req: Request, res: Response) => {
  try {
    const { credentialId, verifierId } = req.body as {
      credentialId: string;
      verifierId: string;
    };

    const verifier = getVerifier(verifierId);
    if (!verifier) {
      return res.status(400).json({ success: false, error: `Unknown verifierId: ${verifierId}` });
    }


    const challenge = verifier.issueChallenge();
    const proof = await holder.generateProof(credentialId, challenge);

    proofStore.set(proof.proofId, { proof, verifierId, expiresAt: Date.now() + PROOF_TTL_MS });

    res.json({
      success: true,
      proofId: proof.proofId,
      verifierId,
      disclosedAttributes: proof.disclosedAttributes,
      predicates: proof.predicates.map(p => ({
        attribute: p.attribute,
        operation: p.operation,
        threshold: p.threshold,
        satisfied: p.satisfied ?? null,
      })),
      bbsProofSize: proof.bbsProof.length,
      totalProofSize: proof.bbsProof.length + proof.dilithiumSignature.length + (proof.pseudonymProof ? proof.pseudonymProof.length : 0),
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/verify', async (req: Request, res: Response) => {
  try {
    const { proofId, verifierId: clientVerifierId } = req.body as { proofId: string; verifierId?: string };

    pruneExpiredProofs();
    const entry = proofStore.get(proofId);
    if (!entry || entry.expiresAt < Date.now()) {
      return res.status(400).json({ success: false, error: 'Proof not found' });
    }

    if (clientVerifierId && clientVerifierId !== entry.verifierId) {
      return res.status(400).json({ success: false, error: `verifierId mismatch: proof belongs to ${entry.verifierId}` });
    }

    const { proof, verifierId } = entry;
    proofStore.delete(proofId); 
    const verifier = getVerifier(verifierId);

    if (!verifier) {
      return res.status(400).json({ success: false, error: `Unknown verifierId: ${verifierId}` });
    }

    const result = await verifier.verifyProof(proof);

    res.json({
      verified: result.verified,
      bbsVerified: result.bbsVerified,
      dilithiumVerified: result.dilithiumVerified,
      isRevoked: result.isRevoked,
      disclosedAttributes: result.disclosedAttributes,
      predicateResults: result.predicateResults,
      timingMs: result.timingMs,
    });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/revoke', (req: Request, res: Response) => {
  try {
    const { credentialId } = req.body as { credentialId: string };
    issuer.revokeCredential(credentialId);
    res.json({ success: true, credentialId });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/api/status', (_req: Request, res: Response) => {
  res.json({
    issuerReady: true,
    holderCredentials: holder ? holder.listCredentials().length : 0,
    verifiers: ['V-A', 'V-B', 'V-C'],
  });
});

init().then(() => {
  app.listen(PORT, () => {
    console.log(`ZKP API server running at http://localhost:${PORT}`);
  });
}).catch(err => {
  console.error('Failed to initialize:', err);
  process.exit(1);
});
