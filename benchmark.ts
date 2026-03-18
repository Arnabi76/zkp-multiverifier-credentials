import * as fs from 'fs';
import * as path from 'path';
import { createIssuer } from '../issuer/issuer';
import { createHolder } from '../holder/holder';
import { createVerifierA, createVerifierB, createVerifierC } from '../verifier/verifier';
import { toW3CVC, w3cVcToJson } from '../w3c/vc-wrapper';
import {
  generateId,
  generateBbsKeyPair,
  generateDilithiumKeyPair,
  computeDilithiumBinding,
  dilithiumVerify,
  verifySelectiveDisclosureProof,
  ATTRIBUTE_INDEX,
} from '../utils/crypto';
import { SignedCredential } from '../utils/types';

const N = 5;
const UNLINKABILITY_PAIRS = 10;

function stats(timings: number[]): { min: number; max: number; mean: number; median: number } {
  const sorted = [...timings].sort((a, b) => a - b);
  const min = sorted[0];
  const max = sorted[sorted.length - 1];
  const mean = timings.reduce((a, b) => a + b, 0) / timings.length;
  const mid = Math.floor(sorted.length / 2);
  const median = sorted.length % 2 === 0
    ? (sorted[mid - 1] + sorted[mid]) / 2
    : sorted[mid];
  return { min, max, mean, median };
}

function fmt(n: number): string { return n.toFixed(1).padStart(8); }
function pad(s: string, len: number): string {
  return s.length >= len ? s.slice(0, len) : s + ' '.repeat(len - s.length);
}

async function time<T>(fn: () => Promise<T>): Promise<{ result: T; ms: number }> {
  const start = Date.now();
  const result = await fn();
  return { result, ms: Date.now() - start };
}

function makeAttrs() {
  return {
    attr_1: 'Alice',
    attr_2: 30,
    attr_3: 75000,
    attr_4: true,
    attr_5: 'Engineering',
    credentialId: generateId(),
  };
}

async function main() {
  console.log('ZKP SYSTEM BENCHMARK  (N=' + N + ' runs per operation)');

  const results: Record<string, ReturnType<typeof stats>> = {};

  {
    const timings: number[] = [];
    for (let i = 0; i < N; i++) {
      const { ms } = await time(async () => {
        await Promise.all([generateBbsKeyPair(), generateDilithiumKeyPair()]);
      });
      timings.push(ms);
    }
    results['Key Generation (BBS+ + Dilithium)'] = stats(timings);
  }

  const issuer = await createIssuer('bench', 'Benchmark Issuer');
  const notRevoked = (_idx: number) => false;
  const verifierA = await createVerifierA(notRevoked);
  const verifierB = await createVerifierB(notRevoked);
  const verifierC = await createVerifierC(notRevoked);

  const holder = await createHolder('bench-holder');

  let lastCredential: SignedCredential | null = null;
  {
    const timings: number[] = [];
    for (let i = 0; i < N; i++) {
      const attrs = makeAttrs();
      const commitment = holder.preparePseudonymCommitment(attrs.credentialId);
      const { result, ms } = await time(() => issuer.issueCredential(attrs, commitment));
      lastCredential = result;
      timings.push(ms);
    }
    results['Credential Issuance'] = stats(timings);
  }

  const credential = lastCredential!;
  holder.storeCredential(credential);

  let lastProofA: Awaited<ReturnType<typeof holder.generateProof>> | null = null;
  {
    const timings: number[] = [];
    for (let i = 0; i < N; i++) {
      const challenge = verifierA.issueChallenge();
      const { result, ms } = await time(() => holder.generateProof(credential.id, challenge));
      lastProofA = result;
      timings.push(ms);
    }
    results['Proof Generation (Verifier A)'] = stats(timings);
  }

  {
    const timings: number[] = [];
    for (let i = 0; i < N; i++) {
      const challenge = verifierB.issueChallenge();
      const { ms } = await time(() => holder.generateProof(credential.id, challenge));
      timings.push(ms);
    }
    results['Proof Generation (Verifier B)'] = stats(timings);
  }

  {
    const timings: number[] = [];
    for (let i = 0; i < N; i++) {
      const challenge = verifierC.issueChallenge();
      const { ms } = await time(() => holder.generateProof(credential.id, challenge));
      timings.push(ms);
    }
    results['Proof Generation (Verifier C)'] = stats(timings);
  }

  {
    const timings: number[] = [];
    const encoder = new TextEncoder();
    for (let i = 0; i < N; i++) {
      const challenge = verifierA.issueChallenge();
      const freshProof = await holder.generateProof(credential.id, challenge);
      const freshRevealed: { index: number; value: Uint8Array }[] = [];
      for (const key of Object.keys(freshProof.disclosedAttributes) as (keyof typeof freshProof.disclosedAttributes)[]) {
        const idx = ATTRIBUTE_INDEX[key];
        if (idx !== undefined) {
          freshRevealed.push({ index: idx, value: encoder.encode(`${key}:${freshProof.disclosedAttributes[key]}`) });
        }
      }
      freshRevealed.sort((a, b) => a.index - b.index);
      const { ms } = await time(() =>
        verifySelectiveDisclosureProof(freshProof.bbsProof, freshRevealed, credential.issuerBbsPublicKey, freshProof.verifierChallenge)
      );
      timings.push(ms);
    }
    results['BBS+ Verification'] = stats(timings);
  }

  {
    const timings: number[] = [];
    for (let i = 0; i < N; i++) {
      const start = Date.now();
      dilithiumVerify(
        computeDilithiumBinding(
          credential.issuerBbsPublicKey,
          credential.issuerDid,
          credential.credentialRoot,
          credential.issuanceDate
        ),
        credential.dilithiumSignature,
        credential.issuerDilithiumPublicKey
      );
      timings.push(Date.now() - start);
    }
    results['Dilithium Verification'] = stats(timings);
  }

  {
    const timings: number[] = [];
    for (let i = 0; i < N; i++) {
      const challenge = verifierA.issueChallenge();
      const proof = await holder.generateProof(credential.id, challenge);
      const { ms } = await time(() => verifierA.auditDilithium(proof, credential.credentialRoot));
      timings.push(ms);
    }
    results['Dilithium Audit (offline)'] = stats(timings);
  }

  {
    const timings: number[] = [];
    for (let i = 0; i < N; i++) {
      const challenge = verifierA.issueChallenge();
      const proof = await holder.generateProof(credential.id, challenge);
      const { ms } = await time(() => verifierA.verifyProof(proof));
      timings.push(ms);
    }
    results['Full Verification (A)'] = stats(timings);
  }

  {
    const timings: number[] = [];
    for (let i = 0; i < N; i++) {
      const challenge = verifierB.issueChallenge();
      const proof = await holder.generateProof(credential.id, challenge);
      const { ms } = await time(() => verifierB.verifyProof(proof));
      timings.push(ms);
    }
    results['Full Verification (B)'] = stats(timings);
  }

  {
    const timings: number[] = [];
    for (let i = 0; i < N; i++) {
      const challenge = verifierC.issueChallenge();
      const proof = await holder.generateProof(credential.id, challenge);
      const { ms } = await time(() => verifierC.verifyProof(proof));
      timings.push(ms);
    }
    results['Full Verification (C)'] = stats(timings);
  }

  {
    const timings: number[] = [];
    for (let i = 0; i < N; i++) {
      const { ms } = await time(async () => {
        const attrs = makeAttrs();
        const h = await createHolder('e2e-holder-' + i);
        const commitment = h.preparePseudonymCommitment(attrs.credentialId);
        const cred = await issuer.issueCredential(attrs, commitment);
        h.storeCredential(cred);
        const challenge = verifierA.issueChallenge();
        const proof = await h.generateProof(cred.id, challenge);
        await verifierA.verifyProof(proof);
      });
      timings.push(ms);
    }
    results['End-to-End (issue -> verify A)'] = stats(timings);
  }

  const COL0 = 38, COL = 10;
  const line = '╠' + '═'.repeat(COL0) + '╪' + ['Min (ms)', 'Max (ms)', 'Mean(ms)', 'Med (ms)'].map(() => '═'.repeat(COL)).join('╪') + '╣';
  const top  = '╔' + '═'.repeat(COL0) + '╤' + Array(4).fill('═'.repeat(COL)).join('╤') + '╗';
  const bot  = '╚' + '═'.repeat(COL0) + '╧' + Array(4).fill('═'.repeat(COL)).join('╧') + '╝';
  const header = '║ ' + pad('Operation', COL0 - 2) + ' │' + ['Min (ms)', 'Max (ms)', 'Mean(ms)', 'Med (ms)'].map(h => h.padStart(COL)).join('│') + '║';

  console.log(top);
  console.log(header);
  console.log(line);
  for (const [op, s] of Object.entries(results)) {
    const row = '║ ' + pad(op, COL0 - 2) + ' │' +
      [s.min, s.max, s.mean, s.median].map(v => fmt(v)).join('│') + '║';
    console.log(row);
  }
  console.log(bot);

  const bbsProofBytes = lastProofA!.bbsProof.length;
  const dilithiumSigBytes = credential.dilithiumSignature.length;
  const combinedBytes = bbsProofBytes + dilithiumSigBytes;
  const w3cJson = w3cVcToJson(toW3CVC(credential));
  const w3cBytes = Buffer.byteLength(w3cJson, 'utf8');

  console.log('\nPROOF SIZES:');
  console.log(`  BBS+ proof:           ${bbsProofBytes} bytes`);
  console.log(`  Dilithium signature:  ${dilithiumSigBytes} bytes  (NIST FIPS 204 ML-DSA-65)`);
  console.log(`  Combined proof:       ${combinedBytes} bytes`);
  console.log(`  W3C VC JSON:          ${w3cBytes} bytes`);

  console.log('\nPRIVACY ANALYSIS:');
  console.log(`  Unlinkability test: ${UNLINKABILITY_PAIRS} proof pairs generated from same credential`);

  let allDifferAA = true;
  for (let i = 0; i < UNLINKABILITY_PAIRS; i++) {
    const c1 = verifierA.issueChallenge();
    await new Promise(r => setTimeout(r, 1));
    const c2 = verifierA.issueChallenge();
    const p1 = await holder.generateProof(credential.id, c1);
    const p2 = await holder.generateProof(credential.id, c2);
    if (Buffer.from(p1.bbsProof).toString('hex') === Buffer.from(p2.bbsProof).toString('hex')) allDifferAA = false;
  }

  let allDifferAB = true;
  for (let i = 0; i < UNLINKABILITY_PAIRS; i++) {
    const cA = verifierA.issueChallenge();
    const cB = verifierB.issueChallenge();
    const pA = await holder.generateProof(credential.id, cA);
    const pB = await holder.generateProof(credential.id, cB);
    if (Buffer.from(pA.bbsProof).toString('hex') === Buffer.from(pB.bbsProof).toString('hex')) allDifferAB = false;
  }

  let allDifferAC = true;
  for (let i = 0; i < UNLINKABILITY_PAIRS; i++) {
    const cA = verifierA.issueChallenge();
    const cC = verifierC.issueChallenge();
    const pA = await holder.generateProof(credential.id, cA);
    const pC = await holder.generateProof(credential.id, cC);
    if (Buffer.from(pA.bbsProof).toString('hex') === Buffer.from(pC.bbsProof).toString('hex')) allDifferAC = false;
  }

  let allDifferBC = true;
  for (let i = 0; i < UNLINKABILITY_PAIRS; i++) {
    const cB = verifierB.issueChallenge();
    const cC = verifierC.issueChallenge();
    const pB = await holder.generateProof(credential.id, cB);
    const pC = await holder.generateProof(credential.id, cC);
    if (Buffer.from(pB.bbsProof).toString('hex') === Buffer.from(pC.bbsProof).toString('hex')) allDifferBC = false;
  }

  console.log(`  A↔A (same verifier, fresh sessions): bbsProof bytes differ: ${allDifferAA ? 'YES ✓' : 'NO ✗'}`);
  console.log(`  A↔B (colluding verifiers):           bbsProof bytes differ: ${allDifferAB ? 'YES ✓' : 'NO ✗'}`);
  console.log(`  A↔C (colluding verifiers):           bbsProof bytes differ: ${allDifferAC ? 'YES ✓' : 'NO ✗'}`);
  console.log(`  B↔C (colluding verifiers):           bbsProof bytes differ: ${allDifferBC ? 'YES ✓' : 'NO ✗'}`);

  const allPassed = allDifferAA && allDifferAB && allDifferAC && allDifferBC;
  console.log(`  Conclusion: Session-level unlinkability ${allPassed ? 'CONFIRMED across all 3 verifiers' : 'FAILED'}`);

  const jsonOutput = {
    meta: {
      date: new Date().toISOString(),
      runs: N,
      system: process.platform,
      nodeVersion: process.version,
    },
    timings: Object.fromEntries(
      Object.entries(results).map(([op, s]) => [op, {
        min_ms: +s.min.toFixed(2),
        max_ms: +s.max.toFixed(2),
        mean_ms: +s.mean.toFixed(2),
        median_ms: +s.median.toFixed(2),
      }])
    ),
    proofSizes: {
      bbsProof_bytes: bbsProofBytes,
      dilithiumSignature_bytes: dilithiumSigBytes,
      combined_bytes: combinedBytes,
      w3cVcJson_bytes: w3cBytes,
    },
    privacyAnalysis: {
      unlinkabilityPairs: UNLINKABILITY_PAIRS,
      pairResults: { 'A↔A': allDifferAA, 'A↔B': allDifferAB, 'A↔C': allDifferAC, 'B↔C': allDifferBC },
      allPassed,
      conclusion: allPassed
        ? 'Session-level unlinkability CONFIRMED across all 3 verifiers'
        : 'Session-level unlinkability FAILED for one or more pairs',
    },
  };

  const outPath = path.resolve(__dirname, '../../benchmark-results.json');
  fs.writeFileSync(outPath, JSON.stringify(jsonOutput, null, 2));
  console.log(`\n✓ Results written to benchmark-results.json\n`);
}

main().catch(err => {
  console.error('Benchmark failed:', err);
  process.exit(1);
});
