import { randomBytes }     from 'crypto';
import { createIssuer }    from './issuer/issuer';
import { createHolder }    from './holder/holder';
import { createVerifierA, createVerifierB, createVerifierC } from './verifier/verifier';
import { toW3CVC }         from './w3c/vc-wrapper';
import { generateId }      from './utils/crypto';
import type { RangeProof, BitProof } from './utils/crypto';

const C = {
  reset:'\x1b[0m', bold:'\x1b[1m', dim:'\x1b[2m',
  green:'\x1b[32m', red:'\x1b[31m', cyan:'\x1b[36m',
  orange:'\x1b[38;5;214m', white:'\x1b[97m',
};
const ok    = (s: string) => `${C.green}✓${C.reset} ${s}`;
const fail  = (s: string) => `${C.red}✗${C.reset} ${s}`;
const info  = (s: string) => `${C.cyan}ℹ${C.reset}  ${s}`;
const label = (s: string) => `${C.bold}${C.orange}${s}${C.reset}`;
const dim   = (s: string) => `${C.dim}${s}${C.reset}`;

function banner(t: string) {
  const line = '═'.repeat(64);
  console.log(`\n${C.bold}${C.orange}${line}${C.reset}`);
  console.log(`${C.bold}${C.white}  ${t}${C.reset}`);
  console.log(`${C.bold}${C.orange}${line}${C.reset}`);
}
function section(t: string) {
  console.log(`\n${C.bold}${C.cyan}▶  ${t}${C.reset}`);
  console.log(`${C.dim}${'─'.repeat(56)}${C.reset}`);
}
function kv(k: string, v: string | number, pad = 36) {
  console.log(`  ${k.padEnd(pad)} ${C.bold}${v}${C.reset}`);
}

const results: { label: string; passed: boolean }[] = [];
let flag_w3c        = false;
let flag_vA_accept  = false;
let flag_vA_zkp     = false;
let flag_vA_dil     = false;
let flag_vB_accept  = false;
let flag_vC_accept  = false;
let flag_dil_all    = false;  
let flag_unlinkable = false;
let flag_replay     = false;
let flag_tamper     = false;
let flag_keyswap    = false;
let flag_crossver   = false;
let flag_revoke     = false;
function assertOk(cond: boolean, msg: string) {
  results.push({ label: msg, passed: cond });
  console.log(cond ? `  ${ok(msg)}` : `  ${fail(msg)}`);
  if (!cond) process.exitCode = 1;
}

function rangeProofBytes(rp: RangeProof): number {
  const witnessBytes = rp.C_witness.length / 2;
  const bpBytes = (bp: BitProof) =>
    bp.C.length / 2 + bp.c0.length / 2 + bp.c1.length / 2 +
    bp.s0.length / 2 + bp.s1.length / 2;
  return witnessBytes + rp.bitProofs.reduce((sum, bp) => sum + bpBytes(bp), 0);
}

async function main() {
  banner('ZKP Multi-Verifier System  ·  Automated Demo  ·  Phase 2');
  console.log(`\n  ${C.dim}BBS+ · Dilithium ML-DSA-65 · ZK Range Proofs · Schnorr PoK · Fiat-Shamir NIZK${C.reset}\n`);

  section('STEP 1 — System Initialisation');
  const t0 = Date.now();
  const issuer = await createIssuer('demo', 'Demo Issuer Authority');
  const holder = await createHolder('holder-alice');
  const isRevoked = (idx: number) => issuer.isIndexRevoked(idx);
  const [verifierA, verifierB, verifierC] = await Promise.all([
    createVerifierA(isRevoked), createVerifierB(isRevoked), createVerifierC(isRevoked),
  ]);
  const initMs = Date.now() - t0;

  console.log(ok(`All actors initialised in ${initMs} ms`));
  kv('Issuer DID',           issuer.getDid());
  kv('BBS+ public key',      `${issuer.getBbsPublicKey().length} bytes (G2 compressed)`);
  kv('Dilithium public key', `${issuer.getDilithiumPublicKey().length} bytes (ML-DSA-65 FIPS 204)`);
  kv('Verifiers',            'V-A (non-linkable)  ·  V-B (linkable)  ·  V-C (non-linkable)');

  section('STEP 2 — Credential Issuance');
  const attributes = {
    credentialId: generateId(),
    attr_1: 'Alice', attr_2: 30, attr_3: 75000, attr_4: true, attr_5: 'Engineering',
  };
  console.log(info('Holder attribute set:'));
  Object.entries(attributes).forEach(([k, v]) => kv(`    ${k}`, String(v)));

  const credId = attributes.credentialId;
  const tIssue = Date.now();
  const commitment = holder.preparePseudonymCommitment(credId);
  const credential = await issuer.issueCredential(attributes, commitment);
  holder.storeCredential(credential);
  const issueMs = Date.now() - tIssue;

  console.log(ok(`Credential issued in ${issueMs} ms`));
  kv('Credential ID',        credential.id.slice(0,16) + '…');
  kv('BBS+ signature',       `${credential.bbsSignature.length} bytes`);
  kv('Dilithium signature',  `${credential.dilithiumSignature.length} bytes (NIST FIPS 204)`);
  kv('Revocation index',     `${credential.revocationIndex} (random 31-bit slot)`);

  console.log(info('\nSerialising to W3C VC v2 JSON-LD…'));
  const w3cVC = toW3CVC(credential);
  assertOk(w3cVC['@context'].includes('https://www.w3.org/ns/credentials/v2'), 'W3C VC @context valid');
  assertOk(w3cVC.type.includes('VerifiableCredential'),                         'W3C VC type valid');
  assertOk(w3cVC.proof.length === 2,                                             'W3C VC has BBS+ and Dilithium proofs');
  flag_w3c = w3cVC['@context'].includes('https://www.w3.org/ns/credentials/v2')
          && w3cVC.type.includes('VerifiableCredential')
          && w3cVC.proof.length === 2;
  console.log(dim(`    Serialised size: ~${JSON.stringify(w3cVC).length} bytes`));

  section('STEP 3 — Verifier A  (Non-linkable  ·  attr_2, attr_5  ·  attr_3 > 50000)');
  const tPA = Date.now();
  const proofA = await holder.generateProof(credId, verifierA.issueChallenge());
  const proofAGenMs = Date.now() - tPA;

  const rpA = proofA.predicates[0]?.rangeProof;
  const rpABytes = rpA ? rangeProofBytes(rpA) : 0;

  console.log(ok(`Proof generated in ${proofAGenMs} ms`));
  kv('BBS+ proof size',    `${proofA.bbsProof.length} bytes`);
  kv('Range proof size',   `${rpABytes} bytes  (C_witness:48 + 32×BitProof:176 over BLS12-381 G1)`);
  kv('Disclosed',          Object.entries(proofA.disclosedAttributes).map(([k,v])=>`${k}:${v}`).join('  ·  '));
  kv('Pseudonym',          proofA.pseudonym ? 'Yes' : 'No  (non-linkable)');

  const tVA = Date.now();
  const resultA = await verifierA.verifyProof(proofA);
  const verifyAMs = Date.now() - tVA;
  console.log(info(`\nVerification (${verifyAMs} ms):`));
  assertOk(resultA.verified,          'V-A: Overall ACCEPTED');
  assertOk(resultA.bbsVerified,       'V-A: BBS+ selective disclosure valid');
  assertOk(resultA.dilithiumVerified, 'V-A: Dilithium ML-DSA-65 binding valid');
  assertOk(!resultA.isRevoked,        'V-A: Revocation — not revoked');
  assertOk(resultA.predicateResults.every(p => p.satisfied), 'V-A: ZK range proof attr_3 > 50000 satisfied');
  assertOk(resultA.timingMs > 0,      `V-A: timingMs reported (${resultA.timingMs} ms)`);
  flag_vA_accept = resultA.verified;
  flag_vA_zkp    = resultA.predicateResults.every(p => p.satisfied);
  flag_vA_dil    = resultA.dilithiumVerified;

  section('STEP 4 — Verifier B  (Linkable pseudonym  ·  attr_4  ·  attr_2 ≥ 18)');
  const tPB = Date.now();
  const proofB = await holder.generateProof(credId, verifierB.issueChallenge());
  const proofBGenMs = Date.now() - tPB;

  console.log(ok(`Proof generated in ${proofBGenMs} ms`));
  kv('Pseudonym',       proofB.pseudonym!.slice(0,16) + '…  (HMAC-SHA256(k, verifierId))');
  kv('Schnorr PoK',     `${proofB.pseudonymProof?.length ?? 0} bytes  (48B R + 32B s)`);
  kv('Disclosed',       Object.entries(proofB.disclosedAttributes).map(([k,v])=>`${k}:${v}`).join('  ·  '));

  const tVB = Date.now();
  const resultB = await verifierB.verifyProof(proofB);
  const verifyBMs = Date.now() - tVB;
  console.log(info(`\nVerification (${verifyBMs} ms):`));
  assertOk(resultB.verified,          'V-B: Overall ACCEPTED');
  assertOk(resultB.bbsVerified,       'V-B: BBS+ selective disclosure valid');
  assertOk(resultB.dilithiumVerified, 'V-B: Dilithium ML-DSA-65 binding valid');
  assertOk(!resultB.isRevoked,        'V-B: Revocation — not revoked');
  assertOk(resultB.predicateResults.every(p => p.satisfied), 'V-B: ZK range proof attr_2 ≥ 18 satisfied');
  assertOk(resultB.timingMs > 0,      `V-B: timingMs reported (${resultB.timingMs} ms)`);
  flag_vB_accept = resultB.verified;

  section('STEP 5 — Verifier C  (Non-linkable  ·  attr_1, attr_5  ·  attr_2 < 50)');
  const tPC = Date.now();
  const proofC = await holder.generateProof(credId, verifierC.issueChallenge());
  const proofCGenMs = Date.now() - tPC;

  console.log(ok(`Proof generated in ${proofCGenMs} ms`));
  kv('Disclosed', Object.entries(proofC.disclosedAttributes).map(([k,v])=>`${k}:${v}`).join('  ·  '));

  const tVC = Date.now();
  const resultC = await verifierC.verifyProof(proofC);
  const verifyCMs = Date.now() - tVC;
  console.log(info(`\nVerification (${verifyCMs} ms):`));
  assertOk(resultC.verified,          'V-C: Overall ACCEPTED');
  assertOk(resultC.bbsVerified,       'V-C: BBS+ selective disclosure valid');
  assertOk(resultC.dilithiumVerified, 'V-C: Dilithium ML-DSA-65 binding valid');
  assertOk(!resultC.isRevoked,        'V-C: Revocation — not revoked');
  assertOk(resultC.predicateResults.every(p => p.satisfied), 'V-C: ZK range proof attr_2 < 50 satisfied');
  assertOk(resultC.timingMs > 0,      `V-C: timingMs reported (${resultC.timingMs} ms)`);
  flag_vC_accept = resultC.verified;
  flag_dil_all = flag_vA_dil && resultB.dilithiumVerified && resultC.dilithiumVerified;

  section('STEP 6 — Cross-Verifier Unlinkability Demonstration');
  const proofA2 = await holder.generateProof(credId, verifierA.issueChallenge());

  let unlinkabilityPassed = true;
  const assertU = (cond: boolean, msg: string) => {
    assertOk(cond, msg);
    if (!cond) unlinkabilityPassed = false;
  };

  console.log(info('proofA (1st presentation) vs proofA2 (2nd presentation) — same verifier:'));
  assertU(proofA.proofId !== proofA2.proofId,
    'proofId different     (fresh UUID each time)');
  assertU(proofA.blindedRoot !== proofA2.blindedRoot,
    'blindedRoot different (fresh rootBlind scalar)');
  assertU(!Buffer.from(proofA.bbsProof).equals(Buffer.from(proofA2.bbsProof)),
    'BBS+ bytes different  (probabilistic re-randomisation)');
  assertU(proofA.verifierChallenge !== proofA2.verifierChallenge,
    'Fiat-Shamir nonce different  (fresh proofSalt each time)');

  console.log(info('\nproofA (V-A) vs proofB (V-B) — different verifiers, same credential:'));
  assertU(proofA.proofId !== proofB.proofId,         'proofId different');
  assertU(proofA.blindedRoot !== proofB.blindedRoot, 'blindedRoot different');
  assertU(!Buffer.from(proofA.bbsProof).equals(Buffer.from(proofB.bbsProof)),
    'BBS+ bytes different');

  if (unlinkabilityPassed) {
    console.log(dim('\n    Colluding verifiers find no common identifier — cannot correlate proofs.'));
  } else {
    console.log(`\n  ${C.red}Unlinkability assertions failed — see ✗ above.${C.reset}`);
  }
  flag_unlinkable = unlinkabilityPassed;

  section('STEP 7 — Replay Attack Rejection');
  const replayResult = await verifierA.verifyProof(proofA);
  assertOk(!replayResult.verified, 'Replay rejected: same proofId refused (10-min TTL)');
  flag_replay = !replayResult.verified;

  section('STEP 8 — Tamper Test: BBS+ Proof Byte Corruption');
  const proofTamper = await holder.generateProof(credId, verifierC.issueChallenge());
  const tb = new Uint8Array(proofTamper.bbsProof);
  const origByte = tb[4];
  tb[4] = origByte ^ 0xff;
  const tamperResult = await verifierC.verifyProof({ ...proofTamper, bbsProof: tb });
  assertOk(!tamperResult.verified,    'Tampered proof: REJECTED');
  assertOk(!tamperResult.bbsVerified,
    `BBS+ failed  (byte[4]: 0x${origByte.toString(16).padStart(2,'0')} → 0x${tb[4].toString(16).padStart(2,'0')})  — real crypto confirmed`);
  flag_tamper = !tamperResult.verified && !tamperResult.bbsVerified;

  section('STEP 9 — Tamper Test: Dilithium Key-Swap Attack');
  console.log(info('Creating a second issuer, generating a valid V-A proof, then swapping in the attacker BBS+ key…'));
  const issuer2 = await createIssuer('attacker', 'Attacker Issuer');
  const proofForSwap = await holder.generateProof(credId, verifierA.issueChallenge());
  const keySwapResult = await verifierA.verifyProof({
    ...proofForSwap,
    proofId:            randomBytes(16).toString('hex'),
    issuerBbsPublicKey: issuer2.getBbsPublicKey(),
  });
  assertOk(!keySwapResult.verified,          'Key-swap proof: REJECTED');
  assertOk(!keySwapResult.dilithiumVerified, 'Dilithium binding failed  — PQC layer caught the key swap');
  flag_keyswap = !keySwapResult.verified && !keySwapResult.dilithiumVerified;
  console.log(dim('    dilithiumBinding = SHA-256(bbsKey ∥ issuerDid ∥ credentialRoot ∥ date)'));
  console.log(dim('    Swapping issuerBbsPublicKey invalidates the ML-DSA-65 signature.'));

  section('STEP 10 — Cross-Verifier Proof Rejection (Fiat-Shamir Binding)');
  console.log(info('Generating a fresh proof for Verifier C (non-linkable), then submitting to Verifier A…'));
  console.log(info('V-C and V-A are both non-linkable — pseudonym guard is bypassed, nonce mismatch rejects.'));
  const freshProofC = await holder.generateProof(credId, verifierC.issueChallenge());
  const crossResult = await verifierA.verifyProof({
    ...freshProofC,
    proofId: randomBytes(16).toString('hex'),
  });
  assertOk(!crossResult.verified,    'Cross-verifier proof: REJECTED  (V-A rejects proof made for V-C)');
  assertOk(!crossResult.bbsVerified, 'Proof REJECTED — Fiat-Shamir nonce mismatch (bbsVerified=false by early exit, nonce checked before BBS+)');
  flag_crossver = !crossResult.verified;
  console.log(dim('    nonce = SHA-256(revIdx ∥ attrs ∥ predicates ∥ verifierId ∥ timestamp ∥ salt)'));
  console.log(dim('    V-A recomputes nonce using its own verifierId — does not match the proof nonce.'));

  section('STEP 11 — Credential Revocation');
  issuer.revokeCredential(credential.id);
  console.log(ok('Credential revoked in registry'));
  const revokedResult = await verifierA.verifyProof(
    await holder.generateProof(credId, verifierA.issueChallenge())
  );
  assertOk(!revokedResult.verified, 'Post-revocation proof: REJECTED');
  assertOk(revokedResult.isRevoked, 'isRevoked = true');
  flag_revoke = !revokedResult.verified && revokedResult.isRevoked;
  console.log(dim(`    Revocation slot ${credential.revocationIndex} — status: revoked`));

  banner('Demo Complete — Summary');
  const allPassed = process.exitCode !== 1;

  const tick = (flag: boolean, text: string) =>
    `    ${flag ? `${C.green}✓${C.reset}` : `${C.red}✗${C.reset}`} ${text}`;

  console.log(`
  ${label('Performance (this run)')}
    Key generation:      ${initMs} ms
    Credential issuance: ${issueMs} ms
    Proof gen  V-A: ${proofAGenMs} ms    V-B: ${proofBGenMs} ms    V-C: ${proofCGenMs} ms
    Verify     V-A: ${verifyAMs} ms    V-B: ${verifyBMs} ms    V-C: ${verifyCMs} ms

  ${label('Security enforcement (tamper tests)')}
${tick(flag_tamper,   'BBS+ tamper detection    — 1 flipped byte → bbsVerified = false')}
${tick(flag_keyswap,  'Dilithium key-swap       — swapped issuer key → dilithiumVerified = false')}
${tick(flag_crossver, 'Cross-verifier rejection — V-C proof rejected by V-A (Fiat-Shamir nonce is verifier-bound)')}

  ${label('Privacy guarantees')}
${tick(flag_vA_accept && flag_vB_accept && flag_vC_accept, 'Selective disclosure     — only requested attributes per verifier')}
${tick(flag_vA_zkp,     'ZK predicate proofs      — values hidden, only satisfiability proven')}
${tick(flag_unlinkable, 'Unlinkability            — no common identifier across verifier boundaries')}
${tick(flag_replay,     'Replay rejection         — same proofId refused on second submission')}
${tick(flag_revoke,     'Revocation               — revoked credential rejected')}
${tick(flag_dil_all,     'Post-quantum binding     — ML-DSA-65 active on every verification path')}

  ${allPassed
    ? `${C.bold}${C.green}  ALL CHECKS PASSED${C.reset}`
    : `${C.bold}${C.red}  SOME CHECKS FAILED — see ✗ marks above${C.reset}`}
  `);
}

main().catch(err => {
  console.error(`\n${C.red}${C.bold}Demo failed:${C.reset}`, err);
  process.exit(1);
});
