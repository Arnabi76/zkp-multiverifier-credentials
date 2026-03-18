Here's a detailed README description section:

---

## Overview

This project implements a **Zero-Knowledge Proof (ZKP)-based multi-verifier credential system** that enables privacy-preserving attribute verification across multiple independent verifiers — without revealing unnecessary personal information.

The system allows a credential holder to selectively disclose specific attributes (e.g., age, institution, role) to different verifiers, proving the validity of those attributes without exposing the full credential. Each verifier receives only what it needs — nothing more.

---

## How It Works

A central **Issuer** signs a credential containing multiple attributes using **BBS+ signatures** over **BLS12-381 elliptic curves**. BBS+ enables selective disclosure — the holder can derive a proof revealing only a chosen subset of attributes while keeping the rest hidden.

For each verification request, the holder generates a **Schnorr Proof of Knowledge**, demonstrating that they possess a valid credential without revealing the underlying secret. This proof is then submitted to the target verifier.

To ensure **post-quantum resistance**, credential signing and issuer authentication are additionally secured using **Dilithium (ML-DSA-65)**, a NIST-standardized lattice-based digital signature scheme. This hybrid approach ensures the system remains secure against both classical and quantum adversaries.

Multiple verifiers can independently verify proofs without communicating with each other or the issuer — making the system **decentralized and scalable**.

---

## Key Features

- **Selective Disclosure** — reveal only the attributes required by each verifier
- **Multi-Verifier Support** — independent, simultaneous verification across N verifiers
- **Post-Quantum Security** — Dilithium (ML-DSA-65) signatures for issuer authentication
- **BBS+ over BLS12-381** — efficient pairing-based signatures enabling unlinkable proofs
- **Schnorr Proof of Knowledge** — zero-knowledge proof of credential possession
- **Privacy by Design** — no verifier learns more than its required attribute subset

---

## Cryptographic Stack

| Component | Scheme |
|---|---|
| Credential Signing | BBS+ over BLS12-381 |
| Proof of Possession | Schnorr Proof of Knowledge |
| Post-Quantum Signing | Dilithium / ML-DSA-65 |
| Elliptic Curve | BLS12-381 |
| ZKP Paradigm | Sigma Protocols / Selective Disclosure |

---
