# Proof-Carrying DNSSEC Validation Prototype

This repository contains a toy prototype for proof-carrying DNSSEC validation, serving as the final project for CSCI 780: Distributed Systems Security.

Work done by Yuanhe Li and Colin Soule.

The model is:

- A resolver-side component fetches a positive DNSSEC answer plus the supporting chain of trust.
- The resolver validates that chain to a fixed trust anchor.
- The resolver emits a structured proof artifact that is explicit, inspectable JSON.
- A client verifies the artifact locally without performing its own network fetches.

The prototype focuses on correctness, transparency, and measurement. It does not try to be deployment-ready.

## Scope

Implemented:

- Positive DNSSEC answers only
- RRset + RRSIG validation
- DNSKEY and DS chain validation to a trust anchor
- Resolver-side proof artifact generation
- Client-side proof replay verification
- Benchmarking for three modes

Not implemented:

- NSEC or NSEC3
- Negative answers
- Wildcards
- CNAME chasing logic across signed zones
- Full DNSSEC validation inside a zk circuit

## Repository Layout

- [pcdnssec/resolver.py](/Users/apple/Desktop/Security/val/pcdnssec/resolver.py): resolver-side fetch, validation, and proof creation
- [pcdnssec/verifier.py](/Users/apple/Desktop/Security/val/pcdnssec/verifier.py): client-side proof verification
- [pcdnssec/benchmark.py](/Users/apple/Desktop/Security/val/pcdnssec/benchmark.py): benchmark harness
- [pcdnssec/trust_anchor.py](/Users/apple/Desktop/Security/val/pcdnssec/trust_anchor.py): trust anchor bootstrap and loading
- [pcdnssec/models.py](/Users/apple/Desktop/Security/val/pcdnssec/models.py): explicit proof artifact data model
- [proof_artifact.json](/Users/apple/Desktop/Security/val/proof_artifact.json): example proof artifact for `cloudflare.com A`
- [benchmark_results.json](/Users/apple/Desktop/Security/val/benchmark_results.json): example benchmark output on three signed domains
- [trust_anchor.json](/Users/apple/Desktop/Security/val/trust_anchor.json): bootstrapped fixed trust anchor used for the sample runs

## Install

```bash
python3 -m pip install -e .
```

The prototype depends on:

- `dnspython`
- `cryptography`

## Quick Start

1. Bootstrap a trust anchor from the live root DNSKEY RRset:

```bash
python3 -m pcdnssec bootstrap-anchor --output trust_anchor.json
```

2. Validate a signed positive answer and emit a proof artifact:

```bash
python3 -m pcdnssec resolve cloudflare.com A \
  --trust-anchor trust_anchor.json \
  --output proof_artifact.json
```

3. Verify the proof artifact on the client side:

```bash
python3 -m pcdnssec verify proof_artifact.json \
  --trust-anchor trust_anchor.json
```

4. Run the benchmark harness:

```bash
python3 -m pcdnssec benchmark \
  cloudflare.com:A ietf.org:A nic.cz:A \
  --trust-anchor trust_anchor.json \
  --output benchmark_results.json
```

## What The Proof Artifact Contains

The artifact is deliberately verbose. It includes:

- query metadata
- the validated answer RRset
- the answer RRSIG
- the root DNSKEY RRset and its RRSIG
- one chain link per delegation, each with:
  parent zone
  child zone
  DS RRset + RRSIG
  child DNSKEY RRset + RRSIG
  matched key tags
- a transcript hash over the canonicalized artifact

The current client verifier replays the cryptographic checks against the explicit transcript instead of recomputing resolution work from the network.

## Circom Bridge

This repository now includes a Circom circuit at [circom/transcript_commitment.circom](/Users/apple/Desktop/Security/dnssec-toy/circom/transcript_commitment.circom).

What it proves today:

- knowledge of the canonical proof-artifact bytes
- binding to the public transcript hash
- a Circom-friendly rolling commitment over the full padded artifact

What it does not prove yet:

- DNSKEY, DS, or RRSIG verification inside the circuit
- SHA-256 or RSA checks inside the circuit
- a full Groth16/PLONK proving flow checked into the repo

The practical boundary is:

1. Python still performs DNSSEC validation and emits the explicit artifact.
2. The Circom circuit proves knowledge of the exact canonical artifact bytes that correspond to the published transcript hash and commitment.
3. A future iteration can replace the rolling commitment with a hash gadget and then progressively move DNSSEC checks into-circuit.

Example flow:

```bash
python3 -m pcdnssec compile-circom --build-dir build/circom

python3 -m pcdnssec prepare-ptau \
  --ptau build/circom/local_powers_of_tau_final.ptau \
  --power 18

python3 -m pcdnssec groth16-setup \
  --build-dir build/circom \
  --ptau build/circom/local_powers_of_tau_final.ptau

python3 -m pcdnssec groth16-prove \
  proof_artifact.json \
  --build-dir build/circom

python3 -m pcdnssec groth16-verify \
  --build-dir build/circom

python3 -m pcdnssec verify-circom-public \
  proof_artifact.json \
  build/circom/public.json
```

Notes:

- `prepare-ptau` creates a local development Powers of Tau file so the workflow does not depend on a downloaded ceremony artifact.
- For the current circuit size, Groth16 needs at least power `18`. `groth16-setup` now recomputes that requirement and regenerates the local ptau automatically if needed.
- `groth16-setup` uses the initial setup key as the local development proving key. That is fine for this toy prototype, but it is not a substitute for a real multi-party ceremony.
- The ptau/setup steps may take several minutes on a laptop because the circuit has one private byte signal per padded artifact byte.

## Benchmark Modes

The harness compares:

1. `trust_the_resolver`
   The client accepts the resolver answer directly.

2. `full_stub_validation`
   The client performs full fetch plus DNSSEC validation itself, using the same recursive resolver only as a transport path for DNS data.

3. `proof_carrying_validation`
   The resolver fetches and validates once, emits a proof artifact, and the client verifies only the artifact.

Reported metrics:

- end-to-end latency
- proof generation time
- client verification time
- fetched network bytes or returned artifact bytes
- whether the response exceeds a UDP-friendly 1232-byte limit

## Example Results

These sample results were generated on April 14, 2026 in this workspace and are checked in at [benchmark_results.json](/Users/apple/Desktop/Security/val/benchmark_results.json).

Highlights from that run:

- `cloudflare.com A`
  trust-the-resolver: `0.030s`, `64 B`
  full stub validation: `0.182s`, `2878 B`
  proof-carrying client verification: `0.0019s`, artifact `4932 B`

- `ietf.org A`
  trust-the-resolver: `0.026s`, `58 B`
  full stub validation: `0.190s`, `3424 B`
  proof-carrying client verification: `0.0046s`, artifact `5643 B`

- `nic.cz A`
  trust-the-resolver: `0.092s`, `40 B`
  full stub validation: `0.331s`, `2722 B`
  proof-carrying client verification: `0.0027s`, artifact `4693 B`

The main tradeoff is visible already: client verification becomes much cheaper than full stub validation, but the explicit proof artifact is larger than a plain DNS answer and larger than a UDP-friendly envelope.

## Notes On Design

- The trust anchor is treated as fixed input once `trust_anchor.json` is created.
- The proof artifact is JSON to keep the transcript inspectable and debuggable.
- The code is structured so a future zk proof system can replace the explicit transcript while preserving the resolver/verifier split.
- The current Circom circuit is an integration bridge, not a full zk-DNSSEC verifier.

## Limitations

- This prototype assumes the queried RRset exists and is directly present in the positive answer section.
- It does not prove non-existence.
- It does not optimize artifact size.
- The benchmark is a prototype measurement harness, not a rigorously controlled experiment.
