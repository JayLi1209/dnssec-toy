from __future__ import annotations

import argparse
import json
from pathlib import Path

from .artifact import artifact_from_dict
from .circom import CIRCOM_ARTIFACT_MAX_BYTES, export_circom_artifact, verify_circom_public_signals


DEFAULT_TRUST_ANCHOR_PATH = Path("trust_anchor.json")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Proof-carrying DNSSEC prototype")
    subparsers = parser.add_subparsers(dest="command", required=True)

    bootstrap = subparsers.add_parser("bootstrap-anchor", help="Bootstrap a trust anchor from the live root DNSKEY")
    bootstrap.add_argument("--resolver", default="1.1.1.1")
    bootstrap.add_argument("--output", default=str(DEFAULT_TRUST_ANCHOR_PATH))

    resolve = subparsers.add_parser("resolve", help="Validate a DNSSEC response and emit a proof artifact")
    resolve.add_argument("qname")
    resolve.add_argument("rdtype")
    resolve.add_argument("--resolver", default="1.1.1.1")
    resolve.add_argument("--trust-anchor", default=str(DEFAULT_TRUST_ANCHOR_PATH))
    resolve.add_argument("--output", default="proof_artifact.json")

    verify = subparsers.add_parser("verify", help="Verify a proof artifact")
    verify.add_argument("proof")
    verify.add_argument("--trust-anchor", default=str(DEFAULT_TRUST_ANCHOR_PATH))

    export_circom = subparsers.add_parser(
        "export-circom",
        help="Export Circom input/public-signal JSON for an existing proof artifact",
    )
    export_circom.add_argument("proof")
    export_circom.add_argument("--input-output", default="circom_input.json")
    export_circom.add_argument("--public-output", default="circom_public.json")
    export_circom.add_argument("--max-bytes", type=int, default=CIRCOM_ARTIFACT_MAX_BYTES)

    verify_circom = subparsers.add_parser(
        "verify-circom-public",
        help="Check that a Circom public-signal file matches a proof artifact",
    )
    verify_circom.add_argument("proof")
    verify_circom.add_argument("public_signals")

    compile_circom = subparsers.add_parser(
        "compile-circom",
        help="Compile the Circom transcript circuit into R1CS/WASM artifacts",
    )
    compile_circom.add_argument("--build-dir", default="build/circom")
    compile_circom.add_argument("--circuit", default="circom/transcript_commitment.circom")

    ptau_prepare = subparsers.add_parser(
        "prepare-ptau",
        help="Create a local development Powers of Tau file for Groth16 setup",
    )
    ptau_prepare.add_argument("--ptau", default="build/circom/local_powers_of_tau_final.ptau")
    ptau_prepare.add_argument("--power", type=int, default=18)

    groth16_setup = subparsers.add_parser(
        "groth16-setup",
        help="Run Groth16 setup and export a verification key",
    )
    groth16_setup.add_argument("--build-dir", default="build/circom")
    groth16_setup.add_argument("--ptau", default="build/circom/local_powers_of_tau_final.ptau")

    groth16_prove = subparsers.add_parser(
        "groth16-prove",
        help="Export inputs, generate witness, and create a Groth16 proof for a proof artifact",
    )
    groth16_prove.add_argument("proof")
    groth16_prove.add_argument("--build-dir", default="build/circom")
    groth16_prove.add_argument("--max-bytes", type=int, default=CIRCOM_ARTIFACT_MAX_BYTES)

    groth16_verify = subparsers.add_parser(
        "groth16-verify",
        help="Verify a generated Groth16 proof",
    )
    groth16_verify.add_argument("--build-dir", default="build/circom")
    groth16_verify.add_argument("--verification-key", default="")
    groth16_verify.add_argument("--public", dest="public_path", default="")
    groth16_verify.add_argument("--proof-path", default="")

    bench = subparsers.add_parser("benchmark", help="Run baseline and proof-carrying benchmarks")
    bench.add_argument("queries", nargs="+", help="Pairs of qname:type, for example cloudflare.com:A")
    bench.add_argument("--resolver", default="1.1.1.1")
    bench.add_argument("--trust-anchor", default=str(DEFAULT_TRUST_ANCHOR_PATH))
    bench.add_argument("--output", default="")
    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "bootstrap-anchor":
        from .trust_anchor import bootstrap_trust_anchor

        path = bootstrap_trust_anchor(args.output, resolver=args.resolver)
        print(path)
        return

    if args.command == "resolve":
        from .resolver import DNSSECResolver
        from .trust_anchor import load_trust_anchor

        trust_anchor = load_trust_anchor(args.trust_anchor)
        resolver = DNSSECResolver(args.resolver)
        result = resolver.validate_and_build_proof(args.qname, args.rdtype, trust_anchor)
        payload = {
            "answer": result.answer.to_dict(),
            "proof": result.proof.to_dict(),
            "metrics": {
                "fetch_count": result.fetch_count,
                "fetched_wire_bytes": result.fetched_wire_bytes,
                "validation_time_s": result.validation_time_s,
                "proof_generation_time_s": result.proof_generation_time_s,
                "end_to_end_time_s": result.end_to_end_time_s,
            },
        }
        Path(args.output).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(args.output)
        return

    if args.command == "verify":
        from .models import RRsetData
        from .trust_anchor import load_trust_anchor
        from .verifier import DNSSECProofVerifier

        payload = json.loads(Path(args.proof).read_text(encoding="utf-8"))
        trust_anchor = load_trust_anchor(args.trust_anchor)
        verifier = DNSSECProofVerifier()
        artifact = artifact_from_dict(payload["proof"])
        answer = RRsetData(**payload["answer"])
        result = verifier.verify(
            artifact.query.qname,
            artifact.query.rdtype,
            answer=answer,
            artifact=artifact,
            trust_anchor=trust_anchor,
        )
        print(json.dumps({
            "valid": result.valid,
            "verification_time_s": result.verification_time_s,
            "proof_size_bytes": result.proof_size_bytes,
            "transcript_hash": result.transcript_hash,
        }, indent=2, sort_keys=True))
        return

    if args.command == "export-circom":
        payload = json.loads(Path(args.proof).read_text(encoding="utf-8"))
        artifact = artifact_from_dict(payload["proof"])
        export_circom_artifact(
            artifact,
            input_path=args.input_output,
            public_path=args.public_output,
            max_bytes=args.max_bytes,
        )
        print(json.dumps({
            "input_output": args.input_output,
            "public_output": args.public_output,
            "max_bytes": args.max_bytes,
        }, indent=2, sort_keys=True))
        return

    if args.command == "verify-circom-public":
        payload = json.loads(Path(args.proof).read_text(encoding="utf-8"))
        artifact = artifact_from_dict(payload["proof"])
        public_signals = json.loads(Path(args.public_signals).read_text(encoding="utf-8"))
        print(json.dumps({
            "valid": verify_circom_public_signals(artifact, public_signals),
        }, indent=2, sort_keys=True))
        return

    if args.command == "compile-circom":
        from .snarkjs import compile_circuit

        print(json.dumps(compile_circuit(circuit_path=args.circuit, build_dir=args.build_dir), indent=2, sort_keys=True))
        return

    if args.command == "prepare-ptau":
        from .snarkjs import prepare_local_ptau

        print(json.dumps({"ptau": prepare_local_ptau(ptau_path=args.ptau, power=args.power)}, indent=2, sort_keys=True))
        return

    if args.command == "groth16-setup":
        from .snarkjs import groth16_setup

        print(json.dumps(groth16_setup(build_dir=args.build_dir, ptau_path=args.ptau), indent=2, sort_keys=True))
        return

    if args.command == "groth16-prove":
        from .snarkjs import export_inputs_for_artifact, generate_witness, groth16_prove

        exported = export_inputs_for_artifact(args.proof, build_dir=args.build_dir, max_bytes=args.max_bytes)
        witness_path = generate_witness(build_dir=args.build_dir)
        proof_paths = groth16_prove(build_dir=args.build_dir, witness_path=witness_path)
        print(json.dumps({
            "input": exported["input"],
            "public_commitment": exported["public"],
            "witness": witness_path,
            "proof": proof_paths["proof"],
            "public_snarkjs": proof_paths["public"],
        }, indent=2, sort_keys=True))
        return

    if args.command == "groth16-verify":
        from .snarkjs import groth16_verify

        valid = groth16_verify(
            build_dir=args.build_dir,
            verification_key_path=args.verification_key or None,
            public_path=args.public_path or None,
            proof_path=args.proof_path or None,
        )
        print(json.dumps({"valid": valid}, indent=2, sort_keys=True))
        return

    if args.command == "benchmark":
        from .benchmark import benchmark_many, format_benchmark_report

        parsed_queries = []
        for item in args.queries:
            qname, rdtype = item.split(":", 1)
            parsed_queries.append((qname, rdtype))
        results = benchmark_many(parsed_queries, recursive_resolver=args.resolver, trust_anchor_path=args.trust_anchor)
        report = format_benchmark_report(results)
        if args.output:
            Path(args.output).write_text(report + "\n", encoding="utf-8")
        print(report)
        return


if __name__ == "__main__":
    main()
