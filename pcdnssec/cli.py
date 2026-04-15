from __future__ import annotations

import argparse
import json
from pathlib import Path

from .benchmark import benchmark_many, format_benchmark_report
from .models import RRsetData
from .resolver import DNSSECResolver
from .serialization import artifact_from_dict
from .trust_anchor import DEFAULT_TRUST_ANCHOR_PATH, bootstrap_trust_anchor, load_trust_anchor
from .verifier import DNSSECProofVerifier


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
        path = bootstrap_trust_anchor(args.output, resolver=args.resolver)
        print(path)
        return

    if args.command == "resolve":
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

    if args.command == "benchmark":
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
