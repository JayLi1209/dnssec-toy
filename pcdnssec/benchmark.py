from __future__ import annotations

import json
import time
from dataclasses import asdict
from typing import Any

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype

from .resolver import DNSSECResolver
from .serialization import rrset_to_data
from .trust_anchor import load_trust_anchor
from .verifier import DNSSECProofVerifier


UDP_FRIENDLY_LIMIT = 1232


def _query_simple(server: str, qname: str, rdtype: str, want_dnssec: bool = False, timeout: float = 5.0):
    query = dns.message.make_query(qname, rdtype, want_dnssec=want_dnssec)
    started = time.perf_counter()
    response = dns.query.udp(query, server, timeout=timeout)
    if response.flags & dns.flags.TC:
        response = dns.query.tcp(query, server, timeout=timeout)
    elapsed = time.perf_counter() - started
    return response, elapsed


def _extract_positive_answer(response, qname: str, rdtype: str):
    name = dns.name.from_text(qname)
    type_value = dns.rdatatype.from_text(rdtype)
    for rrset in response.answer:
        if rrset.name == name and rrset.rdtype == type_value:
            return rrset
    raise ValueError(f"expected positive {rdtype} answer for {qname}")


def run_benchmark(
    qname: str,
    rdtype: str,
    recursive_resolver: str = "1.1.1.1",
    trust_anchor_path: str = "trust_anchor.json",
) -> dict[str, Any]:
    trust_anchor = load_trust_anchor(trust_anchor_path)
    resolver = DNSSECResolver(recursive_resolver=recursive_resolver)
    verifier = DNSSECProofVerifier()

    baseline_response, baseline_time = _query_simple(recursive_resolver, qname, rdtype, want_dnssec=False)
    baseline_answer = rrset_to_data(_extract_positive_answer(baseline_response, qname, rdtype))
    baseline_wire_bytes = len(baseline_response.to_wire())

    full_started = time.perf_counter()
    full_result = resolver.validate_and_build_proof(qname, rdtype, trust_anchor)
    full_elapsed = time.perf_counter() - full_started

    proof_started = time.perf_counter()
    proof_result = resolver.validate_and_build_proof(qname, rdtype, trust_anchor)
    verification = verifier.verify(qname, rdtype, proof_result.answer, proof_result.proof, trust_anchor)
    proof_elapsed = time.perf_counter() - proof_started

    artifact_size = verification.proof_size_bytes
    return {
        "query": {"qname": qname, "rdtype": rdtype.upper()},
        "trust_the_resolver": {
            "answer": baseline_answer.to_dict(),
            "end_to_end_time_s": baseline_time,
            "response_size_bytes": baseline_wire_bytes,
            "exceeds_udp_friendly_limit": baseline_wire_bytes > UDP_FRIENDLY_LIMIT,
        },
        "full_stub_validation": {
            "end_to_end_time_s": full_elapsed,
            "fetch_count": full_result.fetch_count,
            "network_bytes": full_result.fetched_wire_bytes,
            "validation_time_s": full_result.validation_time_s,
            "response_size_bytes": full_result.fetched_wire_bytes,
            "exceeds_udp_friendly_limit": full_result.fetched_wire_bytes > UDP_FRIENDLY_LIMIT,
        },
        "proof_carrying_validation": {
            "validated_answer": proof_result.answer.to_dict(),
            "resolver_end_to_end_time_s": proof_result.end_to_end_time_s,
            "proof_generation_time_s": proof_result.proof_generation_time_s,
            "client_verification_time_s": verification.verification_time_s,
            "end_to_end_time_s": proof_elapsed,
            "proof_size_bytes": artifact_size,
            "response_size_bytes": artifact_size,
            "exceeds_udp_friendly_limit": artifact_size > UDP_FRIENDLY_LIMIT,
            "transcript_hash": verification.transcript_hash,
            "fetch_count": proof_result.fetch_count,
            "network_bytes": proof_result.fetched_wire_bytes,
        },
    }


def benchmark_many(
    queries: list[tuple[str, str]],
    recursive_resolver: str = "1.1.1.1",
    trust_anchor_path: str = "trust_anchor.json",
) -> list[dict[str, Any]]:
    return [
        run_benchmark(qname, rdtype, recursive_resolver=recursive_resolver, trust_anchor_path=trust_anchor_path)
        for qname, rdtype in queries
    ]


def format_benchmark_report(results: list[dict[str, Any]]) -> str:
    return json.dumps(results, indent=2, sort_keys=True)
