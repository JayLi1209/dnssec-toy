"""Proof-carrying DNSSEC validation prototype."""

from .benchmark import run_benchmark
from .resolver import DNSSECResolver, ResolverResult
from .trust_anchor import bootstrap_trust_anchor, load_trust_anchor
from .verifier import DNSSECProofVerifier, VerificationResult

__all__ = [
    "DNSSECProofVerifier",
    "DNSSECResolver",
    "ResolverResult",
    "VerificationResult",
    "bootstrap_trust_anchor",
    "load_trust_anchor",
    "run_benchmark",
]
