from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class RRsetData:
    name: str
    ttl: int
    rdclass: str
    rdtype: str
    records: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class QueryData:
    qname: str
    rdtype: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ChainLink:
    parent_zone: str
    child_zone: str
    ds: RRsetData
    ds_rrsig: RRsetData
    dnskey: RRsetData
    dnskey_rrsig: RRsetData
    matched_key_tags: list[int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "parent_zone": self.parent_zone,
            "child_zone": self.child_zone,
            "ds": self.ds.to_dict(),
            "ds_rrsig": self.ds_rrsig.to_dict(),
            "dnskey": self.dnskey.to_dict(),
            "dnskey_rrsig": self.dnskey_rrsig.to_dict(),
            "matched_key_tags": self.matched_key_tags,
        }


@dataclass(slots=True)
class ProofArtifact:
    version: int
    query: QueryData
    zone: str
    trust_anchor_name: str
    root_dnskey: RRsetData
    root_dnskey_rrsig: RRsetData
    chain: list[ChainLink]
    answer: RRsetData
    answer_rrsig: RRsetData
    transcript_hash: str
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "query": self.query.to_dict(),
            "zone": self.zone,
            "trust_anchor_name": self.trust_anchor_name,
            "root_dnskey": self.root_dnskey.to_dict(),
            "root_dnskey_rrsig": self.root_dnskey_rrsig.to_dict(),
            "chain": [link.to_dict() for link in self.chain],
            "answer": self.answer.to_dict(),
            "answer_rrsig": self.answer_rrsig.to_dict(),
            "transcript_hash": self.transcript_hash,
            "notes": self.notes,
        }


@dataclass(slots=True)
class ResolverResult:
    query: QueryData
    answer: RRsetData
    proof: ProofArtifact
    fetch_count: int
    fetched_wire_bytes: int
    validation_time_s: float
    proof_generation_time_s: float
    end_to_end_time_s: float


@dataclass(slots=True)
class VerificationResult:
    valid: bool
    verification_time_s: float
    proof_size_bytes: int
    transcript_hash: str
