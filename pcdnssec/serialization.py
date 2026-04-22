from __future__ import annotations

import hashlib
import json
from typing import Any

import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from .artifact import artifact_from_dict
from .models import ProofArtifact, RRsetData


def rrset_to_data(rrset: dns.rrset.RRset) -> RRsetData:
    return RRsetData(
        name=rrset.name.to_text(),
        ttl=rrset.ttl,
        rdclass=dns.rdataclass.to_text(rrset.rdclass),
        rdtype=dns.rdatatype.to_text(rrset.rdtype),
        records=sorted(rdata.to_text() for rdata in rrset),
    )


def data_to_rrset(data: RRsetData) -> dns.rrset.RRset:
    return dns.rrset.from_text_list(
        dns.name.from_text(data.name),
        data.ttl,
        dns.rdataclass.from_text(data.rdclass),
        dns.rdatatype.from_text(data.rdtype),
        data.records,
    )


def canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def transcript_hash(artifact: ProofArtifact) -> str:
    payload = artifact.to_dict()
    payload["transcript_hash"] = ""
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def proof_size_bytes(artifact: ProofArtifact, answer: RRsetData) -> int:
    payload = {
        "answer": answer.to_dict(),
        "proof": artifact.to_dict(),
    }
    return len(canonical_json_bytes(payload))
