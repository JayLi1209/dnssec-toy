from __future__ import annotations

import hashlib
import json
from typing import Any

import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset

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


def artifact_from_dict(payload: dict[str, Any]) -> ProofArtifact:
    from .models import ChainLink, ProofArtifact, QueryData

    def rrset_data(node: dict[str, Any]) -> RRsetData:
        return RRsetData(**node)

    chain = [
        ChainLink(
            parent_zone=item["parent_zone"],
            child_zone=item["child_zone"],
            ds=rrset_data(item["ds"]),
            ds_rrsig=rrset_data(item["ds_rrsig"]),
            dnskey=rrset_data(item["dnskey"]),
            dnskey_rrsig=rrset_data(item["dnskey_rrsig"]),
            matched_key_tags=list(item["matched_key_tags"]),
        )
        for item in payload["chain"]
    ]
    return ProofArtifact(
        version=payload["version"],
        query=QueryData(**payload["query"]),
        zone=payload["zone"],
        trust_anchor_name=payload["trust_anchor_name"],
        root_dnskey=rrset_data(payload["root_dnskey"]),
        root_dnskey_rrsig=rrset_data(payload["root_dnskey_rrsig"]),
        chain=chain,
        answer=rrset_data(payload["answer"]),
        answer_rrsig=rrset_data(payload["answer_rrsig"]),
        transcript_hash=payload["transcript_hash"],
        notes=list(payload.get("notes", [])),
    )
