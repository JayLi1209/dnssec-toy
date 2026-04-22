from __future__ import annotations

from typing import Any

from .models import ChainLink, ProofArtifact, QueryData, RRsetData


def artifact_from_dict(payload: dict[str, Any]) -> ProofArtifact:
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
