from __future__ import annotations

import time

import dns.dnssec
import dns.exception
import dns.name

from .models import ProofArtifact, RRsetData, VerificationResult
from .serialization import data_to_rrset, proof_size_bytes, transcript_hash


class DNSSECProofVerifier:
    def verify(
        self,
        query_name: str,
        query_type: str,
        answer: RRsetData,
        artifact: ProofArtifact,
        trust_anchor,
    ) -> VerificationResult:
        started = time.perf_counter()
        expected_hash = transcript_hash(artifact)
        if artifact.transcript_hash != expected_hash:
            raise dns.exception.DNSException("artifact transcript hash mismatch")
        if artifact.query.qname != dns.name.from_text(query_name).to_text():
            raise dns.exception.DNSException("query name mismatch")
        if artifact.query.rdtype != query_type.upper():
            raise dns.exception.DNSException("query type mismatch")
        if answer.to_dict() != artifact.answer.to_dict():
            raise dns.exception.DNSException("answer payload mismatch")

        root_dnskey = data_to_rrset(artifact.root_dnskey)
        root_dnskey_rrsig = data_to_rrset(artifact.root_dnskey_rrsig)
        dns.dnssec.validate(root_dnskey, root_dnskey_rrsig, {trust_anchor.name: trust_anchor})

        trusted_dnskeys = {dns.name.root: root_dnskey}
        for link in artifact.chain:
            parent_zone = dns.name.from_text(link.parent_zone)
            child_zone = dns.name.from_text(link.child_zone)
            ds_rrset = data_to_rrset(link.ds)
            ds_rrsig = data_to_rrset(link.ds_rrsig)
            dnskey_rrset = data_to_rrset(link.dnskey)
            dnskey_rrsig = data_to_rrset(link.dnskey_rrsig)

            dns.dnssec.validate(ds_rrset, ds_rrsig, {parent_zone: trusted_dnskeys[parent_zone]})
            matched = []
            for ds in ds_rrset:
                for dnskey in dnskey_rrset:
                    try:
                        computed = dns.dnssec.make_ds(child_zone, dnskey, ds.digest_type)
                    except Exception:
                        continue
                    if computed == ds:
                        matched.append(dns.dnssec.key_id(dnskey))
            matched = sorted(set(matched))
            if matched != sorted(link.matched_key_tags):
                raise dns.exception.DNSException(f"DS match set mismatch for {child_zone}")
            if not matched:
                raise dns.exception.DNSException(f"no DNSKEY matched DS digest for {child_zone}")
            dns.dnssec.validate(dnskey_rrset, dnskey_rrsig, {child_zone: dnskey_rrset})
            trusted_dnskeys[child_zone] = dnskey_rrset

        zone = dns.name.from_text(artifact.zone)
        answer_rrset = data_to_rrset(artifact.answer)
        answer_rrsig = data_to_rrset(artifact.answer_rrsig)
        dns.dnssec.validate(answer_rrset, answer_rrsig, {zone: trusted_dnskeys[zone]})

        elapsed = time.perf_counter() - started
        return VerificationResult(
            valid=True,
            verification_time_s=elapsed,
            proof_size_bytes=proof_size_bytes(artifact, answer),
            transcript_hash=artifact.transcript_hash,
        )
