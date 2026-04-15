from __future__ import annotations

import time
from dataclasses import dataclass

import dns.dnssec
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.rrset

from .models import ChainLink, ProofArtifact, QueryData, ResolverResult
from .serialization import rrset_to_data, transcript_hash


@dataclass(slots=True)
class _FetchMetrics:
    count: int = 0
    wire_bytes: int = 0


class DNSSECResolver:
    def __init__(self, recursive_resolver: str = "1.1.1.1", timeout: float = 5.0):
        self.recursive_resolver = recursive_resolver
        self.timeout = timeout

    def _query(self, qname: dns.name.Name, rdtype: str, metrics: _FetchMetrics) -> dns.message.Message:
        query = dns.message.make_query(qname, rdtype, want_dnssec=True)
        response = dns.query.udp(query, self.recursive_resolver, timeout=self.timeout)
        if response.flags & dns.flags.TC:
            response = dns.query.tcp(query, self.recursive_resolver, timeout=self.timeout)
        metrics.count += 1
        metrics.wire_bytes += len(response.to_wire())
        return response

    def _extract_rrset(
        self,
        response: dns.message.Message,
        name: dns.name.Name,
        rdtype: dns.rdatatype.RdataType,
    ) -> dns.rrset.RRset:
        for section in (response.answer, response.authority):
            for rrset in section:
                if rrset.name == name and rrset.rdtype == rdtype:
                    return rrset
        raise ValueError(f"missing {dns.rdatatype.to_text(rdtype)} rrset for {name}")

    def _extract_rrsig(
        self,
        response: dns.message.Message,
        covered_name: dns.name.Name,
        covered_type: dns.rdatatype.RdataType,
    ) -> dns.rrset.RRset:
        for section in (response.answer, response.authority):
            for rrset in section:
                if rrset.name != covered_name or rrset.rdtype != dns.rdatatype.RRSIG:
                    continue
                matched = [rdata for rdata in rrset if rdata.type_covered == covered_type]
                if matched:
                    return dns.rrset.from_rdata_list(rrset.name, rrset.ttl, matched)
        raise ValueError(
            f"missing RRSIG covering {dns.rdatatype.to_text(covered_type)} for {covered_name}"
        )

    def _find_zone_apex(self, qname: dns.name.Name, metrics: _FetchMetrics) -> dns.name.Name:
        candidate = qname
        while True:
            response = self._query(candidate, "DNSKEY", metrics)
            for rrset in response.answer:
                if rrset.name == candidate and rrset.rdtype == dns.rdatatype.DNSKEY:
                    return candidate
            if candidate == dns.name.root:
                raise ValueError(f"unable to find signed zone apex for {qname}")
            candidate = candidate.parent()

    def _zone_chain(self, zone_apex: dns.name.Name) -> list[dns.name.Name]:
        chain = [dns.name.root]
        current = dns.name.root
        labels = list(zone_apex.labels[:-1])
        for index in range(len(labels) - 1, -1, -1):
            suffix = dns.name.Name(tuple(labels[index:] + [b""]))
            if suffix != current:
                chain.append(suffix)
                current = suffix
        return chain

    def _matched_ds_keys(self, child_name: dns.name.Name, ds_rrset: dns.rrset.RRset, dnskey_rrset: dns.rrset.RRset) -> list[int]:
        matched: list[int] = []
        for ds in ds_rrset:
            for dnskey in dnskey_rrset:
                try:
                    computed = dns.dnssec.make_ds(child_name, dnskey, ds.digest_type)
                except Exception:
                    continue
                if computed == ds:
                    matched.append(dns.dnssec.key_id(dnskey))
        return sorted(set(matched))

    def validate_and_build_proof(
        self,
        qname_text: str,
        rdtype_text: str,
        trust_anchor: dns.rrset.RRset,
    ) -> ResolverResult:
        started = time.perf_counter()
        metrics = _FetchMetrics()
        qname = dns.name.from_text(qname_text)
        rdtype = dns.rdatatype.from_text(rdtype_text)

        answer_response = self._query(qname, rdtype_text, metrics)
        answer_rrset = self._extract_rrset(answer_response, qname, rdtype)
        answer_rrsig = self._extract_rrsig(answer_response, qname, rdtype)

        zone_apex = self._find_zone_apex(qname, metrics)
        zones = self._zone_chain(zone_apex)

        validation_started = time.perf_counter()
        root_dnskey_response = self._query(dns.name.root, "DNSKEY", metrics)
        root_dnskey_rrset = self._extract_rrset(root_dnskey_response, dns.name.root, dns.rdatatype.DNSKEY)
        root_dnskey_rrsig = self._extract_rrsig(root_dnskey_response, dns.name.root, dns.rdatatype.DNSKEY)
        dns.dnssec.validate(root_dnskey_rrset, root_dnskey_rrsig, {dns.name.root: trust_anchor})

        trusted_dnskeys: dict[dns.name.Name, dns.rrset.RRset] = {dns.name.root: root_dnskey_rrset}
        chain_links: list[ChainLink] = []

        for parent_zone, child_zone in zip(zones, zones[1:]):
            ds_response = self._query(child_zone, "DS", metrics)
            ds_rrset = self._extract_rrset(ds_response, child_zone, dns.rdatatype.DS)
            ds_rrsig = self._extract_rrsig(ds_response, child_zone, dns.rdatatype.DS)
            dns.dnssec.validate(ds_rrset, ds_rrsig, {parent_zone: trusted_dnskeys[parent_zone]})

            dnskey_response = self._query(child_zone, "DNSKEY", metrics)
            dnskey_rrset = self._extract_rrset(dnskey_response, child_zone, dns.rdatatype.DNSKEY)
            dnskey_rrsig = self._extract_rrsig(dnskey_response, child_zone, dns.rdatatype.DNSKEY)
            matched_key_tags = self._matched_ds_keys(child_zone, ds_rrset, dnskey_rrset)
            if not matched_key_tags:
                raise dns.exception.DNSException(f"no DNSKEY matched DS digest for {child_zone}")
            dns.dnssec.validate(dnskey_rrset, dnskey_rrsig, {child_zone: dnskey_rrset})
            trusted_dnskeys[child_zone] = dnskey_rrset
            chain_links.append(
                ChainLink(
                    parent_zone=parent_zone.to_text(),
                    child_zone=child_zone.to_text(),
                    ds=rrset_to_data(ds_rrset),
                    ds_rrsig=rrset_to_data(ds_rrsig),
                    dnskey=rrset_to_data(dnskey_rrset),
                    dnskey_rrsig=rrset_to_data(dnskey_rrsig),
                    matched_key_tags=matched_key_tags,
                )
            )

        dns.dnssec.validate(answer_rrset, answer_rrsig, {zone_apex: trusted_dnskeys[zone_apex]})
        validation_elapsed = time.perf_counter() - validation_started

        proof = ProofArtifact(
            version=1,
            query=QueryData(qname=qname.to_text(), rdtype=rdtype_text.upper()),
            zone=zone_apex.to_text(),
            trust_anchor_name=trust_anchor.name.to_text(),
            root_dnskey=rrset_to_data(root_dnskey_rrset),
            root_dnskey_rrsig=rrset_to_data(root_dnskey_rrsig),
            chain=chain_links,
            answer=rrset_to_data(answer_rrset),
            answer_rrsig=rrset_to_data(answer_rrsig),
            transcript_hash="",
            notes=[
                "Positive answers only.",
                "No NSEC or NSEC3 denial-of-existence support.",
                "Artifact is explicit JSON so a succinct proof system can replace it later.",
            ],
        )
        proof.transcript_hash = transcript_hash(proof)
        ended = time.perf_counter()

        return ResolverResult(
            query=proof.query,
            answer=proof.answer,
            proof=proof,
            fetch_count=metrics.count,
            fetched_wire_bytes=metrics.wire_bytes,
            validation_time_s=validation_elapsed,
            proof_generation_time_s=ended - validation_started,
            end_to_end_time_s=ended - started,
        )
