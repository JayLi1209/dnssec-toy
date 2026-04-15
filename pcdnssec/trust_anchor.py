from __future__ import annotations

import json
from pathlib import Path

import dns.dnssec
import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdatatype
import dns.rrset

from .models import RRsetData
from .serialization import data_to_rrset, rrset_to_data


DEFAULT_TRUST_ANCHOR_PATH = Path("trust_anchor.json")


def _query(server: str, name: str, rdtype: str, timeout: float = 5.0) -> dns.message.Message:
    query = dns.message.make_query(name, rdtype, want_dnssec=True)
    response = dns.query.udp(query, server, timeout=timeout)
    if response.flags & dns.flags.TC:
        response = dns.query.tcp(query, server, timeout=timeout)
    return response


def bootstrap_trust_anchor(
    path: Path | str = DEFAULT_TRUST_ANCHOR_PATH,
    resolver: str = "1.1.1.1",
) -> Path:
    path = Path(path)
    response = _query(resolver, ".", "DNSKEY")
    rrset = next((item for item in response.answer if item.rdtype == dns.rdatatype.DNSKEY), None)
    if rrset is None:
        raise RuntimeError("root DNSKEY query returned no DNSKEY rrset")

    anchors: list[str] = []
    for rdata in rrset:
        if rdata.flags == 257:
            anchors.append(rdata.to_text())
    if not anchors:
        raise RuntimeError("no SEP/KSK records found in root DNSKEY rrset")

    anchor_rrset = dns.rrset.from_text_list(dns.name.root, rrset.ttl, "IN", "DNSKEY", anchors)
    payload = {
        "name": ".",
        "rrset": rrset_to_data(anchor_rrset).to_dict(),
        "resolver": resolver,
        "notes": [
            "Bootstrapped from the live root DNSKEY RRset.",
            "This file is the fixed trust anchor for local validation runs.",
        ],
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def load_trust_anchor(path: Path | str = DEFAULT_TRUST_ANCHOR_PATH) -> dns.rrset.RRset:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return data_to_rrset(RRsetData(**payload["rrset"]))
