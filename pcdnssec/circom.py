from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import ProofArtifact

BN254_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617
CIRCOM_ARTIFACT_MAX_BYTES = 8192
_ROLLING_HASH_BASE = 257
_TRANSCRIPT_HASH_LIMB_BITS = 64
_TRANSCRIPT_HASH_LIMB_COUNT = 4


def canonical_artifact_bytes(artifact: ProofArtifact) -> bytes:
    return json.dumps(artifact.to_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")


def transcript_hash_limbs(transcript_hash_hex: str) -> list[int]:
    digest = bytes.fromhex(transcript_hash_hex)
    if len(digest) != 32:
        raise ValueError("transcript hash must be a 32-byte hex digest")
    limbs: list[int] = []
    bytes_per_limb = _TRANSCRIPT_HASH_LIMB_BITS // 8
    for index in range(_TRANSCRIPT_HASH_LIMB_COUNT):
        chunk = digest[index * bytes_per_limb : (index + 1) * bytes_per_limb]
        limbs.append(int.from_bytes(chunk, "big"))
    return limbs


def rolling_artifact_commitment(
    artifact_bytes: bytes,
    artifact_len: int,
    transcript_limbs: list[int],
) -> int:
    acc = (artifact_len + 1) % BN254_PRIME
    for limb in transcript_limbs:
        acc = (acc * _ROLLING_HASH_BASE + limb + 1) % BN254_PRIME
    for value in artifact_bytes:
        acc = (acc * _ROLLING_HASH_BASE + value + 1) % BN254_PRIME
    return acc


def build_circom_inputs(
    artifact: ProofArtifact,
    *,
    max_bytes: int = CIRCOM_ARTIFACT_MAX_BYTES,
) -> dict[str, Any]:
    artifact_bytes = canonical_artifact_bytes(artifact)
    if len(artifact_bytes) > max_bytes:
        raise ValueError(f"artifact length {len(artifact_bytes)} exceeds circuit capacity {max_bytes}")
    padded_bytes = list(artifact_bytes) + [0] * (max_bytes - len(artifact_bytes))
    transcript_limbs = transcript_hash_limbs(artifact.transcript_hash)
    return {
        "artifactLen": len(artifact_bytes),
        "transcriptHashLimbs": transcript_limbs,
        "artifactBytes": padded_bytes,
    }


def build_circom_public_signals(
    artifact: ProofArtifact,
    *,
    max_bytes: int = CIRCOM_ARTIFACT_MAX_BYTES,
) -> dict[str, Any]:
    inputs = build_circom_inputs(artifact, max_bytes=max_bytes)
    commitment = rolling_artifact_commitment(
        bytes(inputs["artifactBytes"]),
        inputs["artifactLen"],
        list(inputs["transcriptHashLimbs"]),
    )
    return {
        "artifactLen": inputs["artifactLen"],
        "transcriptHashLimbs": inputs["transcriptHashLimbs"],
        "artifactCommitment": str(commitment),
        "maxBytes": max_bytes,
    }


def verify_circom_public_signals(
    artifact: ProofArtifact,
    public_signals: dict[str, Any],
) -> bool:
    max_bytes = int(public_signals["maxBytes"])
    expected = build_circom_public_signals(artifact, max_bytes=max_bytes)
    normalized = {
        "artifactLen": int(public_signals["artifactLen"]),
        "transcriptHashLimbs": [int(item) for item in public_signals["transcriptHashLimbs"]],
        "artifactCommitment": str(public_signals["artifactCommitment"]),
        "maxBytes": max_bytes,
    }
    return normalized == expected


def export_circom_artifact(
    artifact: ProofArtifact,
    *,
    input_path: Path | str,
    public_path: Path | str,
    max_bytes: int = CIRCOM_ARTIFACT_MAX_BYTES,
) -> None:
    input_path = Path(input_path)
    public_path = Path(public_path)
    input_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    input_payload = build_circom_inputs(artifact, max_bytes=max_bytes)
    public_payload = build_circom_public_signals(artifact, max_bytes=max_bytes)
    input_path.write_text(json.dumps(input_payload, indent=2) + "\n", encoding="utf-8")
    public_path.write_text(json.dumps(public_payload, indent=2) + "\n", encoding="utf-8")
