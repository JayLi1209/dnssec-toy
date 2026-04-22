from __future__ import annotations

import json
import math
import re
import subprocess
from pathlib import Path

from .artifact import artifact_from_dict
from .circom import CIRCOM_ARTIFACT_MAX_BYTES, export_circom_artifact


DEFAULT_BUILD_DIR = Path("build/circom")
DEFAULT_CIRCUIT_NAME = "transcript_commitment"
DEFAULT_PTAU = "build/circom/local_powers_of_tau_final.ptau"


def _run(command: list[str], *, cwd: Path | None = None) -> None:
    subprocess.run(command, check=True, cwd=cwd)


def _run_capture(command: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=True, cwd=cwd, capture_output=True, text=True)


def _snarkjs_command() -> list[str]:
    local = Path("node_modules/.bin/snarkjs")
    if local.exists():
        return [str(local)]
    return ["snarkjs"]


def required_ptau_power_for_r1cs(r1cs_path: Path | str) -> int:
    r1cs_path = Path(r1cs_path)
    snarkjs = _snarkjs_command()
    completed = _run_capture(snarkjs + ["r1cs", "info", str(r1cs_path)])
    match = re.search(r"# of Constraints:\s*([0-9]+)", completed.stdout)
    if match is None:
        raise RuntimeError("unable to determine constraint count from snarkjs r1cs info output")
    constraints = int(match.group(1))
    # snarkjs requires 2**power >= 2 * constraints for Groth16 setup.
    return max(1, math.ceil(math.log2(constraints * 2)))


def _cleanup_setup_outputs(paths: list[Path]) -> None:
    for path in paths:
        if path.exists():
            path.unlink()


def compile_circuit(
    *,
    circuit_path: Path | str = Path("circom") / f"{DEFAULT_CIRCUIT_NAME}.circom",
    build_dir: Path | str = DEFAULT_BUILD_DIR,
) -> dict[str, str]:
    circuit_path = Path(circuit_path)
    build_dir = Path(build_dir)
    build_dir.mkdir(parents=True, exist_ok=True)
    _run(
        [
            "circom",
            str(circuit_path),
            "--r1cs",
            "--wasm",
            "--sym",
            "-o",
            str(build_dir),
        ]
    )
    js_dir = build_dir / f"{circuit_path.stem}_js"
    return {
        "r1cs": str(build_dir / f"{circuit_path.stem}.r1cs"),
        "wasm": str(js_dir / f"{circuit_path.stem}.wasm"),
        "sym": str(build_dir / f"{circuit_path.stem}.sym"),
        "witness_generator": str(js_dir / "generate_witness.js"),
    }


def export_inputs_for_artifact(
    proof_path: Path | str,
    *,
    build_dir: Path | str = DEFAULT_BUILD_DIR,
    max_bytes: int = CIRCOM_ARTIFACT_MAX_BYTES,
) -> dict[str, str]:
    proof_path = Path(proof_path)
    payload = json.loads(proof_path.read_text(encoding="utf-8"))
    artifact = artifact_from_dict(payload["proof"])
    build_dir = Path(build_dir)
    input_path = build_dir / "input.json"
    public_path = build_dir / "public.json"
    export_circom_artifact(
        artifact,
        input_path=input_path,
        public_path=public_path,
        max_bytes=max_bytes,
    )
    return {
        "input": str(input_path),
        "public": str(public_path),
    }


def groth16_setup(
    *,
    build_dir: Path | str = DEFAULT_BUILD_DIR,
    circuit_name: str = DEFAULT_CIRCUIT_NAME,
    ptau_path: Path | str = DEFAULT_PTAU,
) -> dict[str, str]:
    build_dir = Path(build_dir)
    snarkjs = _snarkjs_command()
    r1cs_path = build_dir / f"{circuit_name}.r1cs"
    ptau_path = Path(ptau_path)
    initial_zkey = build_dir / f"{circuit_name}_0000.zkey"
    final_zkey = build_dir / f"{circuit_name}_final.zkey"
    verification_key = build_dir / "verification_key.json"
    required_power = required_ptau_power_for_r1cs(r1cs_path)

    if not ptau_path.exists():
        prepare_local_ptau(ptau_path=ptau_path, power=required_power)

    _cleanup_setup_outputs([initial_zkey, final_zkey, verification_key])
    try:
        _run(snarkjs + ["groth16", "setup", str(r1cs_path), str(ptau_path), str(initial_zkey)])
    except subprocess.CalledProcessError as exc:
        error_text = ""
        if exc.stdout:
            error_text += exc.stdout
        if exc.stderr:
            error_text += exc.stderr
        too_small = "circuit too big for this power of tau ceremony" in error_text.lower()
        if too_small:
            prepare_local_ptau(ptau_path=ptau_path, power=required_power)
            _cleanup_setup_outputs([initial_zkey, final_zkey, verification_key])
            _run(snarkjs + ["groth16", "setup", str(r1cs_path), str(ptau_path), str(initial_zkey)])
        else:
            _cleanup_setup_outputs([initial_zkey, final_zkey, verification_key])
            raise RuntimeError(error_text.strip() or "snarkjs groth16 setup failed") from exc

    initial_bytes = initial_zkey.read_bytes()
    final_zkey.write_bytes(initial_bytes)
    try:
        _run(snarkjs + ["zkey", "export", "verificationkey", str(final_zkey), str(verification_key)])
    except subprocess.CalledProcessError as exc:
        _cleanup_setup_outputs([final_zkey, verification_key])
        error_text = ""
        if exc.stdout:
            error_text += exc.stdout
        if exc.stderr:
            error_text += exc.stderr
        raise RuntimeError(error_text.strip() or "snarkjs verification key export failed") from exc
    return {
        "zkey": str(final_zkey),
        "verification_key": str(verification_key),
    }


def prepare_local_ptau(
    *,
    ptau_path: Path | str = DEFAULT_PTAU,
    power: int = 18,
) -> str:
    ptau_path = Path(ptau_path)
    ptau_path.parent.mkdir(parents=True, exist_ok=True)
    snarkjs = _snarkjs_command()
    initial = ptau_path.with_name(f"{ptau_path.stem}_0000.ptau")
    contributed = ptau_path.with_name(f"{ptau_path.stem}_0001.ptau")

    _cleanup_setup_outputs([initial, contributed, ptau_path])
    _run(snarkjs + ["powersoftau", "new", "bn128", str(power), str(initial)])
    _run(
        snarkjs
        + [
            "powersoftau",
            "contribute",
            str(initial),
            str(contributed),
            "--name=pcdnssec local ptau",
            "-e=pcdnssec deterministic dev ptau contribution",
        ]
    )
    _run(snarkjs + ["powersoftau", "prepare", "phase2", str(contributed), str(ptau_path)])
    return str(ptau_path)


def generate_witness(
    *,
    build_dir: Path | str = DEFAULT_BUILD_DIR,
    circuit_name: str = DEFAULT_CIRCUIT_NAME,
    input_path: Path | str | None = None,
) -> str:
    build_dir = Path(build_dir)
    input_path = Path(input_path) if input_path is not None else build_dir / "input.json"
    js_dir = build_dir / f"{circuit_name}_js"
    wasm_path = js_dir / f"{circuit_name}.wasm"
    generator_path = js_dir / "generate_witness.js"
    witness_path = build_dir / "witness.wtns"
    _run(
        [
            "node",
            str(generator_path),
            str(wasm_path),
            str(input_path),
            str(witness_path),
        ]
    )
    return str(witness_path)


def groth16_prove(
    *,
    build_dir: Path | str = DEFAULT_BUILD_DIR,
    circuit_name: str = DEFAULT_CIRCUIT_NAME,
    witness_path: Path | str | None = None,
) -> dict[str, str]:
    build_dir = Path(build_dir)
    snarkjs = _snarkjs_command()
    witness_path = Path(witness_path) if witness_path is not None else build_dir / "witness.wtns"
    final_zkey = build_dir / f"{circuit_name}_final.zkey"
    proof_path = build_dir / "proof.json"
    public_path = build_dir / "public_snarkjs.json"
    _run(snarkjs + ["groth16", "prove", str(final_zkey), str(witness_path), str(proof_path), str(public_path)])
    return {
        "proof": str(proof_path),
        "public": str(public_path),
    }


def groth16_verify(
    *,
    build_dir: Path | str = DEFAULT_BUILD_DIR,
    verification_key_path: Path | str | None = None,
    public_path: Path | str | None = None,
    proof_path: Path | str | None = None,
) -> bool:
    build_dir = Path(build_dir)
    verification_key_path = (
        Path(verification_key_path) if verification_key_path is not None else build_dir / "verification_key.json"
    )
    public_path = Path(public_path) if public_path is not None else build_dir / "public_snarkjs.json"
    proof_path = Path(proof_path) if proof_path is not None else build_dir / "proof.json"
    snarkjs = _snarkjs_command()
    completed = subprocess.run(
        snarkjs + ["groth16", "verify", str(verification_key_path), str(public_path), str(proof_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip() or "snarkjs verify failed")
    return "[INFO]  snarkJS: OK!" in completed.stdout
