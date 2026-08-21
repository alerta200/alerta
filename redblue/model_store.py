"""model_store.py — pack / install / locate the tuned defender adapter.

The vendor `pack()`s the trained adapter directory into a single sealed .nxpack (a tar sealed by
nxpack under a random content key). The customer `install()`s it: the key comes from their activated
licence (License.model_key), the pack is verified + decrypted + unpacked into a per-user model dir,
and the defender then loads it like any local adapter. Air-gapped and stdlib-only (tarfile + nxpack).

Layout:  ~/.nexus/models/<name>/   ← unpacked adapter (adapter_config.json, adapter_model.safetensors…)
Override the root with $NEXUS_MODEL_DIR.
"""
from __future__ import annotations

import io
import os
import tarfile
from pathlib import Path

from . import nxpack

DEFAULT_NAME = "defender"


def models_root() -> Path:
    return Path(os.environ.get("NEXUS_MODEL_DIR") or (Path.home() / ".nexus" / "models"))


def model_path(name: str = DEFAULT_NAME) -> Path:
    return models_root() / name


def installed_adapter(name: str = DEFAULT_NAME) -> str | None:
    """Path to an installed adapter dir if it looks complete (has adapter_config.json), else None."""
    p = model_path(name)
    return str(p) if (p / "adapter_config.json").is_file() else None


def _tar_dir(src: Path) -> bytes:
    """Deterministic-ish tar of the adapter dir's files (flat, sorted) into memory."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for f in sorted(src.iterdir()):
            if f.is_file():
                tar.add(str(f), arcname=f.name)
    return buf.getvalue()


def pack(adapter_dir: str, out_path: str, key: bytes | None = None) -> str:
    """Seal an adapter directory into out_path (.nxpack). Returns the base64 content key to embed
    in licences. Vendor-side; run once per model release."""
    src = Path(adapter_dir)
    if not (src / "adapter_config.json").is_file():
        raise ValueError(f"{adapter_dir} is not a LoRA adapter dir (no adapter_config.json)")
    key = key or nxpack.new_key()
    blob = nxpack.seal(_tar_dir(src), key)
    outp = Path(out_path)
    outp.parent.mkdir(parents=True, exist_ok=True)
    outp.write_bytes(blob)
    return nxpack.key_to_b64(key)


def install(pack_path: str, key_b64: str, name: str = DEFAULT_NAME) -> str:
    """Verify + decrypt + unpack a .nxpack into the per-user model dir. Returns the install path.
    Raises ValueError on a wrong key / tampered pack."""
    blob = Path(pack_path).read_bytes()
    data = nxpack.open_(blob, nxpack.key_from_b64(key_b64))
    dest = model_path(name)
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r") as tar:
        for m in tar.getmembers():
            # flat archive by construction; refuse anything with a path separator (tar-slip guard).
            if m.isfile() and "/" not in m.name and "\\" not in m.name and not m.name.startswith(".."):
                try:
                    tar.extract(m, str(dest), filter="data")   # defense-in-depth (Py 3.12+)
                except TypeError:
                    tar.extract(m, str(dest))                  # older Python: manual guard above
    if not (dest / "adapter_config.json").is_file():
        raise ValueError("pack did not contain a valid adapter (no adapter_config.json)")
    return str(dest)
