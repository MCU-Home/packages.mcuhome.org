# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Building and maintaining one source: its key set, mirror list and index.

A **source** is one self-contained directory (ADR 0025 §1): everything
needed to use it lives at or below it, and nothing in it says anything
about any other source. This module is the write side of that — the read
side, and the authority on what a client must check, is ``verify.py`` at
the repository root.

Three operations matter and each is small:

``init``      lay a source down: ``keys.json`` (root-signed),
              ``mirrors.json`` and an empty ``index.json``
``add``       record one package, in the part that covers it or in the head
``refresh``   renew the two publisher-signed documents before they expire

What deliberately has no operation here is *deleting* anything.
Superseded part files are the sole prunable artefact (§2), and
:func:`unreferenced_parts` only reports them.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from packaging.version import InvalidVersion, Version

from mcuhome.packagetool.documents import (
    INDEX_EXPIRY_DAYS,
    KEYS_EXPIRY_DAYS,
    MIRRORS_EXPIRY_DAYS,
    SIGNATURE_SUFFIX,
    assert_advances,
    dump,
    header,
    write_signed,
)
from mcuhome.packagetool.keys import SigningKey

__all__ = [
    "INDEX_FILE",
    "KEYS_FILE",
    "MIRRORS_FILE",
    "PublicKey",
    "add_package",
    "covering_part",
    "init_source",
    "part_filename",
    "read_document",
    "refresh",
    "unreferenced_parts",
    "write_keys",
]

KEYS_FILE = "keys.json"
MIRRORS_FILE = "mirrors.json"
INDEX_FILE = "index.json"
KEYS_ARCHIVE = "keys"


@dataclass(frozen=True)
class PublicKey:
    """A public key as a document records it, with its validity window."""

    keyid: str
    public: str
    not_before: str
    not_after: str

    def entry(self) -> dict[str, str]:
        return {
            "keyid": self.keyid,
            "public": self.public,
            "not_before": self.not_before,
            "not_after": self.not_after,
        }


def read_document(path: Path) -> dict:
    """One JSON document, or a refusal naming the file."""
    try:
        loaded = json.loads(path.read_bytes())
    except (OSError, ValueError) as failure:
        raise SystemExit(f"{path}: {failure}") from failure
    if not isinstance(loaded, dict):
        raise SystemExit(f"{path} is not a JSON object")
    return loaded


# --------------------------------------------------------------------------- keys


def write_keys(
    source: Path,
    *,
    roots: Sequence[PublicKey],
    threshold: int,
    publishers: Sequence[PublicKey],
    revoked: Sequence[dict[str, str]] = (),
    issued: datetime,
    signers: Sequence[SigningKey],
) -> None:
    """Write (or replace) the source's ``keys.json``, root-signed.

    The predecessor is archived under ``keys/<issued>.json`` before it is
    replaced and is named by the new document's ``previous``, so a client
    that has been offline across rotations can walk backwards to a key
    set it still trusts and then verify forward (ADR 0025 §6). Archived
    key sets are never removed.
    """
    path = source / KEYS_FILE
    previous_link: str | None = None
    if path.exists():
        old = read_document(path)
        assert_advances(old, issued, KEYS_FILE)
        stamped = str(old.get("issued", "")).replace(":", "").replace("-", "")
        archive = source / KEYS_ARCHIVE / f"{stamped}.json"
        archive.parent.mkdir(parents=True, exist_ok=True)
        if not archive.exists():
            archive.write_bytes(path.read_bytes())
            signature = path.with_name(path.name + SIGNATURE_SUFFIX)
            if signature.exists():
                archive.with_name(archive.name + SIGNATURE_SUFFIX).write_bytes(
                    signature.read_bytes()
                )
        previous_link = f"{KEYS_ARCHIVE}/{archive.name}"

    if threshold > len(roots):
        raise SystemExit(f"threshold {threshold} exceeds the {len(roots)} root keys given")
    if len(signers) < threshold:
        raise SystemExit(f"{len(signers)} signing keys given, threshold is {threshold}")

    document = {
        **header(issued=issued, expires_days=KEYS_EXPIRY_DAYS),
        "previous": previous_link,
        "roots": {"threshold": threshold, "keys": [key.entry() for key in roots]},
        "publishers": [key.entry() for key in publishers],
        "revoked": list(revoked),
    }
    write_signed(path, document, signers)


# --------------------------------------------------------------------------- index


def part_filename(covers: dict, payload: bytes) -> str:
    """What a part file is called: a readable shard label plus its content hash.

    Immutability is the service's guarantee rather than every client's
    discipline (ADR 0025 §2), and it is this name that gives it: the same
    content always yields the same name, changed content always yields a
    different one, so no cache at any layer can serve a stale part under
    a current name.
    """
    digest = hashlib.sha256(payload).hexdigest()[:16]
    label = "part"
    for kind in ("versions", "names"):
        span = covers.get(kind) if isinstance(covers, dict) else None
        if isinstance(span, dict) and span.get("min") is not None:
            label = f"{span.get('min')}-{span.get('max')}"
            break
    label = re.sub(r"[^A-Za-z0-9._-]+", "_", label).strip("_") or "part"
    return f"index-{label}-{digest}.json"


def _version_in(covers: dict, version: str) -> bool:
    """Whether *version* belongs in a part declaring *covers*."""
    span = covers.get("versions") if isinstance(covers, dict) else None
    if not isinstance(span, dict):
        return False
    try:
        candidate = Version(version)
        low = Version(str(span["min"]))
        high = Version(str(span["max"]))
    except (InvalidVersion, KeyError, TypeError):
        return False
    return low <= candidate <= high


def covering_part(parts: Sequence[dict], version: str) -> dict | None:
    """The part a new *version* belongs in, or ``None`` for the head.

    Placement is a publishing decision, not a consequence of age: the
    publisher declares what a part covers and every entry goes where it
    is covered (ADR 0025 §2).
    """
    for part in parts:
        if _version_in(part.get("covers") or {}, version):
            return part
    return None


def _entries_of_part(source: Path, part: dict) -> dict:
    """A part's packages, after checking it against the hash in the head."""
    path = source / str(part["file"])
    payload = path.read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    if digest != part.get("sha256"):
        raise SystemExit(f"{path} does not match the sha256 the index head records")
    document = json.loads(payload)
    packages = document.get("packages")
    return packages if isinstance(packages, dict) else {}


def _known_versions(source: Path, index: dict, name: str) -> set[str]:
    """Every version of *name* the source already records, head and parts."""
    found = set((index.get("packages") or {}).get(name, {}))
    for part in index.get("parts") or []:
        found |= set(_entries_of_part(source, part).get(name, {}))
    return found


def add_package(
    source: Path,
    *,
    name: str,
    version: str,
    file: str,
    sha256: str,
    size: int,
    issued: datetime,
    signers: Sequence[SigningKey],
) -> str:
    """Record one package. Returns where it landed, for the workflow log.

    Refuses if the version is already recorded anywhere in the source: a
    published version is immutable, and a second entry under the same
    number is the one thing the whole content-addressing exists to
    prevent.
    """
    path = source / INDEX_FILE
    index = read_document(path)
    assert_advances(index, issued, INDEX_FILE)

    if version in _known_versions(source, index, name):
        raise SystemExit(
            f"{name} {version} is already published in this source — "
            "a published version is never replaced"
        )

    entry = {"file": file, "sha256": sha256, "size": size}
    parts = list(index.get("parts") or [])
    target = covering_part(parts, version)

    if target is None:
        packages = dict(index.get("packages") or {})
        versions = dict(packages.get(name) or {})
        versions[version] = entry
        packages[name] = versions
        index["packages"] = packages
        landed = INDEX_FILE
    else:
        entries = _entries_of_part(source, target)
        versions = dict(entries.get(name) or {})
        versions[version] = entry
        rebuilt = {**entries, name: versions}
        payload = dump({"packages": rebuilt})
        filename = part_filename(target.get("covers") or {}, payload)
        (source / filename).write_bytes(payload)
        target["file"] = filename
        target["sha256"] = hashlib.sha256(payload).hexdigest()
        index["parts"] = parts
        landed = filename

    index.update(header(issued=issued, expires_days=INDEX_EXPIRY_DAYS))
    index.setdefault("parts", parts)
    write_signed(path, index, signers)
    return landed


def unreferenced_parts(source: Path) -> list[Path]:
    """Part files no longer named by the head — prunable after §2's grace period."""
    index = read_document(source / INDEX_FILE)
    referenced = {str(part.get("file")) for part in index.get("parts") or []}
    return sorted(
        candidate
        for candidate in source.glob("index-*.json")
        if candidate.name not in referenced and not candidate.name.endswith(SIGNATURE_SUFFIX)
    )


# --------------------------------------------------------------------------- mirrors


def write_mirrors(
    source: Path,
    *,
    mirrors: Sequence[dict[str, object]],
    issued: datetime,
    signers: Sequence[SigningKey],
) -> None:
    """Write the source's mirror list — where *this* source's data may be fetched."""
    path = source / MIRRORS_FILE
    if path.exists():
        assert_advances(read_document(path), issued, MIRRORS_FILE)
    for mirror in mirrors:
        url = str(mirror.get("url", ""))
        if not url.startswith("https://") or not url.endswith("/"):
            raise SystemExit(f"mirror {url!r} must be an https:// base URL ending in '/'")
    document = {
        **header(issued=issued, expires_days=MIRRORS_EXPIRY_DAYS),
        "mirrors": list(mirrors),
    }
    write_signed(path, document, signers)


# --------------------------------------------------------------------------- lifecycle


def init_source(
    source: Path,
    *,
    roots: Sequence[PublicKey],
    threshold: int,
    publishers: Sequence[PublicKey],
    mirrors: Sequence[dict[str, object]],
    issued: datetime,
    root_signers: Sequence[SigningKey],
    publisher_signers: Sequence[SigningKey],
) -> None:
    """Lay down a complete, empty source."""
    write_keys(
        source,
        roots=roots,
        threshold=threshold,
        publishers=publishers,
        issued=issued,
        signers=root_signers,
    )
    write_mirrors(source, mirrors=mirrors, issued=issued, signers=publisher_signers)
    index = {**header(issued=issued, expires_days=INDEX_EXPIRY_DAYS), "parts": [], "packages": {}}
    write_signed(source / INDEX_FILE, index, publisher_signers)


def refresh(source: Path, *, issued: datetime, signers: Sequence[SigningKey]) -> list[str]:
    """Renew the two publisher-signed documents. Returns what was rewritten.

    ``keys.json`` is deliberately untouched: it is root-signed, root keys
    are offline, and a refresh path that could re-sign it would mean the
    roots were not offline after all.
    """
    rewritten = []
    for filename, days in ((INDEX_FILE, INDEX_EXPIRY_DAYS), (MIRRORS_FILE, MIRRORS_EXPIRY_DAYS)):
        path = source / filename
        if not path.exists():
            continue
        document = read_document(path)
        assert_advances(document, issued, filename)
        document.update(header(issued=issued, expires_days=days))
        write_signed(path, document, signers)
        rewritten.append(filename)
    return rewritten
