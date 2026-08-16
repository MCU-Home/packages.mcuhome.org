# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The signed documents of a source: their header, their bytes, their signatures.

ADR 0025 §3 gives every signed document the same four header fields, and
§4 puts the signature in a detached sibling over **the exact bytes of the
document as served**. Both halves live here, because "the exact bytes"
only means something if one function decides them: :func:`dump` is that
function, and every document this repository writes goes through it.

The serialisation is deliberately the same one
``scripts/build_sdk_archive.py`` already uses for a local index — two
spaces, sorted keys, no ASCII escaping, one trailing newline — so a
locally built source directory and a published one differ in content
rather than in formatting.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

from mcuhome_packages.keys import SigningKey

__all__ = [
    "INDEX_EXPIRY_DAYS",
    "KEYS_EXPIRY_DAYS",
    "MIN_CLIENT",
    "MIRRORS_EXPIRY_DAYS",
    "SCHEMA_VERSION",
    "SIGNATURE_SUFFIX",
    "dump",
    "header",
    "parse_stamp",
    "signature_envelope",
    "stamp",
    "write_signed",
]

#: Schema generation of every document this tool writes (ADR 0025 §3).
#: Informational: no client refuses because of it.
SCHEMA_VERSION = 1

#: The smallest client generation allowed to use what we publish — the
#: one field that *can* refuse. Development documents carry 1; the v1.0
#: release moves documents and shipped clients to 2 together.
MIN_CLIENT = 1

#: How long each kind of document stays valid. The two publisher-signed
#: documents are refreshed weekly by CI, so 30 days survives three weeks
#: of outage. ``keys.json`` is root-signed, and root keys are offline by
#: definition: refreshing it is a manual ceremony, so its window is a
#: year and a scheduled check warns long before it closes.
INDEX_EXPIRY_DAYS = 30
MIRRORS_EXPIRY_DAYS = 30
KEYS_EXPIRY_DAYS = 365

#: What a document's detached signature is called.
SIGNATURE_SUFFIX = ".sig"


def dump(document: object) -> bytes:
    """*document* as the bytes that get served — and therefore signed."""
    return (json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode(
        "utf-8"
    )


def stamp(moment: datetime) -> str:
    """RFC 3339 in UTC, seconds — the one timestamp spelling (ADR 0025 §3)."""
    return moment.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_stamp(text: str) -> datetime:
    """A timestamp back, always timezone-aware."""
    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def header(*, issued: datetime, expires_days: int) -> dict[str, object]:
    """The four fields every signed document starts with."""
    return {
        "version": SCHEMA_VERSION,
        "min_client": MIN_CLIENT,
        "issued": stamp(issued),
        "expires": stamp(issued + timedelta(days=expires_days)),
    }


def signature_envelope(payload: bytes, signers: Iterable[SigningKey]) -> dict[str, object]:
    """The detached signature document for *payload*.

    Sorted by key id so that re-signing unchanged content with the same
    keys produces an unchanged file, and a diff shows a key change rather
    than a reordering.
    """
    signatures = [{"keyid": key.keyid, "sig": key.sign(payload)} for key in signers]
    if not signatures:
        raise SystemExit("refusing to write a signature document with no signatures")
    signatures.sort(key=lambda entry: entry["keyid"])
    return {"version": SCHEMA_VERSION, "signatures": signatures}


def write_signed(path: Path, document: object, signers: Sequence[SigningKey]) -> bytes:
    """Write *document* and its signature; return the bytes that were signed.

    The signature is made over what is written, not over what was meant:
    :func:`dump` runs once and both the file and the signer see its
    result.
    """
    payload = dump(document)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.with_name(path.name + SIGNATURE_SUFFIX).write_bytes(
        dump(signature_envelope(payload, signers))
    )
    return payload


def assert_advances(previous: object, issued: datetime, what: str) -> None:
    """Refuse unless *issued* is strictly newer than the document being replaced.

    ADR 0025 §3 closes the one weakness a timestamp has against a counter
    — it can go backwards under a skewed clock or two concurrent
    publishers — at the writing end rather than at the reading end. This
    is that check, and it is the reason a client may treat ``issued`` as
    monotonic.
    """
    if not isinstance(previous, dict):
        return
    before = previous.get("issued")
    if not isinstance(before, str):
        return
    if issued <= parse_stamp(before):
        raise SystemExit(
            f"{what}: issued {stamp(issued)} is not newer than the published "
            f"{before} — refusing to publish a document that does not advance"
        )
