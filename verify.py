#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Verify an MCUHome package source — the normative reference implementation.

This file *is* the specification of ADR 0025 §9 in executable form. A
client (the command line, the workbench, a build server, or something
nobody here wrote) is conformant when it reaches the same verdicts. Where
this file and prose disagree, this file is the one that was tested.

**Deliberately standalone.** It imports the standard library and
``cryptography`` and nothing of this repository, so it can be copied next
to a mirrored directory and run. That costs a little duplication with
``mcuhome_packages/`` and buys a verifier anyone can audit in one sitting.

**It verifies; it does not fetch.** The input is a source you already
have — a mirrored directory, a cache, a checkout. Choosing a mirror,
transporting bytes and handling failover are the client's, and none of
them can change a verdict: that is the point of signing the content
rather than trusting the host.

What is checked, in the order ADR 0025 §9 gives:

1. the anchor is the caller's, never a document from the source
2. ``keys.json`` — threshold root signatures, walking ``previous`` when
   the source has rotated past the anchor
3. ``mirrors.json`` — a publisher signature
4. (choosing a mirror is the client's)
5. ``index.json`` — a publisher signature, and freshness against state
6. every part named by the head — its sha256
7. package entries — shape; the bytes themselves are checked when fetched
8. revocation — ``compromised`` invalidates the past, ``retired`` does not

Usage::

    verify.py <source-dir> --anchor <anchor.json> [--client-generation N]
              [--now <ISO>] [--state <file>]

Exit status: 0 when every check passes, 1 on the first refusal, 2 on a
usage error.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

#: This verifier's client generation. A document may raise `min_client`
#: to lock out clients with a known flaw; one whose generation is lower
#: refuses rather than continuing (ADR 0025 §3).
CLIENT_GENERATION = 1

KEYS_FILE = "keys.json"
MIRRORS_FILE = "mirrors.json"
INDEX_FILE = "index.json"
SIGNATURE_SUFFIX = ".sig"


class Refused(Exception):
    """A verification verdict of "no", with the reason a user should read."""


@dataclass(frozen=True)
class KeySet:
    """Public keys that may sign something, and how many must."""

    keys: dict[str, str]  # keyid -> base64 raw public key
    threshold: int
    windows: dict[str, tuple[str, str]] = field(default_factory=dict)


def _load(path: Path) -> tuple[bytes, dict]:
    """A document as both its exact bytes and its parsed form.

    The bytes are what a signature covers — never a re-serialisation of
    the parsed form, which would depend on this program's formatting
    rather than on the publisher's.
    """
    if not path.is_file():
        raise Refused(f"{path} is missing")
    payload = path.read_bytes()
    try:
        document = json.loads(payload)
    except ValueError as broken:
        raise Refused(f"{path} is not JSON: {broken}") from broken
    if not isinstance(document, dict):
        raise Refused(f"{path} is not a JSON object")
    return payload, document


def _stamp(text: object, what: str) -> datetime:
    if not isinstance(text, str):
        raise Refused(f"{what} is missing a timestamp")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as broken:
        raise Refused(f"{what}: {text!r} is not an RFC 3339 timestamp") from broken
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def check_signatures(payload: bytes, signature_path: Path, allowed: KeySet, what: str) -> list[str]:
    """The key ids that validly signed *payload*, or a refusal.

    A signature by a key outside *allowed* is not an error, it simply
    does not count — that is what lets one document carry both the
    outgoing and the incoming key across a rotation overlap. Too few
    countable signatures is the error.
    """
    _, envelope = _load(signature_path)
    entries = envelope.get("signatures")
    if not isinstance(entries, list) or not entries:
        raise Refused(f"{signature_path} carries no signatures")

    accepted: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        keyid = entry.get("keyid")
        encoded = allowed.keys.get(keyid) if isinstance(keyid, str) else None
        if encoded is None:
            continue
        try:
            public = Ed25519PublicKey.from_public_bytes(base64.b64decode(encoded, validate=True))
            public.verify(base64.b64decode(str(entry.get("sig")), validate=True), payload)
        except (InvalidSignature, ValueError, TypeError):
            raise Refused(f"{what}: the signature by {keyid} does not verify") from None
        accepted.append(keyid)

    if len(accepted) < allowed.threshold:
        raise Refused(
            f"{what}: {len(accepted)} usable signature(s), {allowed.threshold} required "
            f"(signed by: {', '.join(str(e.get('keyid')) for e in entries if isinstance(e, dict))})"
        )
    return accepted


def check_header(document: dict, *, now: datetime, generation: int, what: str) -> datetime:
    """The four header fields (ADR 0025 §3). Returns the document's ``issued``.

    ``version`` is read but never refused on: schema growth is additive
    by rule, and refusing an unknown generation would break every old
    client on every added field. Refusing is `min_client`'s job alone.
    """
    minimum = document.get("min_client")
    if not isinstance(minimum, int):
        raise Refused(f"{what} declares no min_client")
    if minimum > generation:
        raise Refused(
            f"{what} requires client generation {minimum}; this one is {generation} — "
            "update the tool"
        )
    issued = _stamp(document.get("issued"), what)
    if _stamp(document.get("expires"), what) <= now:
        raise Refused(f"{what} expired on {document.get('expires')} — the source is stale")
    if issued > now:
        raise Refused(f"{what} is dated in the future ({document.get('issued')})")
    return issued


def _valid_at(window: tuple[str, str] | None, moment: datetime, keyid: str, what: str) -> None:
    if window is None:
        return
    if not (_stamp(window[0], what) <= moment <= _stamp(window[1], what)):
        raise Refused(f"{what}: key {keyid} was outside its validity window at {moment:%Y-%m-%d}")


def _revocations(document: dict) -> dict[str, dict]:
    entries = document.get("revoked")
    if not isinstance(entries, list):
        return {}
    return {
        str(entry.get("keyid")): entry
        for entry in entries
        if isinstance(entry, dict) and entry.get("keyid")
    }


def _key_set(document: dict, role: str, threshold: int) -> KeySet:
    if role == "roots":
        block = document.get("roots")
        entries = block.get("keys") if isinstance(block, dict) else None
        threshold = block.get("threshold", threshold) if isinstance(block, dict) else threshold
    else:
        entries = document.get(role)
    if not isinstance(entries, list) or not entries:
        raise Refused(f"{KEYS_FILE} lists no {role}")
    if not isinstance(threshold, int) or threshold < 1:
        raise Refused(f"{KEYS_FILE} declares an unusable threshold {threshold!r}")
    keys = {}
    windows = {}
    for entry in entries:
        if not isinstance(entry, dict) or "keyid" not in entry or "public" not in entry:
            raise Refused(f"{KEYS_FILE} has a malformed {role} entry")
        keys[str(entry["keyid"])] = str(entry["public"])
        if "not_before" in entry and "not_after" in entry:
            windows[str(entry["keyid"])] = (str(entry["not_before"]), str(entry["not_after"]))
    return KeySet(keys=keys, threshold=threshold, windows=windows)


def load_anchor(path: Path) -> KeySet:
    """The caller's trust anchor: root key ids, public keys, threshold.

    It is configuration, never something the source supplies. A client
    that fetched its anchor would reduce every signature below to "the
    host said so".
    """
    _, document = _load(path)
    entries = document.get("keys")
    threshold = document.get("threshold")
    if not isinstance(entries, list) or not entries or not isinstance(threshold, int):
        raise Refused(f"{path} is not an anchor (keys[] and threshold required)")
    return KeySet(
        keys={str(e["keyid"]): str(e["public"]) for e in entries},
        threshold=threshold,
    )


def verify_keys(source: Path, anchor: KeySet, *, now: datetime, generation: int) -> dict:
    """``keys.json``, walking ``previous`` when the source rotated past the anchor.

    Only the *current* key set is held to the header's expiry: a
    superseded one is expected to be expired, and refusing it would make
    catching up after a long offline period impossible — the exact case
    the chain exists for.
    """
    payload, document = _load(source / KEYS_FILE)
    check_header(document, now=now, generation=generation, what=KEYS_FILE)

    chain: list[tuple[Path, bytes, dict]] = [(source / KEYS_FILE, payload, document)]
    while True:
        newest = chain[-1]
        try:
            check_signatures(
                newest[1],
                newest[0].with_name(newest[0].name + SIGNATURE_SUFFIX),
                anchor,
                f"{newest[0].name} against the anchor",
            )
            break
        except Refused as unusable:
            link = newest[2].get("previous")
            if not isinstance(link, str) or not link:
                raise Refused(
                    f"{KEYS_FILE} cannot be verified with the configured anchor and names no "
                    f"predecessor to walk back to ({unusable})"
                ) from unusable
            older = source / link
            if any(older == step[0] for step in chain):
                raise Refused(f"{KEYS_FILE}: the previous-chain loops at {link}") from unusable
            chain.append((older, *_load(older)))

    # Forward again: each document is authorised by the roots of the one
    # before it, which is what makes a rotation a chain rather than a leap.
    trusted = anchor
    for path, body, document in reversed(chain):
        signature = path.with_name(path.name + SIGNATURE_SUFFIX)
        signers = check_signatures(body, signature, trusted, path.name)
        revoked = _revocations(document)
        for keyid in signers:
            if revoked.get(keyid, {}).get("mode") == "compromised":
                raise Refused(f"{path.name} is signed by {keyid}, which is revoked as compromised")
        trusted = _key_set(document, "roots", trusted.threshold)
    return chain[0][2]


def verify_signed_by_publisher(
    source: Path, filename: str, keys: dict, *, now: datetime, generation: int, state: dict
) -> dict:
    """One publisher-signed document: signature, header, and anti-rollback."""
    payload, document = _load(source / filename)
    issued = check_header(document, now=now, generation=generation, what=filename)

    publishers = _key_set(keys, "publishers", 1)
    revoked = _revocations(keys)
    signature = (source / filename).with_name(filename + SIGNATURE_SUFFIX)
    signers = check_signatures(payload, signature, publishers, filename)

    usable = []
    for keyid in signers:
        mode = revoked.get(keyid, {}).get("mode")
        if mode == "compromised":
            # A thief can backdate, so the past of a stolen key is worth
            # no more than its future.
            continue
        if mode == "retired":
            # Retired only means "signs nothing new"; what it signed
            # while valid stays valid, and the window check below decides.
            pass
        _valid_at(publishers.windows.get(keyid), issued, keyid, filename)
        usable.append(keyid)
    if not usable:
        raise Refused(f"{filename}: every signature is by a revoked or out-of-window key")

    seen = state.get(filename)
    if isinstance(seen, str) and issued <= _stamp(seen, filename):
        raise Refused(
            f"{filename} is dated {document.get('issued')}, not newer than the {seen} already "
            "seen — a rolled back or frozen copy"
        )
    state[filename] = document.get("issued")
    return document


def verify_parts(source: Path, index: dict) -> int:
    """Every part the head names, checked against the hash the head records.

    Parts carry no signature of their own: the head's signature reaches
    them through these hashes, which is also why a key compromise does
    not orphan history — the next head re-attests all of it.
    """
    parts = index.get("parts")
    if parts is None:
        return 0
    if not isinstance(parts, list):
        raise Refused(f"{INDEX_FILE}: parts is not a list")
    for part in parts:
        if not isinstance(part, dict) or "file" not in part or "sha256" not in part:
            raise Refused(f"{INDEX_FILE}: a part entry is malformed")
        name = str(part["file"])
        if "/" in name or name.startswith("."):
            raise Refused(f"{INDEX_FILE}: part {name!r} is not a plain file name in the source")
        path = source / name
        if not path.is_file():
            raise Refused(f"part {name} is missing from this copy of the source")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != part["sha256"]:
            raise Refused(f"part {name} hashes to {digest}, the index head says {part['sha256']}")
    return len(parts)


def verify_entries(source: Path, index: dict) -> int:
    """The shape of every package entry, head and parts.

    The *bytes* of a package are checked when it is fetched, against the
    ``sha256`` recorded here; what this can check without fetching is
    that every entry states a file, a hash and a size at all.
    """
    documents = [index]
    for part in index.get("parts") or []:
        documents.append(json.loads((source / str(part["file"])).read_bytes()))
    total = 0
    for document in documents:
        packages = document.get("packages")
        if not isinstance(packages, dict):
            raise Refused("a package index carries no packages object")
        for name, versions in packages.items():
            if not isinstance(versions, dict):
                raise Refused(f"{name}: versions is not an object")
            for version, entry in versions.items():
                if not isinstance(entry, dict) or not {"file", "sha256", "size"} <= set(entry):
                    raise Refused(f"{name} {version}: entry needs file, sha256 and size")
                total += 1
    return total


def verify_source(
    source: Path,
    anchor: KeySet,
    *,
    now: datetime | None = None,
    generation: int = CLIENT_GENERATION,
    state: dict | None = None,
) -> dict:
    """Run every check over *source*. Raises :class:`Refused` on the first failure."""
    now = now or datetime.now(UTC)
    state = {} if state is None else state

    keys = verify_keys(source, anchor, now=now, generation=generation)
    mirrors = verify_signed_by_publisher(
        source, MIRRORS_FILE, keys, now=now, generation=generation, state=state
    )
    index = verify_signed_by_publisher(
        source, INDEX_FILE, keys, now=now, generation=generation, state=state
    )
    for mirror in mirrors.get("mirrors") or []:
        url = str(mirror.get("url", "")) if isinstance(mirror, dict) else ""
        if not url.startswith("https://") or not url.endswith("/"):
            raise Refused(f"{MIRRORS_FILE}: {url!r} is not an https base URL ending in '/'")

    return {
        "roots": len((keys.get("roots") or {}).get("keys") or []),
        "threshold": (keys.get("roots") or {}).get("threshold"),
        "publishers": len(keys.get("publishers") or []),
        "revoked": len(keys.get("revoked") or []),
        "mirrors": len(mirrors.get("mirrors") or []),
        "parts": verify_parts(source, index),
        "entries": verify_entries(source, index),
        "state": state,
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("source", type=Path, help="the source directory to verify")
    parser.add_argument("--anchor", type=Path, required=True, help="the root key set to trust")
    parser.add_argument("--client-generation", type=int, default=CLIENT_GENERATION)
    parser.add_argument("--now", help="ISO timestamp to verify as of, instead of the clock")
    parser.add_argument("--state", type=Path, help="anti-rollback state; read and updated")
    arguments = parser.parse_args(argv)

    state = {}
    if arguments.state and arguments.state.is_file():
        state = json.loads(arguments.state.read_text(encoding="utf-8"))

    try:
        report = verify_source(
            arguments.source,
            load_anchor(arguments.anchor),
            now=_stamp(arguments.now, "--now") if arguments.now else None,
            generation=arguments.client_generation,
            state=state,
        )
    except Refused as refusal:
        print(f"REFUSED  {refusal}", file=sys.stderr)
        return 1

    if arguments.state:
        arguments.state.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    print(
        f"OK  {arguments.source}: {report['threshold']}-of-{report['roots']} roots, "
        f"{report['publishers']} publisher(s), {report['revoked']} revoked, "
        f"{report['mirrors']} mirror(s), {report['parts']} part(s), "
        f"{report['entries']} package entr{'y' if report['entries'] == 1 else 'ies'}"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
