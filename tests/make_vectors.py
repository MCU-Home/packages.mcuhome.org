# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Build the test vectors: one source directory per case, valid and broken.

The vectors are committed, and this script is how they are regenerated —
they exist so that a *client* implementation (the command line, the
workbench, a build server, somebody else's tool) can be tested against
the same corpus as the reference verifier, before that client exists.
That is what makes ADR 0025 §9 a transcription rather than a second
design.

Everything is stamped from fixed times so a regenerated corpus differs
only where its content differs; tests verify "as of" ``NOW``.

Run it from the repository root::

    python tests/make_vectors.py
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from mcuhome_packages.documents import dump, write_signed  # noqa: E402
from mcuhome_packages.keys import (  # noqa: E402
    SigningKey,
    generate,
    key_id,
    load_private,
    public_b64,
)
from mcuhome_packages.source import (  # noqa: E402
    INDEX_FILE,
    KEYS_FILE,
    MIRRORS_FILE,
    PublicKey,
    add_package,
    init_source,
    part_filename,
    read_document,
    write_keys,
)

VECTORS = Path(__file__).parent / "vectors"
KEYS = VECTORS / "_keys"

#: When the corpus is issued, and when a test verifies it. Far enough
#: apart to be realistic, close enough that a 30-day document is live.
BASE = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
NOW = datetime(2026, 2, 1, 12, 0, 0, tzinfo=UTC)

MIRROR = "https://packages.example.org/sdk/"
PACKAGE = ("mcuhome-sdk", "2.4.0", "mcuhome-sdk-2.4.0.tar.zst", "a" * 64, 512345)


def key(name: str) -> SigningKey:
    """A vector key, generated on first use and committed afterwards."""
    path = KEYS / f"{name}.pem"
    if not path.exists():
        return generate(KEYS, name)
    return load_private(path)


def public(signer: SigningKey, *, issued: datetime = BASE, years: int = 3) -> PublicKey:
    return PublicKey(
        keyid=key_id(signer.public),
        public=public_b64(signer.public),
        not_before=_stamp(issued),
        not_after=_stamp(issued + timedelta(days=365 * years)),
    )


def _stamp(moment: datetime) -> str:
    return moment.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def build(
    case: str,
    *,
    roots: list[SigningKey],
    threshold: int,
    root_signers: list[SigningKey],
    publishers: list[SigningKey],
    publisher_signers: list[SigningKey],
    issued: datetime = BASE,
    index_issued: datetime | None = None,
    revoked: list[dict] | None = None,
    with_package: bool = True,
) -> Path:
    """A complete source for *case*, from the same code that publishes for real."""
    source = VECTORS / case
    shutil.rmtree(source, ignore_errors=True)
    source.mkdir(parents=True)

    init_source(
        source,
        roots=[public(signer, issued=issued) for signer in roots],
        threshold=threshold,
        publishers=[public(signer, issued=issued, years=1) for signer in publishers],
        mirrors=[{"url": MIRROR}],
        issued=issued,
        root_signers=root_signers,
        publisher_signers=publisher_signers,
    )
    if revoked:
        document = read_document(source / KEYS_FILE)
        document["revoked"] = revoked
        write_signed(source / KEYS_FILE, document, root_signers)
    if with_package:
        name, version, filename, digest, size = PACKAGE
        add_package(
            source,
            name=name,
            version=version,
            file=filename,
            sha256=digest,
            size=size,
            issued=index_issued or issued + timedelta(minutes=1),
            signers=publisher_signers,
        )
    return source


def resign(source: Path, filename: str, signers: list[SigningKey]) -> None:
    write_signed(source / filename, read_document(source / filename), signers)


def main() -> int:
    KEYS.mkdir(parents=True, exist_ok=True)
    root_a, root_b, root_c = key("root-a"), key("root-b"), key("root-c")
    root_d, root_e, root_f = key("root-d"), key("root-e"), key("root-f")
    pub_1, pub_2, outsider = key("publisher-1"), key("publisher-2"), key("outsider")

    anchor = {
        "version": 1,
        "threshold": 2,
        "keys": [
            {"keyid": key_id(signer.public), "public": public_b64(signer.public)}
            for signer in (root_a, root_b, root_c)
        ],
    }
    (VECTORS / "anchor.json").write_bytes(dump(anchor))

    standard = {
        "roots": [root_a, root_b, root_c],
        "threshold": 2,
        "root_signers": [root_a, root_b, root_c],
        "publishers": [pub_1],
        "publisher_signers": [pub_1],
    }

    # 1 — everything as it should be.
    build("valid", **standard)

    # 2 — an index that expired before NOW: a mirror serving a frozen copy.
    build("expired-index", **{**standard, "issued": BASE - timedelta(days=60)})

    # 3 — the index signed by a key the key set does not list.
    source = build("wrong-key", **standard)
    resign(source, INDEX_FILE, [outsider])

    # 4 — a retired publisher: signed while valid, so it still verifies.
    build(
        "revoked-retired",
        **{
            **standard,
            "publishers": [pub_1, pub_2],
            "revoked": [
                {
                    "keyid": key_id(pub_1.public),
                    "at": _stamp(BASE + timedelta(days=2)),
                    "mode": "retired",
                    "reason": "routine rotation",
                }
            ],
        },
    )

    # 5 — a compromised publisher: a thief can backdate, so its past dies too.
    build(
        "revoked-compromised",
        **{
            **standard,
            "publishers": [pub_1, pub_2],
            "revoked": [
                {
                    "keyid": key_id(pub_1.public),
                    "at": _stamp(BASE + timedelta(days=2)),
                    "mode": "compromised",
                    "reason": "CI secret exposed",
                }
            ],
        },
    )

    # 6 — a rotation overlap: both the outgoing and the incoming key sign.
    build(
        "overlap-dual-signed",
        **{
            **standard,
            "publishers": [pub_1, pub_2],
            "publisher_signers": [pub_1, pub_2],
            "revoked": [
                {
                    "keyid": key_id(pub_1.public),
                    "at": _stamp(BASE + timedelta(days=2)),
                    "mode": "retired",
                    "reason": "routine rotation",
                }
            ],
        },
    )

    # 7 — one byte changed after signing.
    source = build("tampered-index", **standard)
    path = source / INDEX_FILE
    document = read_document(path)
    entry = document["packages"][PACKAGE[0]][PACKAGE[1]]
    entry["sha256"] = "b" * 64
    path.write_bytes(dump(document))

    # 8 — keys.json signed by one root where two are required. The
    # publishing tool refuses to produce this, which is the point; the
    # vector is made by re-signing behind its back.
    source = build("below-threshold", **standard)
    resign(source, KEYS_FILE, [root_a])

    # 9 — a client generation older than the documents demand.
    source = build("min-client-too-high", **standard)
    for filename, signers in (
        (KEYS_FILE, [root_a, root_b, root_c]),
        (MIRRORS_FILE, [pub_1]),
        (INDEX_FILE, [pub_1]),
    ):
        document = read_document(source / filename)
        document["min_client"] = 2
        write_signed(source / filename, document, signers)

    # 10 — a source with a part, and the same source with the part altered.
    for case in ("with-parts", "tampered-part"):
        source = build(case, **standard, with_package=False)
        entries = {
            "packages": {
                PACKAGE[0]: {"1.2.0": {"file": "old.tar.zst", "sha256": "c" * 64, "size": 4096}}
            }
        }
        payload = dump(entries)
        covers = {"versions": {"min": "1.0.0", "max": "1.9999.0"}}
        filename = part_filename(covers, payload)
        (source / filename).write_bytes(payload)
        document = read_document(source / INDEX_FILE)
        document["parts"] = [
            {"file": filename, "sha256": hashlib.sha256(payload).hexdigest(), "covers": covers}
        ]
        write_signed(source / INDEX_FILE, document, [pub_1])
        # A version inside the part's range must land in the part, not the head.
        add_package(
            source,
            name=PACKAGE[0],
            version="1.5.0",
            file="mcuhome-sdk-1.5.0.tar.zst",
            sha256="d" * 64,
            size=4321,
            issued=BASE + timedelta(minutes=2),
            signers=[pub_1],
        )
        if case == "tampered-part":
            named = read_document(source / INDEX_FILE)["parts"][0]["file"]
            altered = json.loads((source / named).read_text())
            altered["packages"][PACKAGE[0]]["1.5.0"]["sha256"] = "e" * 64
            (source / named).write_bytes(dump(altered))

    # 11 — two rotations past the anchor, reachable only by walking `previous`.
    source = build("rotated-chain", **standard)
    write_keys(
        source,
        roots=[public(signer) for signer in (root_d, root_e, root_f)],
        threshold=2,
        publishers=[public(pub_1, years=1)],
        issued=BASE + timedelta(days=1),
        signers=[root_a, root_b],  # the outgoing roots authorise the incoming set
    )
    write_keys(
        source,
        roots=[public(signer) for signer in (root_d, root_e, root_f)],
        threshold=2,
        publishers=[public(pub_1, years=1)],
        issued=BASE + timedelta(days=2),
        signers=[root_d, root_e],  # signed only by keys the anchor has never seen
    )

    print(f"{len(list(VECTORS.glob('*/'))) - 1} vectors written to {VECTORS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
