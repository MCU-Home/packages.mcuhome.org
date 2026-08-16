# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The publishing tool: ``python -m mcuhome_packages <command>``.

Everything an operator or a workflow does to a source goes through here,
so that "how a document is written" has exactly one implementation. What
a *client* does with the result is ``verify.py``, deliberately separate
and deliberately standalone.

Commands:

``keygen``    a fresh Ed25519 key pair
``anchor``    a root key set as a client would embed or configure it
``init``      lay down a complete, empty source
``add``       record one package in a source
``refresh``   renew the publisher-signed documents before they expire
``status``    how long each document is still valid (a CI guard)
``prune``     list superseded part files past their grace period
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

from mcuhome_packages.catalog import CATALOG_FILE, write_catalog
from mcuhome_packages.documents import dump, parse_stamp, stamp
from mcuhome_packages.keys import (
    PUBLIC_SUFFIX,
    SigningKey,
    generate,
    load_private,
    load_private_pem,
)
from mcuhome_packages.source import (
    INDEX_FILE,
    KEYS_FILE,
    MIRRORS_FILE,
    PublicKey,
    add_package,
    init_source,
    read_document,
    refresh,
    unreferenced_parts,
)

#: A superseded part file may be removed once nothing references it, but
#: only after this long — a lagging mirror and a client in the middle of
#: resolving must never be cut off (ADR 0025 §2).
PRUNE_GRACE_DAYS = 90

#: How early ``status`` starts complaining. ``keys.json`` needs an
#: offline ceremony to renew, so its warning has to arrive with enough
#: time to arrange one.
WARN_DAYS = {KEYS_FILE: 60, INDEX_FILE: 7, MIRRORS_FILE: 7}

#: Where a workflow finds the publisher key: one or more PEM blocks in
#: one environment variable, so a key overlap (ADR 0025 §6) needs no
#: change to the workflow, only a second block in the secret.
PUBLISHER_ENV = "MCUHOME_PUBLISHER_KEYS"


def _publisher_keys(paths: list[Path]) -> list[SigningKey]:
    if paths:
        return [load_private(path) for path in paths]
    blob = os.environ.get(PUBLISHER_ENV, "").strip()
    if not blob:
        raise SystemExit(
            f"no publisher key: pass --publisher-key or set {PUBLISHER_ENV} to its PEM"
        )
    blocks = [f"-----BEGIN{part}" for part in blob.split("-----BEGIN") if part.strip()]
    return [load_private_pem(block.encode("utf-8")) for block in blocks]


def _public(path: Path) -> dict:
    document = read_document(path)
    for field in ("keyid", "public"):
        if field not in document:
            raise SystemExit(f"{path} is not a public key file (no {field})")
    return document


def _window(issued: datetime, years: int) -> tuple[str, str]:
    return stamp(issued), stamp(issued + timedelta(days=365 * years))


def _now(argument: str | None) -> datetime:
    return parse_stamp(argument) if argument else datetime.now(UTC)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="mcuhome_packages", description=__doc__.splitlines()[0])
    parser.add_argument("--now", help="ISO timestamp to use instead of the clock (tests)")
    commands = parser.add_subparsers(dest="command", required=True)

    keygen = commands.add_parser("keygen", help="generate an Ed25519 key pair")
    keygen.add_argument("--dir", type=Path, required=True)
    keygen.add_argument("--name", required=True)

    anchor = commands.add_parser("anchor", help="write a root key set for a client")
    anchor.add_argument("--public", type=Path, nargs="+", required=True)
    anchor.add_argument("--threshold", type=int, required=True)
    anchor.add_argument("--out", type=Path, required=True)

    init = commands.add_parser("init", help="lay down a complete, empty source")
    init.add_argument("--source", type=Path, required=True)
    init.add_argument("--root", type=Path, nargs="+", required=True, help=f"*{PUBLIC_SUFFIX} files")
    init.add_argument("--threshold", type=int, required=True)
    init.add_argument("--publisher", type=Path, nargs="+", required=True)
    init.add_argument("--mirror", nargs="+", required=True, help="https base URLs ending in /")
    init.add_argument("--root-key", type=Path, nargs="+", required=True, help="root PEMs to sign")
    init.add_argument("--publisher-key", type=Path, nargs="*", default=[])
    init.add_argument("--root-years", type=int, default=3)
    init.add_argument("--publisher-years", type=int, default=1)

    add = commands.add_parser("add", help="record one package in a source")
    add.add_argument("--source", type=Path, required=True)
    add.add_argument("--name", required=True)
    add.add_argument("--version", required=True)
    add.add_argument("--file", required=True)
    add.add_argument("--sha256", required=True)
    add.add_argument("--size", type=int, required=True)
    add.add_argument("--publisher-key", type=Path, nargs="*", default=[])

    renew = commands.add_parser("refresh", help="renew the publisher-signed documents")
    renew.add_argument("--source", type=Path, nargs="+", required=True)
    renew.add_argument("--publisher-key", type=Path, nargs="*", default=[])

    status = commands.add_parser("status", help="report remaining validity; fail when it runs low")
    status.add_argument("--source", type=Path, nargs="+", required=True)

    prune = commands.add_parser("prune", help="list superseded part files past the grace period")
    prune.add_argument("--source", type=Path, nargs="+", required=True)
    prune.add_argument("--delete", action="store_true")

    commands.add_parser("catalog", help="write sources.json, the site's unsigned directory")

    arguments = parser.parse_args(argv)
    now = _now(arguments.now)

    if arguments.command == "keygen":
        key = generate(arguments.dir, arguments.name)
        print(f"{arguments.name}  {key.keyid}")
        return 0

    if arguments.command == "anchor":
        keys = [_public(path) for path in arguments.public]
        if arguments.threshold > len(keys):
            raise SystemExit(f"threshold {arguments.threshold} exceeds {len(keys)} keys")
        arguments.out.write_bytes(
            dump(
                {
                    "version": 1,
                    "threshold": arguments.threshold,
                    "keys": [{"keyid": k["keyid"], "public": k["public"]} for k in keys],
                    # An anchor is configuration a client carries, not a
                    # document it collects. Published so that a mirror
                    # operator or an auditor can compare it against what
                    # their tool has built in — comparing is the use;
                    # fetching it at verification time is not.
                    "note": (
                        "Trust anchor. Configure it out of band and compare it against "
                        "what your tool ships; downloading it at verification time is "
                        "not verification."
                    ),
                }
            )
        )
        print(f"{arguments.out}  {arguments.threshold}-of-{len(keys)}")
        return 0

    if arguments.command == "init":
        root_window = _window(now, arguments.root_years)
        publisher_window = _window(now, arguments.publisher_years)
        roots = [
            PublicKey(k["keyid"], k["public"], *root_window)
            for k in (_public(path) for path in arguments.root)
        ]
        publishers = [
            PublicKey(k["keyid"], k["public"], *publisher_window)
            for k in (_public(path) for path in arguments.publisher)
        ]
        init_source(
            arguments.source,
            roots=roots,
            threshold=arguments.threshold,
            publishers=publishers,
            mirrors=[{"url": url} for url in arguments.mirror],
            issued=now,
            root_signers=[load_private(path) for path in arguments.root_key],
            publisher_signers=_publisher_keys(arguments.publisher_key),
        )
        print(f"{arguments.source}: {KEYS_FILE}, {MIRRORS_FILE}, {INDEX_FILE} written and signed")
        return 0

    if arguments.command == "add":
        landed = add_package(
            arguments.source,
            name=arguments.name,
            version=arguments.version,
            file=arguments.file,
            sha256=arguments.sha256,
            size=arguments.size,
            issued=now,
            signers=_publisher_keys(arguments.publisher_key),
        )
        print(f"{arguments.name} {arguments.version} recorded in {landed}")
        return 0

    if arguments.command == "refresh":
        signers = _publisher_keys(arguments.publisher_key)
        for source in arguments.source:
            for name in refresh(source, issued=now, signers=signers):
                print(f"{source}/{name} refreshed")
        return 0

    if arguments.command == "status":
        worst = 0
        for source in arguments.source:
            for name, warn in WARN_DAYS.items():
                path = source / name
                if not path.exists():
                    continue
                left = (parse_stamp(read_document(path)["expires"]) - now).days
                mark = "!" if left < warn else " "
                print(f"{mark} {source}/{name}: {left} days left (warn below {warn})")
                if left < warn:
                    worst = 1
        if worst:
            print(
                f"\nrenew: `refresh` for {INDEX_FILE}/{MIRRORS_FILE}; {KEYS_FILE} needs the "
                "offline root keys — see the repository README",
                file=sys.stderr,
            )
        return worst

    if arguments.command == "catalog":
        written = write_catalog(Path("publishing.json"), Path(CATALOG_FILE))
        print(f"{CATALOG_FILE}: {', '.join(written) or 'no sources'}")
        return 0

    if arguments.command == "prune":
        cutoff = now - timedelta(days=PRUNE_GRACE_DAYS)
        for source in arguments.source:
            for candidate in unreferenced_parts(source):
                aged = datetime.fromtimestamp(candidate.stat().st_mtime, UTC) < cutoff
                if aged and arguments.delete:
                    candidate.unlink()
                    print(f"removed {candidate}")
                else:
                    print(f"{'prunable' if aged else 'in grace'}: {candidate}")
        return 0

    raise SystemExit(f"unknown command {arguments.command}")  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
