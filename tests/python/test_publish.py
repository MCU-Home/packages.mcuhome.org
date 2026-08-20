# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The publishing side: what it writes, and what it refuses to write.

The refusals matter more than the writes. A published version is
immutable and eternal (ADR 0025 §1), and every guard here exists so that
the one irreversible mistake — replacing something already published —
cannot be made by a workflow at three in the morning.
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest
from make_vectors import BASE, NOW, VECTORS, key, public

from mcuhome.packagetool.documents import parse_stamp
from mcuhome.packagetool.source import (
    INDEX_FILE,
    KEYS_FILE,
    MIRRORS_FILE,
    add_package,
    covering_part,
    init_source,
    read_document,
    refresh,
    unreferenced_parts,
    write_keys,
    write_mirrors,
)
from verify import load_anchor, verify_source

ANCHOR = load_anchor(VECTORS / "anchor.json")


@pytest.fixture
def source(tmp_path: Path) -> Path:
    roots = [key(name) for name in ("root-a", "root-b", "root-c")]
    publisher = key("publisher-1")
    place = tmp_path / "sdk"
    init_source(
        place,
        roots=[public(signer) for signer in roots],
        threshold=2,
        publishers=[public(publisher, years=1)],
        mirrors=[{"url": "https://packages.example.org/sdk/"}],
        issued=BASE,
        root_signers=roots,
        publisher_signers=[publisher],
    )
    return place


def test_a_fresh_source_verifies(source: Path) -> None:
    assert verify_source(source, ANCHOR, now=NOW)["entries"] == 0


def test_a_published_version_is_never_replaced(source: Path) -> None:
    common = {"name": "mcuhome-sdk", "file": "p.tar.zst", "sha256": "a" * 64, "size": 10}
    add_package(
        source,
        version="2.4.0",
        issued=BASE + timedelta(days=1),
        signers=[key("publisher-1")],
        **common,
    )
    with pytest.raises(SystemExit, match="already published"):
        add_package(
            source,
            version="2.4.0",
            issued=BASE + timedelta(days=2),
            signers=[key("publisher-1")],
            **{**common, "sha256": "b" * 64},
        )


def test_a_document_must_advance(source: Path) -> None:
    """The one weakness a timestamp has against a counter, closed when writing."""
    signers = [key("publisher-1")]
    add_package(
        source,
        name="mcuhome-sdk",
        version="2.4.0",
        file="p.tar.zst",
        sha256="a" * 64,
        size=10,
        issued=BASE + timedelta(days=2),
        signers=signers,
    )
    with pytest.raises(SystemExit, match="does not advance"):
        add_package(
            source,
            name="mcuhome-sdk",
            version="2.5.0",
            file="q.tar.zst",
            sha256="b" * 64,
            size=10,
            issued=BASE + timedelta(days=1),
            signers=signers,
        )


def test_an_entry_lands_in_the_part_that_covers_it(source: Path) -> None:
    from hashlib import sha256

    from mcuhome.packagetool.documents import dump, write_signed
    from mcuhome.packagetool.source import part_filename

    covers = {"versions": {"min": "1.0.0", "max": "1.9999.0"}}
    payload = dump({"packages": {}})
    filename = part_filename(covers, payload)
    (source / filename).write_bytes(payload)
    index = read_document(source / INDEX_FILE)
    index["parts"] = [{"file": filename, "sha256": sha256(payload).hexdigest(), "covers": covers}]
    write_signed(source / INDEX_FILE, index, [key("publisher-1")])

    landed = add_package(
        source,
        name="mcuhome-sdk",
        version="1.5.0",
        file="old.tar.zst",
        sha256="c" * 64,
        size=10,
        issued=BASE + timedelta(days=1),
        signers=[key("publisher-1")],
    )
    assert landed != INDEX_FILE
    # The part file was replaced by one named after its new content, so no
    # cache anywhere can serve the old bytes under the current name.
    assert landed != filename
    assert read_document(source / INDEX_FILE)["packages"] == {}
    assert verify_source(source, ANCHOR, now=NOW)["entries"] == 1
    assert [path.name for path in unreferenced_parts(source)] == [filename]


def test_a_version_outside_every_part_lands_in_the_head(source: Path) -> None:
    parts = [{"file": "x", "sha256": "y", "covers": {"versions": {"min": "1.0", "max": "1.9"}}}]
    assert covering_part(parts, "2.4.0") is None
    assert covering_part(parts, "1.5.0") is parts[0]


def test_refresh_renews_the_publisher_documents_and_leaves_keys_alone(source: Path) -> None:
    before = read_document(source / KEYS_FILE)
    later = BASE + timedelta(days=20)
    assert set(refresh(source, issued=later, signers=[key("publisher-1")])) == {
        INDEX_FILE,
        MIRRORS_FILE,
    }
    # keys.json is root-signed: a CI refresh cannot touch it.
    assert read_document(source / KEYS_FILE) == before
    assert parse_stamp(read_document(source / INDEX_FILE)["expires"]) > parse_stamp(
        before["issued"]
    )
    assert verify_source(source, ANCHOR, now=later + timedelta(days=25))


def test_a_mirror_must_be_an_https_base_url(source: Path) -> None:
    for bad in ("http://mirror.example.org/sdk/", "https://mirror.example.org/sdk"):
        with pytest.raises(SystemExit, match="https"):
            write_mirrors(
                source,
                mirrors=[{"url": bad}],
                issued=BASE + timedelta(days=1),
                signers=[key("publisher-1")],
            )


def test_rotating_keys_archives_the_predecessor(source: Path) -> None:
    roots = [key(name) for name in ("root-a", "root-b", "root-c")]
    write_keys(
        source,
        roots=[public(signer) for signer in (key("root-d"), key("root-e"), key("root-f"))],
        threshold=2,
        publishers=[public(key("publisher-1"), years=1)],
        issued=BASE + timedelta(days=1),
        signers=roots[:2],
    )
    rotated = read_document(source / KEYS_FILE)
    archived = source / str(rotated["previous"])
    assert archived.is_file(), "a client offline across rotations walks this chain"
    assert archived.with_name(archived.name + ".sig").is_file()
    assert json.loads(archived.read_text())["roots"]["keys"][0]["keyid"] == public(roots[0]).keyid
    # The anchor still reaches the new set, through the archived one.
    assert verify_source(source, ANCHOR, now=NOW)


def test_keygen_never_overwrites(tmp_path: Path) -> None:
    from mcuhome.packagetool.keys import generate

    generate(tmp_path, "root-x")
    with pytest.raises(SystemExit, match="refusing to overwrite"):
        generate(tmp_path, "root-x")
