# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""The served site: its directory of sources, and what its pages may load.

Two properties are worth a test rather than a habit.

**The catalogue cannot drift.** ``sources.json`` is generated from
``publishing.json``; a source added to one and not the other would be a
directory that lies, and it would lie silently.

**The pages load nothing from another host.** This host exists so that
integrity is checkable, and a script fetched from somebody else's server
is the one moving part able to rewrite the hashes a visitor is reading.
Linking to another site is fine; *executing* code from one is not, and
the difference is what this checks.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from mcuhome.packagetool.catalog import CATALOG_FILE, build_catalog
from mcuhome.packagetool.source import INDEX_FILE

ROOT = Path(__file__).resolve().parent.parent
PAGES = ["index.html", "browser.html"]


@pytest.fixture(scope="module")
def catalog() -> dict:
    return json.loads((ROOT / CATALOG_FILE).read_text(encoding="utf-8"))


def test_the_catalogue_is_up_to_date(catalog: dict) -> None:
    publishing = json.loads((ROOT / "publishing.json").read_text(encoding="utf-8"))
    assert catalog == build_catalog(publishing), (
        "sources.json is stale — run: python -m mcuhome.packagetool catalog"
    )


def test_the_catalogue_and_the_published_sources_agree(catalog: dict) -> None:
    listed = {entry["name"] for entry in catalog["sources"]}
    published = {path.parent.name for path in ROOT.glob("*/" + INDEX_FILE)}
    assert listed == published, "a source is published but undeclared, or declared but absent"


def test_every_catalogue_entry_points_at_a_real_source(catalog: dict) -> None:
    for entry in catalog["sources"]:
        assert entry["path"] == f"{entry['name']}/"
        assert (ROOT / entry["path"] / INDEX_FILE).is_file()


def test_the_catalogue_says_it_is_not_authoritative(catalog: dict) -> None:
    """The convenience feature must not read as the trust model."""
    assert "authority" in catalog["note"] and "unsigned" in catalog["note"]


@pytest.mark.parametrize("page", PAGES)
def test_a_page_executes_nothing_from_another_host(page: str) -> None:
    html = (ROOT / page).read_text(encoding="utf-8")
    assert not re.search(r"<script[^>]+\bsrc\s*=", html, re.I), "no external script"
    assert not re.search(r"<link[^>]+\bhref\s*=\s*[\"']https?:", html, re.I), "no stylesheet"
    assert not re.search(r"<(img|iframe)[^>]+\bsrc\s*=\s*[\"']https?:", html, re.I)
    assert "@import" not in html


@pytest.mark.parametrize("page", PAGES)
def test_a_page_fetches_only_from_this_host(page: str) -> None:
    html = (ROOT / page).read_text(encoding="utf-8")
    for target in re.findall(r"""fetch\(\s*([^,)]+)""", html):
        assert "http" not in target, f"{page}: fetch({target}) leaves this host"


def test_the_inspection_page_admits_it_verifies_nothing() -> None:
    """The page is served by the host it reads, so it can attest to nothing.

    A host serving a modified package would serve a matching hash and
    this very page, with the check taken out. Showing signed-looking data
    without saying that is worse than showing nothing: it manufactures
    confidence the visitor has no way to earn.
    """
    html = (ROOT / "browser.html").read_text(encoding="utf-8")
    assert "cannot verify" in html or "verifies nothing" in html
    assert "not verified" in html
    # And the caveat has to reach a downloader, not only a careful reader.
    assert "showModal" in html, "every download passes the warning dialog"
    assert "askBeforeDownloading" in html


def test_no_page_sells_the_download_as_protected() -> None:
    """Wording is the whole risk here: 'signed index' reads as 'safe file'."""
    for page in PAGES:
        html = (ROOT / page).read_text(encoding="utf-8")
        assert "signed index" not in html.lower()


def test_sources_can_be_switched_off_not_only_filtered() -> None:
    html = (ROOT / "browser.html").read_text(encoding="utf-8")
    assert 'type: "checkbox"' in html or 'type="checkbox"' in html
    assert "state.enabled" in html


def test_the_browser_reads_the_files_the_site_actually_has() -> None:
    html = (ROOT / "browser.html").read_text(encoding="utf-8")
    assert CATALOG_FILE in html
    assert INDEX_FILE in html
    # A split index keeps most entries in parts; a browser that only read
    # the head would under-report and never say so.
    assert "index.parts" in html
