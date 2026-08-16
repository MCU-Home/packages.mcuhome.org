# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""``sources.json``: the site's directory of sources — and nothing more.

The browsable page needs to know which directories are sources. That is a
convenience, and it must never become anything else: **nothing above a
source has authority** (ADR 0025 §1). A client resolves the source it was
configured with, against the anchor it was configured with; it does not
discover one here, and this file is signed by nobody on purpose.

Saying that in the file itself is the point of the note below. A
directory listing that looks official is exactly how a trust model gets
quietly undermined by its own convenience feature.

It is generated from ``publishing.json`` rather than maintained by hand,
and CI regenerates it and fails on a difference, so the two cannot drift.
"""

from __future__ import annotations

import json
from pathlib import Path

__all__ = ["CATALOG_FILE", "build_catalog", "write_catalog"]

CATALOG_FILE = "sources.json"

NOTE = (
    "Discovery for the browsable page, and unsigned on purpose. Nothing above a source has "
    "authority: every source carries its own root keys, mirror list and signed index, and a "
    "tool resolves the source it was configured with — it never learns of one from here."
)


def build_catalog(publishing: dict) -> dict:
    """The directory document, from the operational configuration."""
    sources = publishing.get("sources")
    if not isinstance(sources, dict):
        raise SystemExit("publishing.json carries no sources object")
    return {
        "note": NOTE,
        "sources": [
            {
                "name": name,
                "path": f"{name}/",
                "title": str(entry.get("title", name)),
                "description": str(entry.get("description", "")),
            }
            for name, entry in sorted(sources.items())
        ],
        "version": 1,
    }


def write_catalog(publishing_path: Path, catalog_path: Path) -> list[str]:
    """Write the catalogue; return the source names it lists."""
    try:
        publishing = json.loads(publishing_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as failure:
        raise SystemExit(f"{publishing_path}: {failure}") from failure
    catalog = build_catalog(publishing)
    catalog_path.write_text(
        json.dumps(catalog, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return [entry["name"] for entry in catalog["sources"]]
