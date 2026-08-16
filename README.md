# packages.mcuhome.org

The **package host**: the hash-pinned packages MCUHome tools build
against, and the tooling that publishes them. Served as
[packages.mcuhome.org](https://packages.mcuhome.org) via GitHub Pages.

The design — layout, trust model, and the rule a client follows — is
[ADR 0025](https://github.com/mcu-home/mcuhome/blob/main/docs/adr/draft/0025-package-distribution.md)
in the flagship repository. This README is how to operate it.

## What is published here

Each top-level directory is a **source**: self-contained, independently
signed, independently mirrorable, and silent about every other
directory. Today there is one:

| Source | Holds |
|---|---|
| `sdk/` | the `mcuhome-sdk-<version>.tar.zst` package a build compiles from |

```
sdk/
├── keys.json      keys.json.sig     3 root keys (threshold 2), and the publisher keys they authorise
├── keys/…                           every superseded key set, kept forever
├── mirrors.json   mirrors.json.sig  where this source's data may be fetched
├── index.json     index.json.sig    which file and which bytes, for every version
├── index-…json                      immutable index parts, when the index is split
└── mcuhome-sdk-<version>.tar.zst    plus a .sha256 sidecar
```

Deliberately **not** here: container images (GHCR), Python
distributions (PyPI), OTA images.

[`browser.html`](browser.html) lists every package of every source in one
table — split indexes included — with per-source switches, search,
sorting and paging. It is an **inspection tool, not a distribution
channel**: it verifies nothing and *cannot*, because a page served by
this host can say nothing about this host. A host serving a modified
package would serve a matching hash and this very page, with the check
taken out. The page says so in a banner, and every download goes through
a dialog that says it again; the anchor lives in the tool for exactly
this reason.

It loads no external script either: a page that displays hashes must not
execute code from somebody else's server, so its hundred lines are
vanilla JavaScript and a test keeps it that way. `sources.json` is the
same list as data, generated from `publishing.json`; it is **unsigned
discovery only** — nothing above a source has authority, and a tool never
learns of a source from there.

## Verifying

`verify.py` is the normative reference implementation — the rule every
client follows, in executable form. It verifies a source you already
have; fetching and mirror selection are the client's business and cannot
change a verdict.

```sh
python verify.py sdk/ --anchor <anchor.json>
```

An **anchor** is the root key set you trust: the *public* halves of the
three root keys, their key ids, and the threshold. Deliberately nothing
else — the publisher keys are not in it, because they are learned from
`keys.json`, which the roots sign. That is what lets a publisher key
rotate yearly without any tool being updated.

It is configuration, never something this host supplies. A tool carries
the anchor for our sources built in (it ships inside the release, on the
same trust as the tool itself); an operator of a private registry
supplies theirs out of band. `anchor.json` is published here so it can be
**compared** against what a tool has built in — downloading it at
verification time is not verification, it is trusting the host again.

## Publishing

Publication **pulls**: this repository fetches a release asset from the
SDK repository, so no repository holds write access to another and there
is no cross-repository secret.

Which upstream release feeds which source is declared in
`publishing.json` — that, and the `source` input, is how the workflow
knows what it is publishing. A second source is an entry in that file,
not a second workflow; CI and the weekly refresh iterate over the same
list.

Publishing itself is a click, not a command:

> **Actions → "Publish a package" → Run workflow**, with `source` and the
> upstream `tag`.

```sh
# Renew the publisher-signed documents before they expire (weekly, in CI)
python -m mcuhome_packages refresh --source sdk

# How long is everything still valid?
python -m mcuhome_packages status --source sdk
```

Nothing is ever replaced: a published version, an index entry and a
superseded key set stay forever. The only prunable artefact is an index
part no head references any more, and only after 90 days:

```sh
python -m mcuhome_packages prune --source sdk          # report
python -m mcuhome_packages prune --source sdk --delete # act
```

## Keys

| Role | Count | Where the private key lives | Signs |
|---|---|---|---|
| root | 3, threshold 2 | offline, physically separated | `keys.json` only |
| publisher | 1 per source | the repository's protected `production` environment | `index.json`, `mirrors.json` |

3-of-which-2 is the smallest configuration that survives both *losing* a
key and *someone stealing* one. The publisher key is the one that has to
be online, so it is the one that will eventually leak — which is why it
is separate, short-lived, and replaceable without touching a client.

### Rotating the publisher key (yearly, or after a leak)

```sh
python -m mcuhome_packages keygen --dir <keydir> --name publisher-sdk-2
python -m mcuhome_packages init --source sdk … --publisher <both .pub.json files> …
```

During the overlap the secret holds **both** PEM blocks, so `index.json`
and `mirrors.json` carry both signatures and old and new clients read the
same file. When the overlap ends, the outgoing key is listed in
`revoked` as `retired` — its earlier signatures stay valid. A key that
*leaked* is listed as `compromised` instead: a thief can backdate, so
its past is worth no more than its future, and every signature it ever
made becomes invalid.

### Renewing `keys.json`

`keys.json` is root-signed and expires after a year, so renewing it is a
deliberate act with the offline keys — CI cannot do it, by construction,
and a refresh path that could would mean the roots were not offline. The
`status` command warns 60 days ahead, and CI fails on that warning.

**Until v1.0 these are development keys**, generated without passphrases
and kept in the workspace. The v1.0 release regenerates them properly,
re-signs the published documents, and raises `min_client` to 2 so no
pre-v1 client — which may lack a security fix — can use this host.

## Mirroring

A mirror is a copy of a source directory. No path rewriting, no
per-mirror layout: whatever is below the base URL is identical
everywhere, so `rsync`, `wget -r` or a bucket sync is the whole job. A
mirror may carry one source and not another. To be listed in a source's
`mirrors.json`, open an issue.

## Development

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest                      # the reference verifier against the committed corpus
ruff check . && ruff format --check .
python tests/make_vectors.py   # regenerate the corpus
```

The test vectors in `tests/vectors/` are the point of the corpus: they
let a *client* implementation be tested against the same cases before
that client exists — valid, expired, rolled back, wrong key, revoked
(retired and compromised), tampered index, tampered part, dual-signed
across a rotation overlap, `min_client` too high, below threshold, and a
key set two rotations past the anchor.
