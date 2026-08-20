# mcuhome-packagetool

`mcuhome-packagetool` is MCUHome's package host: the static site at
`packages.mcuhome.org`, the tool that publishes into it, and the reference
verifier clients check it with. It is where a released SDK package becomes
something a build pins by hash and signature, not by trusting a URL.

## What this repository holds

- `sdk/` — the published MCUHome SDK source: a self-contained directory carrying its own root keys, mirror list, signed index and package files.
- `verify.py` — the normative reference verifier, standalone so it can be copied next to a mirrored source and run with the standard library and `cryptography`.
- `mcuhome/packagetool/` — the publishing tool: it lays a source down, records a package, renews the publisher-signed documents and reports how much validity is left.
- `anchor.json` — the root key set, published so a client can compare it against the anchor it already holds; fetching it at verification time is not verification.
- The pages the host serves, and `sources.json`, the unsigned directory of sources generated from `publishing.json` — a listing for a human to browse, with no authority over any source.

## Using it

A source is a plain directory, and everything needed to trust it is inside:
the packages, the key set that signs the index, and the mirror list. Verifying
one is therefore local work on bytes you already have — a mirror, a cache or a
checkout — against a root anchor supplied out of band:

```sh
python verify.py sdk --anchor anchor.json
```

Operating a source is the other half: `python -m mcuhome.packagetool` lays a
source down, records a package in it, renews its signatures and reports how
long each document is still valid.

## How it fits into MCUHome

The packages served here are the release archives of
[mcuhome-sdk](https://github.com/mcu-home/mcuhome-sdk), pulled from a tagged
release and recorded into the `sdk` source by the publish workflow in this
repository. A source's `index.json` names each package with its size and
sha256, which is what
[mcuhome-workbench](https://github.com/mcu-home/mcuhome-workbench) resolves an
SDK pin against and what
[mcuhome-buildserver](https://github.com/mcu-home/mcuhome-buildserver) finds a
package's bytes by. Because a source is self-contained, a copy of one is worth
exactly as much as the original.

## Layout

| Path | Purpose |
|---|---|
| `sdk/` | The published MCUHome SDK source: signed documents and package files |
| `mcuhome/` | The publishing tool — keys, signed documents, sources, catalogue |
| `tests/` | The suite, and the fixed source directories it verifies, one per outcome |
| `.github/` | The publish, refresh and check workflows |

## Working on this repository

The repository wants Python 3.13 and its `dev` extra; beyond `cryptography`
and `packaging` it uses the standard library. The gate is lint, the unit suite
against the fixed test vectors, and the regenerated catalogue matched against
`publishing.json`:

```sh
pip install -e '.[dev]'
ruff check . && ruff format --check . && pytest -q
python -m mcuhome.packagetool catalog && git diff --exit-code sources.json
```

The same commands run on every push and pull request, followed there by the
reference verifier over every source `publishing.json` declares, so a broken
signature or an expiring document fails here rather than in somebody's build.

## Configuration

`publishing.json` declares each source: which upstream repository and
release-asset pattern feed it, and the title and description the catalogue
publishes for it. Adding a source is an entry in that file, not a change to a
workflow. The publisher key the tool signs with comes from `--publisher-key`
or from `MCUHOME_PUBLISHER_KEYS`, which holds its PEM.

## Security

A package is trusted by signature and hash, never by the host or the mirror
that served it: root keys sign `keys.json` and stay offline, the publisher key
signs `index.json` and `mirrors.json` from a protected CI environment, and a
verdict is reached against an anchor the client already holds. Nothing
published is deleted — a superseded part file past its grace period is the
only artefact the tool will remove. Report a suspected key or signature
compromise through
[the organization's security policy](https://github.com/mcu-home/.github/blob/main/SECURITY.md).

## Documentation

- [`verify.py`](verify.py) — what a client must check, in executable form
- [`mcuhome/packagetool/`](mcuhome/packagetool/) — the publishing tool, documented module by module
- [packages.mcuhome.org](https://packages.mcuhome.org) — the sources this repository serves
- [The MCUHome organization](https://github.com/mcu-home) — the other repositories of the project

## Contributing and support

Bug reports and questions go to this repository's
[issue tracker](https://github.com/mcu-home/mcuhome-packagetool/issues).
How a change is submitted is described in
[the organization's contributing rules](https://github.com/mcu-home/.github/blob/main/CONTRIBUTING.md).

## License

Apache License 2.0, see [`LICENSE`](LICENSE).
