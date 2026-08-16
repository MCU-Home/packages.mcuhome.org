# Test keys — no authority anywhere, ever

These Ed25519 private keys exist **only** to build the test vectors in
the directory above. They are committed on purpose: the corpus has to be
reproducible, and a client implementation being tested against it needs
to be able to add cases of its own.

None of them appears in any published `keys.json`, so a signature by any
of them is worth exactly nothing outside `tests/`. Deleting them breaks
`make_vectors.py` and nothing else.

The real keys are elsewhere and are not in any repository: three offline
root keys, and one publisher key per source that lives in this
repository's protected environment. See `README.md` at the root.
