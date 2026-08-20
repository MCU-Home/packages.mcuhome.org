# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Ed25519 key material: generation, identity, signing.

Two kinds of key exist, and the difference is where the private half
lives rather than anything about the key itself (ADR 0025 §5): **root**
keys are offline and sign only ``keys.json``, **publisher** keys live in
a protected CI environment and sign a source's ``index.json`` and
``mirrors.json``.

A key's **identity is the SHA-256 of its raw 32-byte public key**, hex.
It is derived, never assigned: two files holding the same key have the
same id, and a key id in a signature therefore names bytes rather than a
label somebody chose.

Private keys are stored as unencrypted PKCS#8 PEM. That is a deliberate
choice for the development key set only — ADR 0025's consequences say
so, and the v1.0 ceremony replaces them with passphrase-protected keys
kept apart. The file mode is 0600 either way.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

__all__ = [
    "PUBLIC_SUFFIX",
    "SigningKey",
    "generate",
    "key_id",
    "load_private",
    "load_public",
    "public_b64",
]

#: What a generated key's public half is called next to its PEM. It is a
#: small JSON document rather than a bare string so that the key id
#: travels with the key and nobody has to recompute it by hand.
PUBLIC_SUFFIX = ".pub.json"


def key_id(public: Ed25519PublicKey) -> str:
    """The key's identity: SHA-256 of its raw public bytes, hex."""
    return hashlib.sha256(_raw(public)).hexdigest()


def public_b64(public: Ed25519PublicKey) -> str:
    """The raw 32-byte public key, base64 — how a document records it."""
    return base64.b64encode(_raw(public)).decode("ascii")


def load_public(encoded: str) -> Ed25519PublicKey:
    """A public key back from the base64 :func:`public_b64` wrote."""
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(encoded, validate=True))


def _raw(public: Ed25519PublicKey) -> bytes:
    return public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


@dataclass(frozen=True)
class SigningKey:
    """One private key, with the identity its public half determines."""

    keyid: str
    private: Ed25519PrivateKey

    @property
    def public(self) -> Ed25519PublicKey:
        return self.private.public_key()

    def sign(self, payload: bytes) -> str:
        """*payload* signed, base64 — the exact bytes, never a digest of them."""
        return base64.b64encode(self.private.sign(payload)).decode("ascii")


def load_private(path: Path) -> SigningKey:
    """A signing key from an unencrypted PKCS#8 PEM file."""
    private = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise SystemExit(f"{path} is not an Ed25519 private key")
    return SigningKey(keyid=key_id(private.public_key()), private=private)


def load_private_pem(pem: bytes) -> SigningKey:
    """The same, from PEM bytes — what a CI secret hands over."""
    private = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(private, Ed25519PrivateKey):
        raise SystemExit("the supplied PEM is not an Ed25519 private key")
    return SigningKey(keyid=key_id(private.public_key()), private=private)


def generate(directory: Path, name: str) -> SigningKey:
    """A fresh key pair as ``<name>.pem`` and ``<name>.pub.json`` in *directory*.

    Refuses rather than overwrites: a key file that already exists is
    either in use or a backup, and the one irreversible mistake available
    here is replacing it.
    """
    directory.mkdir(parents=True, exist_ok=True)
    private_path = directory / f"{name}.pem"
    public_path = directory / f"{name}{PUBLIC_SUFFIX}"
    for existing in (private_path, public_path):
        if existing.exists():
            raise SystemExit(f"{existing} exists — refusing to overwrite key material")

    private = Ed25519PrivateKey.generate()
    private_path.write_bytes(
        private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    private_path.chmod(0o600)

    key = SigningKey(keyid=key_id(private.public_key()), private=private)
    # Written through the same dumper the documents use, so a public key
    # file and a document agree byte for byte about how a key is spelled.
    from mcuhome.packagetool.documents import dump

    public_path.write_bytes(
        dump({"keyid": key.keyid, "public": public_b64(key.public), "name": name})
    )
    return key
