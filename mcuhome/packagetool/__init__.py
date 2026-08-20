# SPDX-FileCopyrightText: 2026 The MCUHome Contributors
# SPDX-License-Identifier: Apache-2.0
"""Publishing tooling for the MCUHome package host.

The write side of a source. The read side — what a client must check, and
therefore the authority on whether a source is trustworthy — is
``verify.py`` at the repository root, which imports nothing from here on
purpose.
"""
