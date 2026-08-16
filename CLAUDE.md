# CLAUDE.md

@AGENTS.md

## Claude Code specifics

- No project subagents or hooks live here.
- The **private keys are not in this repository and never will be.**
  Until v1.0 the development key set lives in the workspace at
  `.keys/packages/` (three roots, one publisher per source); the
  publisher key is additionally a repository secret. Never commit key
  material, never print a private key, and never move a root key into
  CI — the whole point of the root/publisher split is that the roots are
  offline.
