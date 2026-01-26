# Conan config

This directory is reserved for repo-specific Conan configuration such as
profiles and remotes.

Typical usage:

```bash
conan config install conan/config
```

Notes:
- If you add profiles here, prefer naming them explicitly (e.g. `profiles/linux-x86_64`).
- This repo defaults to `conan profile detect --force` in `scripts/bootstrap.sh`.
