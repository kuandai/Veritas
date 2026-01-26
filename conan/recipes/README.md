# Custom Conan recipes

## cyrus-sasl (SRP enabled)

This repo includes a custom `cyrus-sasl/2.1.28` recipe with SRP and SRP
setpass enabled by default.

Usage (Conan v2):

```bash
conan export conan/recipes/cyrus-sasl/2.1.28 --version 2.1.28
conan install . -of build -s build_type=Debug --build=missing
```

Notes:
- If SRP plugins are built as shared modules, set `SASL_PLUGIN_PATH` to the
  package's `lib/sasl2` directory at runtime.
- Override options if needed, e.g. `-o cyrus-sasl/*:with_srp=False`.
