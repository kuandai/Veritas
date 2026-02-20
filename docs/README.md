# Veritas Documentation

Entry point for project documentation. This folder is intentionally structured
to separate architecture, component docs, protocols, and status snapshots.

## Index

- `architecture/overview.md`: system-level overview and boundaries.
- `architecture/notary-threat-model.md`: Notary trust boundaries and attacker model.
- `architecture/notary-pki-policy.md`: Notary certificate profile and lifecycle policy baseline.
- `build.md`: build instructions (including SRP-enabled SASL recipe).
- `components/`
  - `components/gatekeeper.md`
  - `components/notary.md`
  - `components/shared.md`
  - `components/libveritas.md`
- `protocol/README.md`: protobuf layout and status.
- `security/changes.md`: deployment-impacting security behavior and operator
  responsibilities.
- `security/tracking.md`: security hardening item register and sprint status.
- `status/current-state.md`: current implementation snapshot, with placeholders
  and aspirational features clearly marked.
