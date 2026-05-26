# Hyperion Productization Guide

Hyperion now ships a first-class `hyperion` CLI, formal JSON Schemas, a packaged C ABI header, a Python helper package, Docker/devcontainer setup, starter kits, and a one-command submission-pack assembly path.

## CLI

```sh
cargo run --quiet --bin hyperion -- commands --markdown
cargo run --quiet --bin hyperion -- bundle init --out target/hyperion-certification-wizard
cargo run --quiet --bin hyperion -- bundle lint --bundle docs/certification_data_bundle.json --trust-anchors docs/certification_data_bundle_trust_anchors.json
cargo run --quiet --bin hyperion -- artifacts import --root target/hyperion-cert-artifact-import --out target/hyperion-artifact-report
cargo run --quiet --bin hyperion -- release freeze --artifacts target/hyperion-cert-artifact-import --out target/hyperion-submission-pack --allow-incomplete
cargo run --quiet --bin hyperion -- report workspace --out target/hyperion-report-workspace
cargo run --quiet --bin hyperion -- schemas write --out docs/schemas
cargo run --quiet --bin hyperion -- c-header write --out include/hyperion_emv.h
```

Without `--allow-incomplete`, `hyperion release freeze` fails closed until all release-freeze slots are bound to reviewed external artifacts.

## Make Targets

```sh
make verify
make coverage
make bundle
make workspace
make freeze
make schemas
make header
```

## Schemas

Schemas live under `docs/schemas/` for data bundles, integration manifests, report packs, and freeze manifests. They are reference schemas for user tooling and CI validation; the Rust parsers remain the fail-closed source of truth.

## SDK Assets

- `include/hyperion_emv.h` packages the stable C ABI entry points.
- `python/hyperion_tools` provides standard-library helpers for hashing generated submission directories.
- `Dockerfile` and `.devcontainer/devcontainer.json` provide repeatable development environments.
- `starter-kits/` contains minimal integration templates for Rust, C ABI, Python automation, Android SoftPoS, and PC/SC desktop adapters.

## Boundary

These productization tools assemble, validate, hash, lint, and package certification candidates. They do not replace EMVCo, scheme, acquirer, lab, device/L1, PCI/PED, CAPK authority, official vector, trace acceptance, or signed conformance approval.
