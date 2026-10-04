# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- Renamed the umbrella project from Hisar to Masoon; links, names and identifiers updated.

## [0.1.0] - 2026-10-03

### Added

- `atm analyse` with table, Markdown, JSON, SARIF 2.1.0 and HTML output, plus `--fail-on` thresholds.
- `atm validate`, `atm init`, `atm catalogue`, `atm diff` and `atm schema` commands.
- Pydantic v2 input schema with JSON Schema export at `schema/system.schema.json`.
- Catalogue of 30 threats and 29 controls with STRIDE, OWASP Top 10 for LLM Applications 2025, OWASP Top 10 for Agentic Applications 2026 (ids and titles from the OWASP GenAI Security Project crosswalk repository; please check against the published PDF) and MITRE ATLAS mappings.
- Rule DSL (`all`, `any`, `not` over named predicates) evaluated without `eval`.
- Deterministic scoring with inherent and residual severity and a 0..100 residual risk score.
- Mermaid system diagram with untrusted channels drawn in red.
- Four worked examples with committed reports, a composite GitHub Action, CI and release workflows.

[Unreleased]: https://github.com/basitalisandhu/agent-threat-model/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/basitalisandhu/agent-threat-model/releases/tag/v0.1.0
