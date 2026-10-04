# Contributing

Thanks for considering a contribution. The project is small on purpose: a schema, a catalogue, a rule engine and a few renderers. Most useful contributions are catalogue entries, better predicates and real-world example systems.

## Set up

Requires Python 3.11 or newer. With [uv](https://docs.astral.sh/uv/):

```bash
git clone https://github.com/basitalisandhu/agent-threat-model
cd agent-threat-model
uv sync
uv run pytest -q
```

Without uv:

```bash
python3 -m venv .venv && . .venv/bin/activate
python3 -m pip install -e ".[dev]"
python3 -m pytest -q
```

## Before you open a pull request

```bash
make check          # ruff check, ruff format --check, pytest
make docs           # regenerate schema/system.schema.json and docs/catalogue.md
make reports        # regenerate examples/reports/ after catalogue or engine changes
```

CI runs the same commands on Python 3.11 and 3.12 and fails if the generated files or the committed example reports are out of date.

## Adding a threat

1. Add an entry to `agent_threat_model/catalogue/threats.yaml`. Required fields: `id` (kebab-case), `title`, `description`, `stride`, `owasp_llm`, `mitre_atlas` (ids must exist in `agent_threat_model/catalogue/references.py`, which mirrors the ATLAS data distribution), `applies_when`, `likelihood`, `impact`, `mitigations`.
2. Set `owasp_agentic` to the ASI ids (ASI01..ASI10) that fit, from the allowlist in `references.py` (sourced from the OWASP GenAI Security Project crosswalk repository); leave it empty only when no entry fits.
3. Every mitigation must be a control id in `controls.yaml`.
4. If no existing predicate expresses the condition, add one to `agent_threat_model/predicates.py` with the `@predicate` decorator, a one-line docstring (it is rendered into `docs/catalogue.md`) and a test in `tests/test_predicates.py` with a positive and a negative case.
5. Run `make docs reports check`.

## Adding a control

Add an entry to `controls.yaml` with `id`, `title`, `description`, `type` (preventive, detective, corrective), `effort` (low, medium, high) and at least one real `references` URL (OWASP, NIST, MITRE ATLAS, a Masoon repository or a primary source). A control must be cited by at least one threat; the test suite enforces this.

## Style

- `ruff` formats and lints; line length 100.
- No model names or vendor identifiers in the repository. `model_provider` is free text in user files.
- Plain language in descriptions: say what goes wrong and who can cause it.
- Deterministic output. Renderers must not emit timestamps or random ids.

## Reporting security issues

See [SECURITY.md](SECURITY.md).
