# Good first issues

Issues the maintainer intends to open under the `good first issue` label, written out so
they can be filed in one sitting. Each is self-contained and has acceptance criteria that
`make check` can verify. Read [CONTRIBUTING.md](../CONTRIBUTING.md) first: `ruff` must
pass, generated files (`schema/system.schema.json`, `docs/catalogue.md`,
`examples/reports/`) must be regenerated when their inputs change, and renderers must
stay deterministic (no timestamps, no random ids).

## 1. Add a CSV reporter for the threat register

**Context.** `atm analyse` writes table, Markdown, JSON, SARIF and HTML. Risk registers
and spreadsheets want one row per applicable threat.

**Acceptance criteria.**

- `atm analyse system.yaml --format csv` writes a header row and one row per applicable
  threat in the same order as the table: `rank, id, title, stride, owasp_llm,
  owasp_agentic, mitre_atlas, inherent_score, inherent_severity, residual_score,
  residual_severity, affected, mitigating_controls_in_place, missing_controls`.
  List-valued columns are joined with `;`.
- Implemented as `agent_threat_model/reporters/csvout.py` using the standard
  `csv` module, registered next to the other reporters, and listed in the `--format`
  help and the README "Commands" table.
- Tests in `tests/test_reports.py`: the row count equals the number of applicable
  threats for `examples/support-bot.yaml`, the header is as above, and the output is
  identical across two runs.

## 2. Let `atm validate` take several files

**Context.** `atm validate` checks one system file. Repositories that keep one file per
agent want `atm validate systems/*.yaml` in CI.

**Acceptance criteria.**

- `atm validate FILE [FILE ...]` validates each file, prints one `ok:` or `error:` line
  per file, and exits 2 if any file fails (0 otherwise). A single file behaves exactly
  as today.
- Tests in `tests/test_cli.py` cover two valid files, one valid and one invalid file,
  and a missing path.
- README "Commands" table and `docs/input-format.md` mention the multi-file form.

## 3. Add a `diagram` subcommand

**Context.** `agent_threat_model/diagram.py` renders the Mermaid system diagram, but it
is only reachable inside the Markdown and HTML reports. People want the `.mmd` on its
own for wikis and design documents.

**Acceptance criteria.**

- `atm diagram system.yaml [-o FILE.mmd]` prints (or writes) the same Mermaid text the
  Markdown report embeds, with untrusted channels still drawn in red.
- Test: the output for `examples/support-bot.yaml` equals the diagram block extracted
  from `examples/reports/support-bot.md`.
- README "Commands" table gains a row.

## 4. Add a fifth worked example: a research agent

**Context.** The four examples cover a support bot, a coding agent, a finance agent and
a Masoon-governed variant. A browsing agent (web search tool, file write tool, persistent
memory, untrusted web pages as an input channel) exercises threats the others do not.

**Acceptance criteria.**

- `examples/research-agent.yaml` validates, has a `system.description`, declares at
  least one `network` tool, one `write` tool, `memory: persistent` and an untrusted
  channel with `origin: web` (or the nearest value `docs/input-format.md` allows).
- `tests/test_examples.py` asserts that `ssrf-via-url-tool`, `memory-poisoning` and
  `indirect-prompt-injection` apply to it.
- `make reports` regenerates `examples/reports/research-agent.{md,json,sarif,html}`
  and the Makefile `reports` target lists the new name.
- README's "30-second demo" section mentions it in the list of examples.

## 5. Add an issue form for proposing a threat or control

**Context.** CONTRIBUTING describes the YAML fields of a catalogue entry, but there is
no `.github/ISSUE_TEMPLATE/`, so proposals arrive as free text.

**Acceptance criteria.**

- `.github/ISSUE_TEMPLATE/new-threat.yml` with inputs for id (kebab-case), title,
  STRIDE category (dropdown), OWASP LLM ids, OWASP Agentic ids, MITRE ATLAS ids,
  likelihood and impact (dropdowns 1 to 5), the `applies_when` condition in words, the
  controls that mitigate it, and a public reference URL (required).
- `.github/ISSUE_TEMPLATE/new-control.yml` with id, title, type (preventive, detective,
  corrective), effort (low, medium, high), description and a reference URL.
- Both parse as YAML and render on GitHub's "New issue" page; CONTRIBUTING links them.

## 6. Document the JSON report format

**Context.** `atm analyse --format json` is the input for the GitHub Action's outputs and
for anyone scripting on top of the tool, but its shape is only visible by reading
`examples/reports/support-bot.json`.

**Acceptance criteria.**

- `docs/report-format.md` describes every top-level key and every field of a threat
  entry and of the `summary` object, with the type and one example value each, taken
  from `examples/reports/support-bot.json`.
- A test loads that example report and asserts that the set of keys documented
  (parsed from the Markdown table) equals the set of keys in the file, so the document
  cannot drift silently.
- README links the document from the "Commands" table row for `atm analyse`.
