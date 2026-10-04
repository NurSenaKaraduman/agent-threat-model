# agent-threat-model: threat modeling for AI agents

Threat modeling for AI agents and LLM applications, for security architects and the engineers who own an agent: describe the system in YAML and get a STRIDE and OWASP Agentic threat model with a ranked threat register, a Mermaid diagram, a control checklist, a residual risk score and SARIF for GitHub code scanning. Deterministic, offline, no model in the loop, so the same input always gives the same report and it runs in CI.

Part of [Masoon](https://github.com/basitalisandhu/masoon) ([docs](https://basitalisandhu.github.io/masoon/)), open-source trust infrastructure for AI agents: who they are, what they may touch, and proof of what they did.

[![CI](https://github.com/basitalisandhu/agent-threat-model/actions/workflows/ci.yml/badge.svg)](https://github.com/basitalisandhu/agent-threat-model/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

## Why

Agent systems fail in predictable ways: an email the agent reads tells it to forward the customer database, a shell tool runs without a sandbox, a payment tool needs no approval, a static API key sits in the prompt. Security reviews keep rediscovering the same twenty-odd threats by hand. This tool encodes them once, as rules over the architecture you declare, and tells you which ones apply to your system, how bad they are, and which control removes the most risk for the least effort.

What it is not: a scanner of code or prompts, and not a judgement about your implementation. It reasons only about what you declare. Treat the output as the starting checklist for a review, and keep the YAML next to the code so the model is diffed with every change.

## When to use this

- **How do I threat-model an LLM agent or an MCP integration before it ships?** Write the YAML once and run `atm analyse` in the pull request.
- **Which OWASP Agentic Top 10 and MITRE ATLAS entries apply to my agent architecture?** Every applicable threat in the report carries its OWASP LLM, OWASP Agentic and ATLAS ids.
- **How do I get agent threat findings into GitHub code scanning?** `--format sarif` plus the GitHub Action uploads them as alerts.
- **Which control reduces the most risk for my agent?** The report ranks missing controls by the number of applicable threats they mitigate.
- **How do I show that a design change (brokered credentials, approval gates) lowered the risk?** `atm diff old.yaml new.yaml` prints the threats removed and the score change.

## 30-second demo

```bash
pipx install git+https://github.com/basitalisandhu/agent-threat-model   # see "Install" below
atm init system.yaml                 # writes the support-bot example
atm analyse system.yaml
```

Output for [`examples/support-bot.yaml`](examples/support-bot.yaml), a retrieval-backed support chatbot that reads inbound email and can send email (excerpt):

```text
Threat model: Customer support assistant

#   Threat                                 STRIDE                  OWASP LLM            Inherent  Residual    Affected
--  -------------------------------------  ----------------------  -------------------  --------  ----------  ---------------------------------------------------------
1   excessive-agency                       Elevation of privilege  LLM06                16 High   16 High     create-ticket, support-bot
2   indirect-prompt-injection              Tampering               LLM01                16 High   16 High     inbound-email, support-bot, web-chat
3   credential-exfiltration-via-tool-args  Information disclosure  LLM02, LLM01         15 High   15 High     create-ticket, lookup-customer, send-email, support-bot
4   data-exfiltration-via-messaging        Information disclosure  LLM02, LLM01         15 High   15 High     crm, inbound-email, lookup-customer, send-email ...
5   denial-of-wallet                       Denial of service       LLM10                12 High   12 High     support-bot
6   destructive-write-actions              Tampering               LLM06, LLM01         12 High   12 High     create-ticket, inbound-email, support-bot, web-chat
...
21  insecure-output-handling               Tampering               LLM05                9 Medium  6.6 Medium  create-ticket, support-bot

21 of the catalogue threats apply to 'Customer support assistant' (0 critical, 14 high, 7 medium, 0 low after mitigations). Residual risk score 99/100 (Critical). The 1 control(s) in place reduce modelled risk by 1% compared with the same system with no controls.

Highest-leverage missing controls:
  - approval-gates: Human approval for high-impact actions (mitigates 9 applicable threat(s))
  - audit-log: Tamper-evident audit log of every tool call (mitigates 9 applicable threat(s))
  - least-privilege-tool-scopes: Least-privilege scopes on every tool (mitigates 8 applicable threat(s))
  - adversarial-testing: Adversarial testing before and after release (mitigates 4 applicable threat(s))
  - brokered-credentials: Short-lived, scoped, brokered credentials (mitigates 4 applicable threat(s))
```

Then write the full report:

```bash
atm analyse system.yaml --format markdown -o threat-model.md   # also: json, sarif, html
```

The same accounts-payable agent with and without Masoon-style controls (brokered credentials, approvals enforced outside the model, audit log, kill switch, budget caps):

```bash
$ atm diff examples/finance-agent.yaml examples/masoon-governed.yaml
Residual risk score: 90 (critical) -> 27 (medium), change -63
Removed threats (10)
  - credential-exfiltration-via-tool-args  15 high  Credential exfiltration through tool call arguments
  - excessive-agency  12.9 high  Excessive agency on write, exec or payment tools
  - missing-audit-trail  12 high  No tamper-evident audit trail of tool calls
  ...
```

Generated reports for every example are committed under [`examples/reports/`](examples/reports/).

## Install

Requires Python 3.11 or newer. PyPI publication is pending, so install from the repository:

```bash
pipx install git+https://github.com/basitalisandhu/agent-threat-model                  # isolated CLI install
uvx --from git+https://github.com/basitalisandhu/agent-threat-model atm --help         # run without installing
pip install git+https://github.com/basitalisandhu/agent-threat-model                   # into the current environment
git clone https://github.com/basitalisandhu/agent-threat-model && cd agent-threat-model && uv sync   # for development
```

Once the package is on PyPI the short forms work too: `pipx install agent-threat-model`, `uvx agent-threat-model --help`, `pip install agent-threat-model`.

Both `atm` and `agent-threat-model` are installed as commands.

## Commands

| Command | What it does |
|---|---|
| `atm analyse system.yaml` | Ranked table in the terminal (rich colours when available, plain text otherwise). `--format markdown\|json\|sarif\|html`, `-o FILE`, `--fail-on high` to break a build. `analyze` works too. |
| `atm validate system.yaml` | Schema and cross-reference check, including control ids. Exit code 2 on error. |
| `atm init [path]` | Write the support-bot example to start from. |
| `atm catalogue [threats\|controls]` | List the bundled catalogue; `--format markdown\|json`. |
| `atm diff old.yaml new.yaml` | Threats added, removed and re-scored between two descriptions; `--fail-on-regression`. |
| `atm schema` | Print the JSON Schema for system files. |

## Input format

A system file has seven top-level keys. Full reference: [docs/input-format.md](docs/input-format.md); JSON Schema: [schema/system.schema.json](schema/system.schema.json).

```yaml
system:
  name: Customer support assistant
  owner: support-platform team
principals:
  - {id: customer, kind: human, trust: low, channels: [web-chat]}
agents:
  - id: support-bot
    model_provider: hosted LLM          # free text
    autonomy: act                       # suggest | act-with-approval | act
    memory: session                     # none | session | persistent
    inputs: [web-chat, knowledge-base]  # channel ids
    tools: [search-kb, send-email]      # tool ids
channels:
  - {id: web-chat, kind: chat, trusted: false, origin: user}
  - {id: knowledge-base, kind: rag, trusted: true, origin: internal}
tools:
  - id: send-email
    kind: messaging                     # read | write | exec | network | payment | messaging
    target: smtp relay
    scope: send email from support@ to any address
    auth: static-key                    # none | static-key | short-lived | brokered
    approval: none                      # none | threshold | always
    sandboxed: false
data_stores:
  - {id: crm, sensitivity: confidential}   # public | internal | confidential | regulated
controls: [output-encoding]              # control ids already in place (see atm catalogue)
```

## Catalogue

30 threats and 29 controls, defined in YAML under [`agent_threat_model/catalogue/`](agent_threat_model/catalogue/) and documented in [docs/catalogue.md](docs/catalogue.md). Each threat carries a STRIDE category, OWASP Top 10 for LLM Applications 2025 ids, OWASP Top 10 for Agentic Applications 2026 ids, MITRE ATLAS technique ids (validated against the ATLAS data distribution), a likelihood and impact score, an `applies_when` rule and the controls that mitigate it.

| STRIDE | Threats (examples) |
|---|---|
| Spoofing | unauthenticated-tool, cross-agent-trust, low-trust-principal-drives-agent |
| Tampering | indirect-prompt-injection, tool-poisoning, memory-poisoning, rag-poisoning, supply-chain-unpinned, insecure-output-handling, destructive-write-actions, malicious-file-input, hallucinated-actions, agent-config-tampering |
| Repudiation | missing-audit-trail |
| Information disclosure | credential-exfiltration-via-tool-args, data-exfiltration-via-messaging, ssrf-via-url-tool, static-long-lived-credentials, sensitive-data-disclosure, system-prompt-leakage, session-cross-contamination |
| Denial of service | no-rate-limits, denial-of-wallet |
| Elevation of privilege | excessive-agency, unsandboxed-exec, over-permissive-scopes, approval-fatigue, hitl-bypass, missing-kill-switch |

Rules are a small DSL over named predicates, evaluated in Python without `eval`:

```yaml
applies_when:
  all:
    - "agent_has_tool_kind(kinds=messaging)"
    - any:
        - untrusted_channel_in_agent_inputs
        - "agent_reaches_sensitive_store(min=confidential)"
```

Scoring: inherent severity is likelihood x impact (1..25); impact rises by one when regulated data is in scope; each control in place reduces the residual in proportion to its type (preventive 1.0, detective 0.6, corrective 0.5), to a floor of 20% of inherent. The residual risk score (0..100) compares the residual total with what the same system would score with no controls at all, so adding a control always moves it down.

Every threat also maps to the OWASP Top 10 for Agentic Applications 2026 (ASI01 to ASI10) where an entry fits; one threat (`system-prompt-leakage`) is left unmapped. The ids and titles come from the OWASP GenAI Security Project's own [crosswalk repository](https://github.com/GenAI-Security-Project/crosswalk) (`CROSSREF.md`). If you have the published PDF, please check the mapping against it and open an issue for anything that differs.

## CI usage

Keep `system.yaml` in the repository and run the model on every change:

```bash
atm validate system.yaml
atm analyse system.yaml --format sarif -o agent-threat-model.sarif --fail-on critical
atm diff main/system.yaml system.yaml --fail-on-regression    # against the previous version
```

The SARIF output is valid SARIF 2.1.0 and uploads to GitHub code scanning, where each applicable threat appears as an alert pointing at the element that triggers it.

### GitHub Action

```yaml
name: threat-model
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  atm:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: basitalisandhu/agent-threat-model@v0.1.0   # pin a release tag
        with:
          system-file: system.yaml
          fail-on: critical          # none | low | medium | high | critical
```

Inputs: `system-file`, `sarif-file`, `markdown-file`, `fail-on`, `upload` (set `false` to skip the code scanning upload), `python-version`, `version` (PyPI version to install; by default the action installs itself from the checked-out tag). Outputs: `sarif-file`, `residual-risk-score`, `rating`. See [action.yml](action.yml).

## Frequently asked questions

**How do I threat-model an AI agent?**
Write down what the system is made of and apply a catalogue of known agent threats to it. With this tool that means a YAML file with seven keys (system, principals, agents, channels, tools, data_stores, controls) that says which agents exist, what they read, which tools they can call with what authority and approval, and which data stores they reach; `atm analyse system.yaml` then evaluates 30 catalogue threats against it with `applies_when` rules, scores each one by likelihood and impact, applies the controls you already have, and prints a ranked threat register with the highest-leverage missing controls. `atm init` writes a complete example to start from, and the YAML lives next to the code so the model is diffed with every change.

**Which OWASP Agentic Top 10 and MITRE ATLAS entries apply to my architecture?**
Every applicable threat in the report carries its STRIDE category, OWASP Top 10 for LLM Applications 2025 ids, OWASP Top 10 for Agentic Applications 2026 ids (ASI01 to ASI10) and MITRE ATLAS technique ids, validated against the ATLAS data distribution. `atm catalogue threats --format markdown` lists the full mapping, and [docs/catalogue.md](docs/catalogue.md) documents each threat, when it applies and which controls mitigate it. The agentic ids come from the OWASP GenAI Security Project's crosswalk; one threat (`system-prompt-leakage`) is deliberately left unmapped.

**Is there a model in the loop, and is the output reproducible?**
No model, no network, no randomness. Rules are a small DSL over named predicates evaluated in Python without `eval`, scoring is arithmetic (inherent severity is likelihood times impact, each control in place reduces the residual in proportion to its type, to a floor of 20% of inherent), and the same input always gives the same report, which is why it runs in CI and why 108 tests can pin the catalogue, rules, reports, diff and CLI. Treat the output as the starting checklist for a human review, not as a judgement about your implementation: it reasons only about what you declare.

**How do I get the findings into GitHub code scanning or fail a build?**
`atm analyse system.yaml --format sarif -o agent-threat-model.sarif --fail-on critical` writes valid SARIF 2.1.0 and exits non-zero at the severity you choose; the GitHub Action `basitalisandhu/agent-threat-model@v0.1.0` runs that and uploads the SARIF so each applicable threat appears as a code scanning alert pointing at the element that triggers it. `atm diff old.yaml new.yaml --fail-on-regression` fails when a change adds threats or raises the residual score, so a pull request that removes an approval gate is caught.

**How do I show that brokered credentials or approval gates lowered the risk?**
Model the system twice, with and without the control, and run `atm diff`. The bundled example compares an accounts-payable agent before and after Masoon-style controls (brokered credentials, approvals enforced outside the model, audit log, kill switch, budget caps): the residual risk score falls from 90 (critical) to 27 (medium) and ten threats are removed, including credential exfiltration through tool arguments, excessive agency and the missing audit trail. The generated reports for every example are committed under [examples/reports/](examples/reports/) so the numbers can be checked without installing anything.

## Roadmap

- Review of the OWASP Agentic Top 10 mapping against the published document, and a mapping for `system-prompt-leakage`.
- Custom catalogue overlays (`--catalogue extra.yaml`) so teams can add their own threats and controls without forking.
- Richer predicates: per-channel trust for principals, tool-to-tool data flow, model-capability flags.
- Import from running systems: generate the YAML from MCP server manifests and Masoon Broker policies.
- Diagram export to SVG and PNG without a browser.
- A `--baseline` mode that scores against a stored report and comments on pull requests.

## Contributing

Issues and pull requests are welcome. Adding a threat or control is a YAML change plus a test; see [CONTRIBUTING.md](CONTRIBUTING.md). Run `make check` (ruff and pytest) before opening a pull request. Security problems: see [SECURITY.md](SECURITY.md).

## Sibling projects

- [masoon](https://github.com/basitalisandhu/masoon): the platform front door, with the [docs site](https://basitalisandhu.github.io/masoon/).
- [Masoon Broker](https://basitalisandhu.github.io/masoon/masoon-broker.html): scoped, short-lived credentials for AI agents with approvals, kill switch and tamper-evident audit.
- [llm-agent-control-plane](https://github.com/basitalisandhu/llm-agent-control-plane): deterministic policy enforcement point for LLM agents.
- [ai-agent-incidents](https://github.com/basitalisandhu/ai-agent-incidents): open, structured dataset of publicly documented AI agent security incidents, mapped to OWASP and MITRE ATLAS ([browse it](https://basitalisandhu.github.io/ai-agent-incidents/)).
- [agentic-semgrep-rules](https://github.com/basitalisandhu/agentic-semgrep-rules): Semgrep rule pack for insecure agent code: unbounded tool permissions, eval of model output, SSRF through tool URLs, prompt interpolation, MCP servers without auth.
- [agent-security-skills](https://github.com/basitalisandhu/agent-security-skills): Claude Code plugin and agentskills-compatible skill pack for agent security reviews: threat modelling, config audits, policy generation, incident lookup.

## Licence

MIT, see [LICENSE](LICENSE). Copyright 2026 Muhammad Basit Ali.
