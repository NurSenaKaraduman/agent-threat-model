# Input format

A system description is one YAML file with seven top-level keys. Unknown keys are errors, ids must match `^[a-z0-9][a-z0-9._-]*$` and be unique across all element types, and every reference must resolve. `atm validate` checks all of this; the JSON Schema lives at [`schema/system.schema.json`](../schema/system.schema.json) and `atm schema` prints it.

```yaml
system: {...}
principals: [...]
agents: [...]
channels: [...]
tools: [...]
data_stores: [...]
controls: [...]
```

## system

| Field | Type | Notes |
|---|---|---|
| `name` | string, required | Shown in report titles. |
| `description` | string | One paragraph on what the system does. |
| `owner` | string | Team or person accountable. |

## principals

Who talks to the system. Optional, but linking principals to channels enables threats about low-trust principals.

| Field | Type | Notes |
|---|---|---|
| `id` | id, required | |
| `kind` | `human` or `service`, required | |
| `trust` | `low`, `medium` or `high`, required | How much the operator trusts instructions from this principal. Anonymous users and external partners are `low`. |
| `channels` | list of channel ids | Channels this principal speaks through. |
| `description` | string | |

## agents

At least one is required.

| Field | Type | Notes |
|---|---|---|
| `id` | id, required | |
| `model_provider` | string | Free text, for example `hosted LLM` or `self-hosted model`. Not interpreted. |
| `autonomy` | `suggest`, `act-with-approval` or `act`, required | `suggest` never calls side-effecting tools on its own. `act-with-approval` asks a human. `act` runs on its own. |
| `memory` | `none`, `session` or `persistent` | Default `none`. |
| `inputs` | list of channel ids | What the agent reads. |
| `tools` | list of tool ids | What the agent may call. |
| `delegates_to` | list of agent ids | Other agents this one sends tasks to. |
| `model_pinned` | bool | `true` when the model version is pinned and change-controlled. Default `false`. |
| `description` | string | |

## channels

Where content enters the agent's context.

| Field | Type | Notes |
|---|---|---|
| `id` | id, required | |
| `kind` | `chat`, `email`, `web`, `document`, `rag`, `api`, `file` or `cli`, required | |
| `trusted` | bool, required | `false` when an attacker could influence the content. Public chat, inbound email, web pages, shared documents and tickets are untrusted. |
| `origin` | `user`, `third-party` or `internal`, required | |
| `description` | string | |

## tools

What the agent can do. Only tools referenced by an agent are considered reachable; an unreferenced tool is ignored by the rules.

| Field | Type | Notes |
|---|---|---|
| `id` | id, required | |
| `kind` | `read`, `write`, `exec`, `network`, `payment` or `messaging`, required | |
| `target` | string | What the tool touches. When it equals a data store id, the rules treat the tool as reaching that store. |
| `scope` | string | Free text. An empty scope, a `*` or words such as `all`, `admin`, `full`, `root`, `owner`, `any` or `unrestricted` count as broad. |
| `auth` | `none`, `static-key`, `short-lived` or `brokered`, required | |
| `approval` | `none`, `threshold` or `always` | Default `none`. |
| `sandboxed` | bool | Default `false`. Matters for `exec` tools. |
| `provider` | `first-party` or `third-party` | Default `first-party`. Third-party tools bring their own descriptions, which the model reads. |
| `pinned` | bool | `true` when the tool version or description hash is pinned. Default `false`. |
| `data_stores` | list of data store ids | Stores the tool can reach, in addition to `target`. |
| `description` | string | |

## data_stores

| Field | Type | Notes |
|---|---|---|
| `id` | id, required | |
| `sensitivity` | `public`, `internal`, `confidential` or `regulated`, required | A `regulated` store in scope raises a threat's impact by one. |
| `description` | string | |

## controls

A list of control ids from the catalogue that are already in place (`atm catalogue controls` lists them). Unknown ids fail validation. Controls affect the model in two ways: a threat that lists the control as a mitigation gets a lower residual score, and a few threats (for example `missing-audit-trail`) do not apply at all when their control is present.

## Rule DSL

Threats in the catalogue carry an `applies_when` rule. You only need this if you edit the catalogue, but it explains why a threat applies to your system; every finding shows its rule.

A rule is a predicate call written as a string, or a mapping with one of `all`, `any` or `not`:

```yaml
applies_when: untrusted_channel_in_agent_inputs

applies_when: "agent_has_tool_kind(kinds=exec|write)"

applies_when:
  all:
    - "control_missing(control=budget-caps)"
    - any:
        - "agent_has_tool_kind(kinds=payment|network)"
        - "agent_autonomy_in(autonomy=act)"
```

Arguments are `key=value`; several values are separated with `|`. Rules are parsed into a tree and evaluated by calling named Python functions from a registry, so a catalogue file can never execute code. The predicates and their meaning are listed at the end of [catalogue.md](catalogue.md).

## Scoring

- Inherent severity per threat = likelihood x impact, each 1..5, from the catalogue.
- Impact is raised by one (to at most 5) when a `regulated` data store is among the affected elements.
- Coverage = sum of the weights of mitigating controls in place divided by the sum of weights of all listed mitigations, with weights preventive 1.0, detective 0.6, corrective 0.5.
- Residual severity = inherent x (1 - 0.8 x coverage). A fully mitigated threat keeps 20% of its inherent score.
- Bands: critical 20..25, high 12..19.9, medium 6..11.9, low below 6.
- Residual risk score = 100 x residual total / inherent total of the same system with no controls at all. Rating: critical 75+, high 50+, medium 25+, otherwise low.

## A complete example

See [`examples/`](../examples/) for four systems: a support chatbot, a coding agent, an accounts payable agent and the same agent governed by Masoon controls. `atm init` writes the support-bot example to start from.
