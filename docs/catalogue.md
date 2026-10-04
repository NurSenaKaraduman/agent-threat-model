# Catalogue reference

Generated from `agent_threat_model/catalogue/threats.yaml` and `controls.yaml` by `scripts/gen_catalogue_doc.py`. Do not edit by hand.

30 threats, 29 controls, 21 predicates.

LLM ids refer to the OWASP Top 10 for LLM Applications 2025. ASI ids refer to the OWASP Top 10 for Agentic Applications 2026 as listed in the OWASP GenAI Security Project crosswalk repository (https://github.com/GenAI-Security-Project/crosswalk, CROSSREF.md); please check the mapping against the published PDF and open an issue if an id or title differs. MITRE ATLAS ids are validated against the ATLAS data distribution.

## Threats

| Id | Title | STRIDE | OWASP LLM | OWASP Agentic | MITRE ATLAS | L x I | Applies when |
|---|---|---|---|---|---|---|---|
| [`indirect-prompt-injection`](#indirect-prompt-injection) | Indirect prompt injection via untrusted channel | Tampering | LLM01 | ASI01 | [AML.T0051.001](https://atlas.mitre.org/techniques/AML.T0051.001) | 4 x 4 | `untrusted_channel_in_agent_inputs` |
| [`direct-prompt-injection`](#direct-prompt-injection) | Direct prompt injection and jailbreak by a user | Tampering | LLM01 | ASI01 | [AML.T0051.000](https://atlas.mitre.org/techniques/AML.T0051.000), [AML.T0054](https://atlas.mitre.org/techniques/AML.T0054) | 4 x 3 | `all(agent_has_input_of_origin(origin=user), agent_has_any_tool)` |
| [`tool-poisoning`](#tool-poisoning) | Tool poisoning via third-party tool descriptions | Tampering | LLM01, LLM03 | ASI04, ASI01 | [AML.T0110](https://atlas.mitre.org/techniques/AML.T0110), [AML.T0104](https://atlas.mitre.org/techniques/AML.T0104), [AML.T0099](https://atlas.mitre.org/techniques/AML.T0099) | 3 x 4 | `third_party_tool` |
| [`credential-exfiltration-via-tool-args`](#credential-exfiltration-via-tool-args) | Credential exfiltration through tool call arguments | Information disclosure | LLM02, LLM01 | ASI02, ASI03 | [AML.T0098](https://atlas.mitre.org/techniques/AML.T0098), [AML.T0086](https://atlas.mitre.org/techniques/AML.T0086), [AML.T0083](https://atlas.mitre.org/techniques/AML.T0083) | 3 x 5 | `all(tool_auth_in(auth=static-key), agent_has_tool_kind(kinds=network|messaging|write))` |
| [`excessive-agency`](#excessive-agency) | Excessive agency on write, exec or payment tools | Elevation of privilege | LLM06 | ASI02, ASI03 | [AML.T0053](https://atlas.mitre.org/techniques/AML.T0053) | 4 x 4 | `tool_kind_without_approval(kinds=write|exec|payment)` |
| [`ssrf-via-url-tool`](#ssrf-via-url-tool) | Server-side request forgery through URL-accepting tools | Information disclosure | LLM06, LLM05 | ASI02 | [AML.T0053](https://atlas.mitre.org/techniques/AML.T0053) | 3 x 4 | `agent_has_tool_kind(kinds=network)` |
| [`data-exfiltration-via-messaging`](#data-exfiltration-via-messaging) | Data exfiltration through messaging tools | Information disclosure | LLM02, LLM01 | ASI02 | [AML.T0086](https://atlas.mitre.org/techniques/AML.T0086), [AML.T0025](https://atlas.mitre.org/techniques/AML.T0025) | 3 x 5 | `all(agent_has_tool_kind(kinds=messaging), any(untrusted_channel_in_agent_inputs, agent_reaches_sensitive_store(min=confidential)))` |
| [`memory-poisoning`](#memory-poisoning) | Persistent memory poisoning | Tampering | LLM01, LLM04 | ASI06 | [AML.T0080.000](https://atlas.mitre.org/techniques/AML.T0080.000) | 3 x 4 | `agent_memory_is(memory=persistent)` |
| [`unsandboxed-exec`](#unsandboxed-exec) | Unsandboxed code or shell execution | Elevation of privilege | LLM06, LLM05 | ASI05 | [AML.T0050](https://atlas.mitre.org/techniques/AML.T0050), [AML.T0105](https://atlas.mitre.org/techniques/AML.T0105), [AML.T0072](https://atlas.mitre.org/techniques/AML.T0072) | 4 x 5 | `tool_kind_not_sandboxed(kinds=exec)` |
| [`static-long-lived-credentials`](#static-long-lived-credentials) | Static long-lived credentials held by the agent | Information disclosure | LLM02 | ASI03 | [AML.T0055](https://atlas.mitre.org/techniques/AML.T0055), [AML.T0083](https://atlas.mitre.org/techniques/AML.T0083) | 3 x 4 | `tool_auth_in(auth=static-key)` |
| [`unauthenticated-tool`](#unauthenticated-tool) | Side-effecting tool with no authentication | Spoofing | LLM06 | ASI03 | [AML.T0053](https://atlas.mitre.org/techniques/AML.T0053) | 3 x 4 | `tool_auth_in(auth=none, kinds=write|exec|payment|messaging|network)` |
| [`missing-audit-trail`](#missing-audit-trail) | No tamper-evident audit trail of tool calls | Repudiation | - | ASI10 | - | 4 x 3 | `all(control_missing(control=audit-log), agent_has_any_tool)` |
| [`missing-kill-switch`](#missing-kill-switch) | No kill switch or credential revocation | Elevation of privilege | LLM06 | ASI10, ASI08 | - | 3 x 4 | `all(control_missing(control=kill-switch), agent_autonomy_in(autonomy=act|act-with-approval))` |
| [`rag-poisoning`](#rag-poisoning) | Retrieval corpus poisoning | Tampering | LLM08, LLM04, LLM01 | ASI06 | [AML.T0070](https://atlas.mitre.org/techniques/AML.T0070), [AML.T0071](https://atlas.mitre.org/techniques/AML.T0071), [AML.T0066](https://atlas.mitre.org/techniques/AML.T0066) | 3 x 4 | `agent_has_channel_kind(kinds=rag)` |
| [`over-permissive-scopes`](#over-permissive-scopes) | Over-permissive tool scopes | Elevation of privilege | LLM06 | ASI03 | [AML.T0053](https://atlas.mitre.org/techniques/AML.T0053) | 3 x 4 | `tool_scope_broad` |
| [`approval-fatigue`](#approval-fatigue) | Approval fatigue leads to rubber-stamping | Elevation of privilege | LLM06 | ASI09 | - | 3 x 3 | `approval_always_tool_count_at_least(min=3)` |
| [`insecure-output-handling`](#insecure-output-handling) | Model output consumed without validation | Tampering | LLM05 | ASI05 | [AML.T0077](https://atlas.mitre.org/techniques/AML.T0077), [AML.T0067](https://atlas.mitre.org/techniques/AML.T0067) | 3 x 3 | `any(agent_has_tool_kind(kinds=exec|write), agent_has_channel_kind(kinds=web))` |
| [`supply-chain-unpinned`](#supply-chain-unpinned) | Unpinned model or tool versions | Tampering | LLM03 | ASI04 | [AML.T0010](https://atlas.mitre.org/techniques/AML.T0010), [AML.T0010.005](https://atlas.mitre.org/techniques/AML.T0010.005), [AML.T0109](https://atlas.mitre.org/techniques/AML.T0109) | 2 x 4 | `any(agent_model_unpinned, tool_unpinned)` |
| [`no-rate-limits`](#no-rate-limits) | No rate limits on tool calls | Denial of service | LLM10 | ASI08 | [AML.T0029](https://atlas.mitre.org/techniques/AML.T0029), [AML.T0034](https://atlas.mitre.org/techniques/AML.T0034) | 3 x 3 | `all(control_missing(control=rate-limiting), agent_has_any_tool)` |
| [`cross-agent-trust`](#cross-agent-trust) | Implicit trust between agents | Spoofing | LLM01, LLM06 | ASI07, ASI08 | [AML.T0051.001](https://atlas.mitre.org/techniques/AML.T0051.001), [AML.T0073](https://atlas.mitre.org/techniques/AML.T0073) | 3 x 4 | `agent_delegates_to_agent` |
| [`hitl-bypass`](#hitl-bypass) | Human-in-the-loop enforced only in the prompt | Elevation of privilege | LLM06, LLM01 | ASI09, ASI01 | [AML.T0053](https://atlas.mitre.org/techniques/AML.T0053) | 3 x 5 | `all(agent_autonomy_in(autonomy=act-with-approval), control_missing(control=runtime-policy-enforcement))` |
| [`denial-of-wallet`](#denial-of-wallet) | Denial of wallet | Denial of service | LLM10 | ASI08 | [AML.T0034.002](https://atlas.mitre.org/techniques/AML.T0034.002), [AML.T0034](https://atlas.mitre.org/techniques/AML.T0034) | 3 x 4 | `all(control_missing(control=budget-caps), any(agent_has_tool_kind(kinds=payment|network), agent_autonomy_in(autonomy=act)))` |
| [`sensitive-data-disclosure`](#sensitive-data-disclosure) | Sensitive data reachable by the model | Information disclosure | LLM02 | ASI03, ASI02 | [AML.T0057](https://atlas.mitre.org/techniques/AML.T0057), [AML.T0085.000](https://atlas.mitre.org/techniques/AML.T0085.000), [AML.T0036](https://atlas.mitre.org/techniques/AML.T0036) | 3 x 4 | `agent_reaches_sensitive_store(min=confidential)` |
| [`system-prompt-leakage`](#system-prompt-leakage) | System prompt and configuration leakage | Information disclosure | LLM07 | - | [AML.T0056](https://atlas.mitre.org/techniques/AML.T0056), [AML.T0069.002](https://atlas.mitre.org/techniques/AML.T0069.002), [AML.T0084](https://atlas.mitre.org/techniques/AML.T0084), [AML.T0084.001](https://atlas.mitre.org/techniques/AML.T0084.001) | 4 x 2 | `agent_has_input_of_origin(origin=user|third-party)` |
| [`destructive-write-actions`](#destructive-write-actions) | Destructive actions through write tools | Tampering | LLM06, LLM01 | ASI02 | [AML.T0101](https://atlas.mitre.org/techniques/AML.T0101) | 3 x 4 | `all(agent_has_tool_kind(kinds=write), untrusted_channel_in_agent_inputs)` |
| [`low-trust-principal-drives-agent`](#low-trust-principal-drives-agent) | Low-trust principal drives an autonomous agent | Spoofing | LLM06 | ASI01, ASI03 | [AML.T0053](https://atlas.mitre.org/techniques/AML.T0053) | 3 x 4 | `all(low_trust_principal_feeds_agent, agent_autonomy_in(autonomy=act))` |
| [`session-cross-contamination`](#session-cross-contamination) | Memory leaks between users or sessions | Information disclosure | LLM02 | ASI06 | [AML.T0057](https://atlas.mitre.org/techniques/AML.T0057), [AML.T0092](https://atlas.mitre.org/techniques/AML.T0092) | 2 x 4 | `all(agent_memory_is(memory=session|persistent), agent_has_input_of_origin(origin=user))` |
| [`malicious-file-input`](#malicious-file-input) | Malicious files and documents as input | Tampering | LLM01 | ASI01 | [AML.T0051.001](https://atlas.mitre.org/techniques/AML.T0051.001), [AML.T0011.000](https://atlas.mitre.org/techniques/AML.T0011.000) | 3 x 3 | `agent_has_channel_kind(kinds=file|document, untrusted=true)` |
| [`hallucinated-actions`](#hallucinated-actions) | Acting on hallucinated facts or identifiers | Tampering | LLM09, LLM06 | ASI02, ASI04 | [AML.T0060](https://atlas.mitre.org/techniques/AML.T0060), [AML.T0053](https://atlas.mitre.org/techniques/AML.T0053) | 3 x 3 | `all(agent_autonomy_in(autonomy=act|act-with-approval), agent_has_tool_kind(kinds=exec|write|payment))` |
| [`agent-config-tampering`](#agent-config-tampering) | Agent configuration tampering | Tampering | LLM03, LLM06 | ASI10, ASI04 | [AML.T0081](https://atlas.mitre.org/techniques/AML.T0081) | 2 x 4 | `all(agent_has_tool_kind(kinds=write|exec), control_missing(control=runtime-policy-enforcement))` |

### indirect-prompt-injection

**Indirect prompt injection via untrusted channel**

Content the agent reads from an untrusted channel (email, web pages, documents, retrieved passages, API responses) carries instructions that the model follows as if they came from the operator. Every tool the agent can reach becomes available to whoever wrote that content.

- STRIDE: Tampering
- OWASP LLM Top 10 (2025): LLM01 Prompt Injection
- OWASP Agentic Top 10 (2026): ASI01 Agent Goal Hijack
- MITRE ATLAS: [AML.T0051.001](https://atlas.mitre.org/techniques/AML.T0051.001)
- Inherent severity: likelihood 4 x impact 4 = 16
- Applies when: `untrusted_channel_in_agent_inputs`
- Mitigations: [`input-provenance-tagging`](#input-provenance-tagging), [`untrusted-content-isolation`](#untrusted-content-isolation), [`prompt-injection-filtering`](#prompt-injection-filtering), [`least-privilege-tool-scopes`](#least-privilege-tool-scopes), [`approval-gates`](#approval-gates)
- Reference: <https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/main/2_0_vulns/LLM01_PromptInjection.md>

### direct-prompt-injection

**Direct prompt injection and jailbreak by a user**

A user types instructions that override the system prompt or safety guidance, then uses the agent's tools for purposes the operator did not intend. Any agent that accepts user input and has tools is exposed.

- STRIDE: Tampering
- OWASP LLM Top 10 (2025): LLM01 Prompt Injection
- OWASP Agentic Top 10 (2026): ASI01 Agent Goal Hijack
- MITRE ATLAS: [AML.T0051.000](https://atlas.mitre.org/techniques/AML.T0051.000), [AML.T0054](https://atlas.mitre.org/techniques/AML.T0054)
- Inherent severity: likelihood 4 x impact 3 = 12
- Applies when: `all(agent_has_input_of_origin(origin=user), agent_has_any_tool)`
- Mitigations: [`least-privilege-tool-scopes`](#least-privilege-tool-scopes), [`runtime-policy-enforcement`](#runtime-policy-enforcement), [`approval-gates`](#approval-gates), [`prompt-injection-filtering`](#prompt-injection-filtering), [`adversarial-testing`](#adversarial-testing)

### tool-poisoning

**Tool poisoning via third-party tool descriptions**

A third-party tool or tool server ships descriptions, schemas or results that contain hidden instructions. The model reads them as trusted configuration and can be steered to leak data or call other tools.

- STRIDE: Tampering
- OWASP LLM Top 10 (2025): LLM01 Prompt Injection, LLM03 Supply Chain
- OWASP Agentic Top 10 (2026): ASI04 Agentic Supply Chain Vulnerabilities, ASI01 Agent Goal Hijack
- MITRE ATLAS: [AML.T0110](https://atlas.mitre.org/techniques/AML.T0110), [AML.T0104](https://atlas.mitre.org/techniques/AML.T0104), [AML.T0099](https://atlas.mitre.org/techniques/AML.T0099)
- Inherent severity: likelihood 3 x impact 4 = 12
- Applies when: `third_party_tool`
- Mitigations: [`tool-integrity-pinning`](#tool-integrity-pinning), [`input-provenance-tagging`](#input-provenance-tagging), [`least-privilege-tool-scopes`](#least-privilege-tool-scopes), [`approval-gates`](#approval-gates)
- Reference: <https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices>

### credential-exfiltration-via-tool-args

**Credential exfiltration through tool call arguments**

A tool holds a static key that is visible to the model (in configuration, descriptions or memory) and another tool can send data outward. An injected instruction asks the model to place the secret into a URL, message body or file that leaves the system.

- STRIDE: Information disclosure
- OWASP LLM Top 10 (2025): LLM02 Sensitive Information Disclosure, LLM01 Prompt Injection
- OWASP Agentic Top 10 (2026): ASI02 Tool Misuse and Exploitation, ASI03 Identity and Privilege Abuse
- MITRE ATLAS: [AML.T0098](https://atlas.mitre.org/techniques/AML.T0098), [AML.T0086](https://atlas.mitre.org/techniques/AML.T0086), [AML.T0083](https://atlas.mitre.org/techniques/AML.T0083)
- Inherent severity: likelihood 3 x impact 5 = 15
- Applies when: `all(tool_auth_in(auth=static-key), agent_has_tool_kind(kinds=network|messaging|write))`
- Mitigations: [`secrets-out-of-context`](#secrets-out-of-context), [`brokered-credentials`](#brokered-credentials), [`egress-allowlist`](#egress-allowlist), [`argument-validation`](#argument-validation), [`audit-log`](#audit-log)

### excessive-agency

**Excessive agency on write, exec or payment tools**

An agent that may act on its own can call a tool with side effects without any approval step. One wrong inference, one injected instruction or one hallucinated argument becomes a real-world action.

- STRIDE: Elevation of privilege
- OWASP LLM Top 10 (2025): LLM06 Excessive Agency
- OWASP Agentic Top 10 (2026): ASI02 Tool Misuse and Exploitation, ASI03 Identity and Privilege Abuse
- MITRE ATLAS: [AML.T0053](https://atlas.mitre.org/techniques/AML.T0053)
- Inherent severity: likelihood 4 x impact 4 = 16
- Applies when: `tool_kind_without_approval(kinds=write|exec|payment)`
- Mitigations: [`approval-gates`](#approval-gates), [`runtime-policy-enforcement`](#runtime-policy-enforcement), [`least-privilege-tool-scopes`](#least-privilege-tool-scopes), [`audit-log`](#audit-log), [`kill-switch`](#kill-switch)
- Reference: <https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/main/2_0_vulns/LLM06_ExcessiveAgency.md>

### ssrf-via-url-tool

**Server-side request forgery through URL-accepting tools**

A tool fetches URLs chosen by the model. Attacker-influenced input makes it request internal services, cloud metadata endpoints or private address ranges, and the response flows back into the context.

- STRIDE: Information disclosure
- OWASP LLM Top 10 (2025): LLM06 Excessive Agency, LLM05 Improper Output Handling
- OWASP Agentic Top 10 (2026): ASI02 Tool Misuse and Exploitation
- MITRE ATLAS: [AML.T0053](https://atlas.mitre.org/techniques/AML.T0053)
- Inherent severity: likelihood 3 x impact 4 = 12
- Applies when: `agent_has_tool_kind(kinds=network)`
- Mitigations: [`egress-allowlist`](#egress-allowlist), [`argument-validation`](#argument-validation), [`sandboxed-execution`](#sandboxed-execution), [`audit-log`](#audit-log)
- Reference: <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>

### data-exfiltration-via-messaging

**Data exfiltration through messaging tools**

The agent can send email or chat messages and also reads untrusted content or sensitive data. An injected instruction forwards that data to an attacker-chosen recipient in a message that looks routine.

- STRIDE: Information disclosure
- OWASP LLM Top 10 (2025): LLM02 Sensitive Information Disclosure, LLM01 Prompt Injection
- OWASP Agentic Top 10 (2026): ASI02 Tool Misuse and Exploitation
- MITRE ATLAS: [AML.T0086](https://atlas.mitre.org/techniques/AML.T0086), [AML.T0025](https://atlas.mitre.org/techniques/AML.T0025)
- Inherent severity: likelihood 3 x impact 5 = 15
- Applies when: `all(agent_has_tool_kind(kinds=messaging), any(untrusted_channel_in_agent_inputs, agent_reaches_sensitive_store(min=confidential)))`
- Mitigations: [`egress-allowlist`](#egress-allowlist), [`dlp-outbound`](#dlp-outbound), [`approval-gates`](#approval-gates), [`input-provenance-tagging`](#input-provenance-tagging), [`audit-log`](#audit-log)

### memory-poisoning

**Persistent memory poisoning**

The agent writes what it learns into long-term memory. Content from one interaction (possibly injected) is stored and later retrieved as trusted context, so a single poisoned message steers every future session.

- STRIDE: Tampering
- OWASP LLM Top 10 (2025): LLM01 Prompt Injection, LLM04 Data and Model Poisoning
- OWASP Agentic Top 10 (2026): ASI06 Memory and Context Poisoning
- MITRE ATLAS: [AML.T0080.000](https://atlas.mitre.org/techniques/AML.T0080.000)
- Inherent severity: likelihood 3 x impact 4 = 12
- Applies when: `agent_memory_is(memory=persistent)`
- Mitigations: [`memory-write-validation`](#memory-write-validation), [`session-isolation`](#session-isolation), [`input-provenance-tagging`](#input-provenance-tagging), [`audit-log`](#audit-log)

### unsandboxed-exec

**Unsandboxed code or shell execution**

An exec tool runs model-chosen commands on a host that holds credentials, source code or network access. Any injection or mistake becomes arbitrary code execution with the host's privileges.

- STRIDE: Elevation of privilege
- OWASP LLM Top 10 (2025): LLM06 Excessive Agency, LLM05 Improper Output Handling
- OWASP Agentic Top 10 (2026): ASI05 Unexpected Code Execution
- MITRE ATLAS: [AML.T0050](https://atlas.mitre.org/techniques/AML.T0050), [AML.T0105](https://atlas.mitre.org/techniques/AML.T0105), [AML.T0072](https://atlas.mitre.org/techniques/AML.T0072)
- Inherent severity: likelihood 4 x impact 5 = 20
- Applies when: `tool_kind_not_sandboxed(kinds=exec)`
- Mitigations: [`sandboxed-execution`](#sandboxed-execution), [`approval-gates`](#approval-gates), [`egress-allowlist`](#egress-allowlist), [`kill-switch`](#kill-switch), [`audit-log`](#audit-log)

### static-long-lived-credentials

**Static long-lived credentials held by the agent**

Tools authenticate with static keys that do not expire. If a key leaks through logs, prompts or an injected exfiltration it remains valid until someone notices, and it cannot be scoped to a single task.

- STRIDE: Information disclosure
- OWASP LLM Top 10 (2025): LLM02 Sensitive Information Disclosure
- OWASP Agentic Top 10 (2026): ASI03 Identity and Privilege Abuse
- MITRE ATLAS: [AML.T0055](https://atlas.mitre.org/techniques/AML.T0055), [AML.T0083](https://atlas.mitre.org/techniques/AML.T0083)
- Inherent severity: likelihood 3 x impact 4 = 12
- Applies when: `tool_auth_in(auth=static-key)`
- Mitigations: [`brokered-credentials`](#brokered-credentials), [`secrets-out-of-context`](#secrets-out-of-context), [`audit-log`](#audit-log), [`kill-switch`](#kill-switch)

### unauthenticated-tool

**Side-effecting tool with no authentication**

A tool that writes, executes, pays, sends or fetches requires no authentication at all. Calls cannot be attributed to an agent or principal, and anything that can reach the endpoint can use it.

- STRIDE: Spoofing
- OWASP LLM Top 10 (2025): LLM06 Excessive Agency
- OWASP Agentic Top 10 (2026): ASI03 Identity and Privilege Abuse
- MITRE ATLAS: [AML.T0053](https://atlas.mitre.org/techniques/AML.T0053)
- Inherent severity: likelihood 3 x impact 4 = 12
- Applies when: `tool_auth_in(auth=none, kinds=write|exec|payment|messaging|network)`
- Mitigations: [`agent-identity`](#agent-identity), [`brokered-credentials`](#brokered-credentials), [`audit-log`](#audit-log)

### missing-audit-trail

**No tamper-evident audit trail of tool calls**

Tool calls are not recorded in a store the agent cannot modify. After an incident nobody can say which input triggered which action, and the agent's actions can be repudiated or quietly altered.

- STRIDE: Repudiation
- OWASP LLM Top 10 (2025): -
- OWASP Agentic Top 10 (2026): ASI10 Rogue Agents
- MITRE ATLAS: -
- Inherent severity: likelihood 4 x impact 3 = 12
- Applies when: `all(control_missing(control=audit-log), agent_has_any_tool)`
- Mitigations: [`audit-log`](#audit-log), [`behavioural-monitoring`](#behavioural-monitoring), [`incident-response-playbook`](#incident-response-playbook)
- Reference: <https://atlas.mitre.org/mitigations/AML.M0024>

### missing-kill-switch

**No kill switch or credential revocation**

An agent that acts in the world cannot be stopped quickly. When behaviour goes wrong the only options are to find the process and the keys by hand while actions keep happening.

- STRIDE: Elevation of privilege
- OWASP LLM Top 10 (2025): LLM06 Excessive Agency
- OWASP Agentic Top 10 (2026): ASI10 Rogue Agents, ASI08 Cascading Agent Failures
- MITRE ATLAS: -
- Inherent severity: likelihood 3 x impact 4 = 12
- Applies when: `all(control_missing(control=kill-switch), agent_autonomy_in(autonomy=act|act-with-approval))`
- Mitigations: [`kill-switch`](#kill-switch), [`brokered-credentials`](#brokered-credentials), [`incident-response-playbook`](#incident-response-playbook)

### rag-poisoning

**Retrieval corpus poisoning**

The agent retrieves passages from an index. Anyone who can get a document into that index (shared drives, ticket systems, public pages) can plant content that is retrieved as authoritative and acted on.

- STRIDE: Tampering
- OWASP LLM Top 10 (2025): LLM08 Vector and Embedding Weaknesses, LLM04 Data and Model Poisoning, LLM01 Prompt Injection
- OWASP Agentic Top 10 (2026): ASI06 Memory and Context Poisoning
- MITRE ATLAS: [AML.T0070](https://atlas.mitre.org/techniques/AML.T0070), [AML.T0071](https://atlas.mitre.org/techniques/AML.T0071), [AML.T0066](https://atlas.mitre.org/techniques/AML.T0066)
- Inherent severity: likelihood 3 x impact 4 = 12
- Applies when: `agent_has_channel_kind(kinds=rag)`
- Mitigations: [`rag-source-vetting`](#rag-source-vetting), [`input-provenance-tagging`](#input-provenance-tagging), [`prompt-injection-filtering`](#prompt-injection-filtering), [`audit-log`](#audit-log)
- Reference: <https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/main/2_0_vulns/LLM08_VectorAndEmbeddingWeaknesses.md>

### over-permissive-scopes

**Over-permissive tool scopes**

A tool is granted wildcard, admin or undeclared scope. Whatever goes wrong, the blast radius is the whole account rather than the one resource the task needed.

- STRIDE: Elevation of privilege
- OWASP LLM Top 10 (2025): LLM06 Excessive Agency
- OWASP Agentic Top 10 (2026): ASI03 Identity and Privilege Abuse
- MITRE ATLAS: [AML.T0053](https://atlas.mitre.org/techniques/AML.T0053)
- Inherent severity: likelihood 3 x impact 4 = 12
- Applies when: `tool_scope_broad`
- Mitigations: [`least-privilege-tool-scopes`](#least-privilege-tool-scopes), [`brokered-credentials`](#brokered-credentials), [`approval-gates`](#approval-gates)

### approval-fatigue

**Approval fatigue leads to rubber-stamping**

Many tools demand approval on every call, so reviewers click through without reading. The approval step still exists on paper but no longer catches anything.

- STRIDE: Elevation of privilege
- OWASP LLM Top 10 (2025): LLM06 Excessive Agency
- OWASP Agentic Top 10 (2026): ASI09 Human-Agent Trust Exploitation
- MITRE ATLAS: -
- Inherent severity: likelihood 3 x impact 3 = 9
- Applies when: `approval_always_tool_count_at_least(min=3)`
- Mitigations: [`approval-fatigue-controls`](#approval-fatigue-controls), [`runtime-policy-enforcement`](#runtime-policy-enforcement), [`least-privilege-tool-scopes`](#least-privilege-tool-scopes)

### insecure-output-handling

**Model output consumed without validation**

Downstream components render model output in a browser, pass it to a shell or database, or execute it. Injected or malformed output becomes cross-site scripting, command injection or unintended writes.

- STRIDE: Tampering
- OWASP LLM Top 10 (2025): LLM05 Improper Output Handling
- OWASP Agentic Top 10 (2026): ASI05 Unexpected Code Execution
- MITRE ATLAS: [AML.T0077](https://atlas.mitre.org/techniques/AML.T0077), [AML.T0067](https://atlas.mitre.org/techniques/AML.T0067)
- Inherent severity: likelihood 3 x impact 3 = 9
- Applies when: `any(agent_has_tool_kind(kinds=exec|write), agent_has_channel_kind(kinds=web))`
- Mitigations: [`output-encoding`](#output-encoding), [`argument-validation`](#argument-validation), [`sandboxed-execution`](#sandboxed-execution)
- Reference: <https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/main/2_0_vulns/LLM05_ImproperOutputHandling.md>

### supply-chain-unpinned

**Unpinned model or tool versions**

The model version, tool packages or tool servers are not pinned. A silent upstream change (or a deliberate rug pull) alters behaviour and permissions without any review.

- STRIDE: Tampering
- OWASP LLM Top 10 (2025): LLM03 Supply Chain
- OWASP Agentic Top 10 (2026): ASI04 Agentic Supply Chain Vulnerabilities
- MITRE ATLAS: [AML.T0010](https://atlas.mitre.org/techniques/AML.T0010), [AML.T0010.005](https://atlas.mitre.org/techniques/AML.T0010.005), [AML.T0109](https://atlas.mitre.org/techniques/AML.T0109)
- Inherent severity: likelihood 2 x impact 4 = 8
- Applies when: `any(agent_model_unpinned, tool_unpinned)`
- Mitigations: [`tool-integrity-pinning`](#tool-integrity-pinning), [`model-version-pinning`](#model-version-pinning), [`adversarial-testing`](#adversarial-testing)
- Reference: <https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/main/2_0_vulns/LLM03_SupplyChain.md>

### no-rate-limits

**No rate limits on tool calls**

Nothing bounds how many tool calls or loop iterations an agent may make. A runaway loop or an attacker-driven burst exhausts quotas, floods downstream systems and amplifies every other threat.

- STRIDE: Denial of service
- OWASP LLM Top 10 (2025): LLM10 Unbounded Consumption
- OWASP Agentic Top 10 (2026): ASI08 Cascading Agent Failures
- MITRE ATLAS: [AML.T0029](https://atlas.mitre.org/techniques/AML.T0029), [AML.T0034](https://atlas.mitre.org/techniques/AML.T0034)
- Inherent severity: likelihood 3 x impact 3 = 9
- Applies when: `all(control_missing(control=rate-limiting), agent_has_any_tool)`
- Mitigations: [`rate-limiting`](#rate-limiting), [`budget-caps`](#budget-caps), [`behavioural-monitoring`](#behavioural-monitoring)

### cross-agent-trust

**Implicit trust between agents**

One agent passes tasks to another. The receiving agent treats the message as an instruction from a trusted operator, so an injection in the first agent's input is laundered into a privileged action by the second (a confused deputy).

- STRIDE: Spoofing
- OWASP LLM Top 10 (2025): LLM01 Prompt Injection, LLM06 Excessive Agency
- OWASP Agentic Top 10 (2026): ASI07 Insecure Inter-Agent Communication, ASI08 Cascading Agent Failures
- MITRE ATLAS: [AML.T0051.001](https://atlas.mitre.org/techniques/AML.T0051.001), [AML.T0073](https://atlas.mitre.org/techniques/AML.T0073)
- Inherent severity: likelihood 3 x impact 4 = 12
- Applies when: `agent_delegates_to_agent`
- Mitigations: [`agent-identity`](#agent-identity), [`input-provenance-tagging`](#input-provenance-tagging), [`least-privilege-tool-scopes`](#least-privilege-tool-scopes), [`audit-log`](#audit-log)

### hitl-bypass

**Human-in-the-loop enforced only in the prompt**

The agent is meant to ask before acting, but the rule lives in the prompt. An injected instruction, a jailbreak or a tool that calls another tool routes around the human.

- STRIDE: Elevation of privilege
- OWASP LLM Top 10 (2025): LLM06 Excessive Agency, LLM01 Prompt Injection
- OWASP Agentic Top 10 (2026): ASI09 Human-Agent Trust Exploitation, ASI01 Agent Goal Hijack
- MITRE ATLAS: [AML.T0053](https://atlas.mitre.org/techniques/AML.T0053)
- Inherent severity: likelihood 3 x impact 5 = 15
- Applies when: `all(agent_autonomy_in(autonomy=act-with-approval), control_missing(control=runtime-policy-enforcement))`
- Mitigations: [`runtime-policy-enforcement`](#runtime-policy-enforcement), [`approval-gates`](#approval-gates), [`audit-log`](#audit-log), [`kill-switch`](#kill-switch)

### denial-of-wallet

**Denial of wallet**

The agent can spend money or paid API quota and nothing caps the amount per task. A loop, an injection or a malicious user turns the agent into a bill.

- STRIDE: Denial of service
- OWASP LLM Top 10 (2025): LLM10 Unbounded Consumption
- OWASP Agentic Top 10 (2026): ASI08 Cascading Agent Failures
- MITRE ATLAS: [AML.T0034.002](https://atlas.mitre.org/techniques/AML.T0034.002), [AML.T0034](https://atlas.mitre.org/techniques/AML.T0034)
- Inherent severity: likelihood 3 x impact 4 = 12
- Applies when: `all(control_missing(control=budget-caps), any(agent_has_tool_kind(kinds=payment|network), agent_autonomy_in(autonomy=act)))`
- Mitigations: [`budget-caps`](#budget-caps), [`rate-limiting`](#rate-limiting), [`approval-gates`](#approval-gates), [`behavioural-monitoring`](#behavioural-monitoring)
- Reference: <https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/main/2_0_vulns/LLM10_UnboundedConsumption.md>

### sensitive-data-disclosure

**Sensitive data reachable by the model**

The agent can read confidential or regulated records through a tool. Whatever enters the context can be summarised, quoted or exfiltrated, and a shared service account returns records the requesting user may not be entitled to.

- STRIDE: Information disclosure
- OWASP LLM Top 10 (2025): LLM02 Sensitive Information Disclosure
- OWASP Agentic Top 10 (2026): ASI03 Identity and Privilege Abuse, ASI02 Tool Misuse and Exploitation
- MITRE ATLAS: [AML.T0057](https://atlas.mitre.org/techniques/AML.T0057), [AML.T0085.000](https://atlas.mitre.org/techniques/AML.T0085.000), [AML.T0036](https://atlas.mitre.org/techniques/AML.T0036)
- Inherent severity: likelihood 3 x impact 4 = 12
- Applies when: `agent_reaches_sensitive_store(min=confidential)`
- Mitigations: [`per-user-authorisation`](#per-user-authorisation), [`least-privilege-tool-scopes`](#least-privilege-tool-scopes), [`dlp-outbound`](#dlp-outbound), [`audit-log`](#audit-log)
- Reference: <https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/main/2_0_vulns/LLM02_SensitiveInformationDisclosure.md>

### system-prompt-leakage

**System prompt and configuration leakage**

Users or third-party content can coax the model into revealing its system prompt, tool list and configuration. On its own this is reconnaissance; it becomes serious when the prompt holds secrets or business rules.

- STRIDE: Information disclosure
- OWASP LLM Top 10 (2025): LLM07 System Prompt Leakage
- OWASP Agentic Top 10 (2026): not mapped
- MITRE ATLAS: [AML.T0056](https://atlas.mitre.org/techniques/AML.T0056), [AML.T0069.002](https://atlas.mitre.org/techniques/AML.T0069.002), [AML.T0084](https://atlas.mitre.org/techniques/AML.T0084), [AML.T0084.001](https://atlas.mitre.org/techniques/AML.T0084.001)
- Inherent severity: likelihood 4 x impact 2 = 8
- Applies when: `agent_has_input_of_origin(origin=user|third-party)`
- Mitigations: [`secrets-out-of-context`](#secrets-out-of-context), [`runtime-policy-enforcement`](#runtime-policy-enforcement), [`adversarial-testing`](#adversarial-testing)
- Reference: <https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/main/2_0_vulns/LLM07_SystemPromptLeakage.md>

### destructive-write-actions

**Destructive actions through write tools**

The agent can modify or delete data and reads untrusted content. An injected instruction (or a plain mistake) deletes records, overwrites files or force-pushes over history.

- STRIDE: Tampering
- OWASP LLM Top 10 (2025): LLM06 Excessive Agency, LLM01 Prompt Injection
- OWASP Agentic Top 10 (2026): ASI02 Tool Misuse and Exploitation
- MITRE ATLAS: [AML.T0101](https://atlas.mitre.org/techniques/AML.T0101)
- Inherent severity: likelihood 3 x impact 4 = 12
- Applies when: `all(agent_has_tool_kind(kinds=write), untrusted_channel_in_agent_inputs)`
- Mitigations: [`approval-gates`](#approval-gates), [`backups-and-rollback`](#backups-and-rollback), [`least-privilege-tool-scopes`](#least-privilege-tool-scopes), [`audit-log`](#audit-log)

### low-trust-principal-drives-agent

**Low-trust principal drives an autonomous agent**

A principal the operator does not trust (anonymous users, external partners) can send instructions to an agent that acts without approval. The agent's tools are effectively exposed to the public.

- STRIDE: Spoofing
- OWASP LLM Top 10 (2025): LLM06 Excessive Agency
- OWASP Agentic Top 10 (2026): ASI01 Agent Goal Hijack, ASI03 Identity and Privilege Abuse
- MITRE ATLAS: [AML.T0053](https://atlas.mitre.org/techniques/AML.T0053)
- Inherent severity: likelihood 3 x impact 4 = 12
- Applies when: `all(low_trust_principal_feeds_agent, agent_autonomy_in(autonomy=act))`
- Mitigations: [`approval-gates`](#approval-gates), [`agent-identity`](#agent-identity), [`least-privilege-tool-scopes`](#least-privilege-tool-scopes), [`rate-limiting`](#rate-limiting)

### session-cross-contamination

**Memory leaks between users or sessions**

The agent keeps memory and serves more than one user. Without strict partitioning, one user's data or instructions surface in another user's session.

- STRIDE: Information disclosure
- OWASP LLM Top 10 (2025): LLM02 Sensitive Information Disclosure
- OWASP Agentic Top 10 (2026): ASI06 Memory and Context Poisoning
- MITRE ATLAS: [AML.T0057](https://atlas.mitre.org/techniques/AML.T0057), [AML.T0092](https://atlas.mitre.org/techniques/AML.T0092)
- Inherent severity: likelihood 2 x impact 4 = 8
- Applies when: `all(agent_memory_is(memory=session|persistent), agent_has_input_of_origin(origin=user))`
- Mitigations: [`session-isolation`](#session-isolation), [`per-user-authorisation`](#per-user-authorisation), [`memory-write-validation`](#memory-write-validation)

### malicious-file-input

**Malicious files and documents as input**

The agent parses files or documents. Crafted files exploit parser bugs, hide instructions in metadata or invisible text, and carry macros or links that later tools act on.

- STRIDE: Tampering
- OWASP LLM Top 10 (2025): LLM01 Prompt Injection
- OWASP Agentic Top 10 (2026): ASI01 Agent Goal Hijack
- MITRE ATLAS: [AML.T0051.001](https://atlas.mitre.org/techniques/AML.T0051.001), [AML.T0011.000](https://atlas.mitre.org/techniques/AML.T0011.000)
- Inherent severity: likelihood 3 x impact 3 = 9
- Applies when: `agent_has_channel_kind(kinds=file|document, untrusted=true)`
- Mitigations: [`untrusted-content-isolation`](#untrusted-content-isolation), [`sandboxed-execution`](#sandboxed-execution), [`prompt-injection-filtering`](#prompt-injection-filtering), [`input-provenance-tagging`](#input-provenance-tagging)

### hallucinated-actions

**Acting on hallucinated facts or identifiers**

The agent invents a package name, account id, file path or amount and a side-effecting tool executes it. Attackers register the names models tend to invent so the mistake resolves to something malicious.

- STRIDE: Tampering
- OWASP LLM Top 10 (2025): LLM09 Misinformation, LLM06 Excessive Agency
- OWASP Agentic Top 10 (2026): ASI02 Tool Misuse and Exploitation, ASI04 Agentic Supply Chain Vulnerabilities
- MITRE ATLAS: [AML.T0060](https://atlas.mitre.org/techniques/AML.T0060), [AML.T0053](https://atlas.mitre.org/techniques/AML.T0053)
- Inherent severity: likelihood 3 x impact 3 = 9
- Applies when: `all(agent_autonomy_in(autonomy=act|act-with-approval), agent_has_tool_kind(kinds=exec|write|payment))`
- Mitigations: [`argument-validation`](#argument-validation), [`approval-gates`](#approval-gates), [`tool-integrity-pinning`](#tool-integrity-pinning), [`adversarial-testing`](#adversarial-testing)
- Reference: <https://arxiv.org/abs/2406.10279>

### agent-config-tampering

**Agent configuration tampering**

Prompts, tool lists and policies live in files or stores an agent can write to, or that lack change control. Modifying them silently changes what the agent is allowed to do.

- STRIDE: Tampering
- OWASP LLM Top 10 (2025): LLM03 Supply Chain, LLM06 Excessive Agency
- OWASP Agentic Top 10 (2026): ASI10 Rogue Agents, ASI04 Agentic Supply Chain Vulnerabilities
- MITRE ATLAS: [AML.T0081](https://atlas.mitre.org/techniques/AML.T0081)
- Inherent severity: likelihood 2 x impact 4 = 8
- Applies when: `all(agent_has_tool_kind(kinds=write|exec), control_missing(control=runtime-policy-enforcement))`
- Mitigations: [`runtime-policy-enforcement`](#runtime-policy-enforcement), [`tool-integrity-pinning`](#tool-integrity-pinning), [`audit-log`](#audit-log), [`least-privilege-tool-scopes`](#least-privilege-tool-scopes)

## Controls

| Id | Title | Type | Effort | Mitigates |
|---|---|---|---|---|
| [`argument-validation`](#argument-validation) | Strict schemas for tool arguments | preventive | low | `credential-exfiltration-via-tool-args`, `ssrf-via-url-tool`, `insecure-output-handling`, `hallucinated-actions` |
| [`budget-caps`](#budget-caps) | Hard budget caps on spend and tokens | preventive | low | `no-rate-limits`, `denial-of-wallet` |
| [`egress-allowlist`](#egress-allowlist) | Allowlist network egress and message recipients | preventive | low | `credential-exfiltration-via-tool-args`, `ssrf-via-url-tool`, `data-exfiltration-via-messaging`, `unsandboxed-exec` |
| [`incident-response-playbook`](#incident-response-playbook) | Incident response playbook for agent incidents | corrective | low | `missing-audit-trail`, `missing-kill-switch` |
| [`kill-switch`](#kill-switch) | Kill switch with credential revocation | corrective | low | `excessive-agency`, `unsandboxed-exec`, `static-long-lived-credentials`, `missing-kill-switch`, `hitl-bypass` |
| [`model-version-pinning`](#model-version-pinning) | Pin and change-control the model version | preventive | low | `supply-chain-unpinned` |
| [`output-encoding`](#output-encoding) | Treat model output as untrusted data downstream | preventive | low | `insecure-output-handling` |
| [`prompt-injection-filtering`](#prompt-injection-filtering) | Detect injection attempts in untrusted content | detective | low | `indirect-prompt-injection`, `direct-prompt-injection`, `rag-poisoning`, `malicious-file-input` |
| [`rate-limiting`](#rate-limiting) | Rate limits on tool calls and iterations | preventive | low | `no-rate-limits`, `denial-of-wallet`, `low-trust-principal-drives-agent` |
| [`secrets-out-of-context`](#secrets-out-of-context) | Keep secrets out of the model context | preventive | low | `credential-exfiltration-via-tool-args`, `static-long-lived-credentials`, `system-prompt-leakage` |
| [`tool-integrity-pinning`](#tool-integrity-pinning) | Pin tool versions and hash tool descriptions | preventive | low | `tool-poisoning`, `supply-chain-unpinned`, `hallucinated-actions`, `agent-config-tampering` |
| [`adversarial-testing`](#adversarial-testing) | Adversarial testing before and after release | detective | medium | `direct-prompt-injection`, `supply-chain-unpinned`, `system-prompt-leakage`, `hallucinated-actions` |
| [`agent-identity`](#agent-identity) | Authenticated identities for agents and principals | preventive | medium | `unauthenticated-tool`, `cross-agent-trust`, `low-trust-principal-drives-agent` |
| [`approval-fatigue-controls`](#approval-fatigue-controls) | Design approvals that people can actually review | preventive | medium | `approval-fatigue` |
| [`approval-gates`](#approval-gates) | Human approval for high-impact actions | preventive | medium | `indirect-prompt-injection`, `direct-prompt-injection`, `tool-poisoning`, `excessive-agency`, `data-exfiltration-via-messaging`, `unsandboxed-exec`, `over-permissive-scopes`, `hitl-bypass`, `denial-of-wallet`, `destructive-write-actions`, `low-trust-principal-drives-agent`, `hallucinated-actions` |
| [`audit-log`](#audit-log) | Tamper-evident audit log of every tool call | detective | medium | `credential-exfiltration-via-tool-args`, `excessive-agency`, `ssrf-via-url-tool`, `data-exfiltration-via-messaging`, `memory-poisoning`, `unsandboxed-exec`, `static-long-lived-credentials`, `unauthenticated-tool`, `missing-audit-trail`, `rag-poisoning`, `cross-agent-trust`, `hitl-bypass`, `sensitive-data-disclosure`, `destructive-write-actions`, `agent-config-tampering` |
| [`backups-and-rollback`](#backups-and-rollback) | Backups and rollback for agent-writable data | corrective | medium | `destructive-write-actions` |
| [`brokered-credentials`](#brokered-credentials) | Short-lived, scoped, brokered credentials | preventive | medium | `credential-exfiltration-via-tool-args`, `static-long-lived-credentials`, `unauthenticated-tool`, `missing-kill-switch`, `over-permissive-scopes` |
| [`dlp-outbound`](#dlp-outbound) | Data loss prevention on outbound messages | detective | medium | `data-exfiltration-via-messaging`, `sensitive-data-disclosure` |
| [`input-provenance-tagging`](#input-provenance-tagging) | Tag every input with its provenance and trust level | preventive | medium | `indirect-prompt-injection`, `tool-poisoning`, `data-exfiltration-via-messaging`, `memory-poisoning`, `rag-poisoning`, `cross-agent-trust`, `malicious-file-input` |
| [`least-privilege-tool-scopes`](#least-privilege-tool-scopes) | Least-privilege scopes on every tool | preventive | medium | `indirect-prompt-injection`, `direct-prompt-injection`, `tool-poisoning`, `excessive-agency`, `over-permissive-scopes`, `approval-fatigue`, `cross-agent-trust`, `sensitive-data-disclosure`, `destructive-write-actions`, `low-trust-principal-drives-agent`, `agent-config-tampering` |
| [`memory-write-validation`](#memory-write-validation) | Validate and expire writes to persistent memory | preventive | medium | `memory-poisoning`, `session-cross-contamination` |
| [`per-user-authorisation`](#per-user-authorisation) | Access data with the end user's permissions | preventive | medium | `sensitive-data-disclosure`, `session-cross-contamination` |
| [`rag-source-vetting`](#rag-source-vetting) | Vet, sign and scan retrieval sources | preventive | medium | `rag-poisoning` |
| [`runtime-policy-enforcement`](#runtime-policy-enforcement) | Enforce policy outside the model | preventive | medium | `direct-prompt-injection`, `excessive-agency`, `approval-fatigue`, `hitl-bypass`, `system-prompt-leakage`, `agent-config-tampering` |
| [`sandboxed-execution`](#sandboxed-execution) | Run code and shell tools in an ephemeral sandbox | preventive | medium | `ssrf-via-url-tool`, `unsandboxed-exec`, `insecure-output-handling`, `malicious-file-input` |
| [`session-isolation`](#session-isolation) | Isolate memory and context per user and session | preventive | medium | `memory-poisoning`, `session-cross-contamination` |
| [`behavioural-monitoring`](#behavioural-monitoring) | Monitor agent behaviour for anomalies | detective | high | `missing-audit-trail`, `no-rate-limits`, `denial-of-wallet` |
| [`untrusted-content-isolation`](#untrusted-content-isolation) | Isolate untrusted content from the privileged agent | preventive | high | `indirect-prompt-injection`, `malicious-file-input` |

### argument-validation

**Strict schemas for tool arguments** (preventive, low effort)

Every tool declares a strict argument schema (types, enums, ranges, allowlisted paths) that the runtime validates before execution. Free-text shell or SQL arguments are replaced with structured parameters.

- Mitigates: [`credential-exfiltration-via-tool-args`](#credential-exfiltration-via-tool-args), [`ssrf-via-url-tool`](#ssrf-via-url-tool), [`insecure-output-handling`](#insecure-output-handling), [`hallucinated-actions`](#hallucinated-actions)
- Reference: <https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html>
- Reference: <https://atlas.mitre.org/mitigations/AML.M0033>

### budget-caps

**Hard budget caps on spend and tokens** (preventive, low effort)

Each task carries a cap on model spend, payment amounts and paid API calls. Reaching the cap stops the task and alerts an operator.

- Mitigates: [`no-rate-limits`](#no-rate-limits), [`denial-of-wallet`](#denial-of-wallet)
- Reference: <https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/main/2_0_vulns/LLM10_UnboundedConsumption.md>
- Reference: <https://atlas.mitre.org/mitigations/AML.M0004>

### egress-allowlist

**Allowlist network egress and message recipients** (preventive, low effort)

Tools that fetch URLs or send messages may only reach allowlisted domains and recipients. Private address ranges, metadata endpoints and redirects to them are blocked at the network layer, not in the prompt.

- Mitigates: [`credential-exfiltration-via-tool-args`](#credential-exfiltration-via-tool-args), [`ssrf-via-url-tool`](#ssrf-via-url-tool), [`data-exfiltration-via-messaging`](#data-exfiltration-via-messaging), [`unsandboxed-exec`](#unsandboxed-exec)
- Reference: <https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html>
- Reference: <https://atlas.mitre.org/mitigations/AML.M0032>

### incident-response-playbook

**Incident response playbook for agent incidents** (corrective, low effort)

A written playbook covers how to pause agents, revoke credentials, preserve audit evidence and notify affected users, and it is exercised.

- Mitigates: [`missing-audit-trail`](#missing-audit-trail), [`missing-kill-switch`](#missing-kill-switch)
- Reference: <https://csrc.nist.gov/pubs/sp/800/61/r3/final>
- Reference: <https://github.com/basitalisandhu/ai-agent-incidents>

### kill-switch

**Kill switch with credential revocation** (corrective, low effort)

An operator can halt one agent or all agents immediately. Halting revokes outstanding credentials and cancels queued tool calls, and the switch is tested regularly.

- Mitigates: [`excessive-agency`](#excessive-agency), [`unsandboxed-exec`](#unsandboxed-exec), [`static-long-lived-credentials`](#static-long-lived-credentials), [`missing-kill-switch`](#missing-kill-switch), [`hitl-bypass`](#hitl-bypass)
- Reference: <https://basitalisandhu.github.io/masoon/masoon-broker.html>
- Reference: <https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf>

### model-version-pinning

**Pin and change-control the model version** (preventive, low effort)

The model version and provider are pinned, changes go through evaluation before rollout, and the system records which version served each request.

- Mitigates: [`supply-chain-unpinned`](#supply-chain-unpinned)
- Reference: <https://atlas.mitre.org/mitigations/AML.M0023>
- Reference: <https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/main/2_0_vulns/LLM03_SupplyChain.md>

### output-encoding

**Treat model output as untrusted data downstream** (preventive, low effort)

Model output is encoded before it is rendered in a browser, parameterised before it reaches a database or shell, and never interpreted as code without a sandbox and a review step.

- Mitigates: [`insecure-output-handling`](#insecure-output-handling)
- Reference: <https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>
- Reference: <https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/main/2_0_vulns/LLM05_ImproperOutputHandling.md>

### prompt-injection-filtering

**Detect injection attempts in untrusted content** (detective, low effort)

Untrusted content is scanned with heuristics or a classifier before it reaches the model, and hits are logged and quarantined. This is a detective layer, not a boundary; pair it with provenance tagging.

- Mitigates: [`indirect-prompt-injection`](#indirect-prompt-injection), [`direct-prompt-injection`](#direct-prompt-injection), [`rag-poisoning`](#rag-poisoning), [`malicious-file-input`](#malicious-file-input)
- Reference: <https://atlas.mitre.org/mitigations/AML.M0015>
- Reference: <https://atlas.mitre.org/mitigations/AML.M0020>
- Reference: <https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html>

### rate-limiting

**Rate limits on tool calls and iterations** (preventive, low effort)

Per-agent and per-principal limits on tool calls, loop iterations and concurrent tasks stop runaway loops and amplification.

- Mitigates: [`no-rate-limits`](#no-rate-limits), [`denial-of-wallet`](#denial-of-wallet), [`low-trust-principal-drives-agent`](#low-trust-principal-drives-agent)
- Reference: <https://atlas.mitre.org/mitigations/AML.M0004>
- Reference: <https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html>

### secrets-out-of-context

**Keep secrets out of the model context** (preventive, low effort)

Credentials are injected by the tool runtime at call time and never appear in prompts, tool descriptions, memory or logs the model can read, so an injected instruction cannot ask the model to repeat them.

- Mitigates: [`credential-exfiltration-via-tool-args`](#credential-exfiltration-via-tool-args), [`static-long-lived-credentials`](#static-long-lived-credentials), [`system-prompt-leakage`](#system-prompt-leakage)
- Reference: <https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html>
- Reference: <https://atlas.mitre.org/mitigations/AML.M0012>
- Reference: <https://atlas.mitre.org/techniques/AML.T0083>

### tool-integrity-pinning

**Pin tool versions and hash tool descriptions** (preventive, low effort)

Tool servers and packages are pinned to reviewed versions, tool descriptions are hashed at review time, and any change blocks the agent until it is re-reviewed.

- Mitigates: [`tool-poisoning`](#tool-poisoning), [`supply-chain-unpinned`](#supply-chain-unpinned), [`hallucinated-actions`](#hallucinated-actions), [`agent-config-tampering`](#agent-config-tampering)
- Reference: <https://atlas.mitre.org/mitigations/AML.M0013>
- Reference: <https://atlas.mitre.org/mitigations/AML.M0014>
- Reference: <https://atlas.mitre.org/mitigations/AML.M0023>
- Reference: <https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices>

### adversarial-testing

**Adversarial testing before and after release** (detective, medium effort)

The system is tested against injection, jailbreak and tool-abuse cases in CI and periodically in production, and findings feed back into the catalogue of controls.

- Mitigates: [`direct-prompt-injection`](#direct-prompt-injection), [`supply-chain-unpinned`](#supply-chain-unpinned), [`system-prompt-leakage`](#system-prompt-leakage), [`hallucinated-actions`](#hallucinated-actions)
- Reference: <https://atlas.mitre.org/mitigations/AML.M0008>
- Reference: <https://atlas.mitre.org/mitigations/AML.M0016>
- Reference: <https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf>

### agent-identity

**Authenticated identities for agents and principals** (preventive, medium effort)

Each agent and principal has its own identity. Messages between agents and calls to tools are authenticated and carry the originating principal, so a downstream agent can apply its own policy.

- Mitigates: [`unauthenticated-tool`](#unauthenticated-tool), [`cross-agent-trust`](#cross-agent-trust), [`low-trust-principal-drives-agent`](#low-trust-principal-drives-agent)
- Reference: <https://atlas.mitre.org/mitigations/AML.M0032>
- Reference: <https://cheatsheetseries.owasp.org/cheatsheets/Microservices_Security_Cheat_Sheet.html>
- Reference: <https://basitalisandhu.github.io/masoon/masoon-broker.html>

### approval-fatigue-controls

**Design approvals that people can actually review** (preventive, medium effort)

Approvals are risk-based rather than blanket, batched where safe, show a diff of the intended effect, and repeated denials or time-outs stop the task instead of retrying.

- Mitigates: [`approval-fatigue`](#approval-fatigue)
- Reference: <https://atlas.mitre.org/mitigations/AML.M0029>
- Reference: <https://basitalisandhu.github.io/masoon/masoon-broker.html>

### approval-gates

**Human approval for high-impact actions** (preventive, medium effort)

Write, exec, payment and messaging actions above a defined threshold require an explicit approval from an accountable human before they run. Approval requests show the exact arguments and expected effect.

- Mitigates: [`indirect-prompt-injection`](#indirect-prompt-injection), [`direct-prompt-injection`](#direct-prompt-injection), [`tool-poisoning`](#tool-poisoning), [`excessive-agency`](#excessive-agency), [`data-exfiltration-via-messaging`](#data-exfiltration-via-messaging), [`unsandboxed-exec`](#unsandboxed-exec), [`over-permissive-scopes`](#over-permissive-scopes), [`hitl-bypass`](#hitl-bypass), [`denial-of-wallet`](#denial-of-wallet), [`destructive-write-actions`](#destructive-write-actions), [`low-trust-principal-drives-agent`](#low-trust-principal-drives-agent), [`hallucinated-actions`](#hallucinated-actions)
- Reference: <https://atlas.mitre.org/mitigations/AML.M0029>
- Reference: <https://basitalisandhu.github.io/masoon/masoon-broker.html>
- Reference: <https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/main/2_0_vulns/LLM06_ExcessiveAgency.md>

### audit-log

**Tamper-evident audit log of every tool call** (detective, medium effort)

Every tool call is recorded with the acting agent, principal, arguments, result, approval decision and provenance of the triggering input, in a hash-chained or append-only store that the agent cannot modify.

- Mitigates: [`credential-exfiltration-via-tool-args`](#credential-exfiltration-via-tool-args), [`excessive-agency`](#excessive-agency), [`ssrf-via-url-tool`](#ssrf-via-url-tool), [`data-exfiltration-via-messaging`](#data-exfiltration-via-messaging), [`memory-poisoning`](#memory-poisoning), [`unsandboxed-exec`](#unsandboxed-exec), [`static-long-lived-credentials`](#static-long-lived-credentials), [`unauthenticated-tool`](#unauthenticated-tool), [`missing-audit-trail`](#missing-audit-trail), [`rag-poisoning`](#rag-poisoning), [`cross-agent-trust`](#cross-agent-trust), [`hitl-bypass`](#hitl-bypass), [`sensitive-data-disclosure`](#sensitive-data-disclosure), [`destructive-write-actions`](#destructive-write-actions), [`agent-config-tampering`](#agent-config-tampering)
- Reference: <https://atlas.mitre.org/mitigations/AML.M0024>
- Reference: <https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html>
- Reference: <https://basitalisandhu.github.io/masoon/masoon-broker.html>

### backups-and-rollback

**Backups and rollback for agent-writable data** (corrective, medium effort)

Data stores an agent can write to have point-in-time backups and a tested rollback path, so a destructive action is recoverable.

- Mitigates: [`destructive-write-actions`](#destructive-write-actions)
- Reference: <https://csrc.nist.gov/pubs/sp/800/34/r1/upd1/final>

### brokered-credentials

**Short-lived, scoped, brokered credentials** (preventive, medium effort)

Agents never hold long-lived secrets. A broker issues per-task credentials bound to a scope, a time limit and an audit record, and can revoke them centrally.

- Mitigates: [`credential-exfiltration-via-tool-args`](#credential-exfiltration-via-tool-args), [`static-long-lived-credentials`](#static-long-lived-credentials), [`unauthenticated-tool`](#unauthenticated-tool), [`missing-kill-switch`](#missing-kill-switch), [`over-permissive-scopes`](#over-permissive-scopes)
- Reference: <https://basitalisandhu.github.io/masoon/masoon-broker.html>
- Reference: <https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html>
- Reference: <https://atlas.mitre.org/mitigations/AML.M0019>

### dlp-outbound

**Data loss prevention on outbound messages** (detective, medium effort)

Outgoing email, chat messages and uploads are scanned for classified data and blocked or held for review when they contain it.

- Mitigates: [`data-exfiltration-via-messaging`](#data-exfiltration-via-messaging), [`sensitive-data-disclosure`](#sensitive-data-disclosure)
- Reference: <https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/main/2_0_vulns/LLM02_SensitiveInformationDisclosure.md>
- Reference: <https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final>

### input-provenance-tagging

**Tag every input with its provenance and trust level** (preventive, medium effort)

Each span of text that enters the model context is labelled with its origin (user, third party, internal) and trust level, and the runtime refuses to let instructions from untrusted spans drive privileged tool calls.

- Mitigates: [`indirect-prompt-injection`](#indirect-prompt-injection), [`tool-poisoning`](#tool-poisoning), [`data-exfiltration-via-messaging`](#data-exfiltration-via-messaging), [`memory-poisoning`](#memory-poisoning), [`rag-poisoning`](#rag-poisoning), [`cross-agent-trust`](#cross-agent-trust), [`malicious-file-input`](#malicious-file-input)
- Reference: <https://atlas.mitre.org/mitigations/AML.M0030>
- Reference: <https://atlas.mitre.org/mitigations/AML.M0033>
- Reference: <https://github.com/basitalisandhu/llm-agent-control-plane>
- Reference: <https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/main/2_0_vulns/LLM01_PromptInjection.md>

### least-privilege-tool-scopes

**Least-privilege scopes on every tool** (preventive, medium effort)

Every tool is granted the narrowest scope that the task needs (specific repositories, mailboxes, tables, amounts) and scopes are reviewed when the task changes. Wildcard and admin scopes are not issued to agents.

- Mitigates: [`indirect-prompt-injection`](#indirect-prompt-injection), [`direct-prompt-injection`](#direct-prompt-injection), [`tool-poisoning`](#tool-poisoning), [`excessive-agency`](#excessive-agency), [`over-permissive-scopes`](#over-permissive-scopes), [`approval-fatigue`](#approval-fatigue), [`cross-agent-trust`](#cross-agent-trust), [`sensitive-data-disclosure`](#sensitive-data-disclosure), [`destructive-write-actions`](#destructive-write-actions), [`low-trust-principal-drives-agent`](#low-trust-principal-drives-agent), [`agent-config-tampering`](#agent-config-tampering)
- Reference: <https://atlas.mitre.org/mitigations/AML.M0028>
- Reference: <https://atlas.mitre.org/mitigations/AML.M0026>
- Reference: <https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/main/2_0_vulns/LLM06_ExcessiveAgency.md>
- Reference: <https://basitalisandhu.github.io/masoon/masoon-broker.html>

### memory-write-validation

**Validate and expire writes to persistent memory** (preventive, medium effort)

Writes to long-term memory are schema-validated, tagged with provenance, reviewed or rate limited, and expire by default so a single poisoned interaction cannot steer every future session.

- Mitigates: [`memory-poisoning`](#memory-poisoning), [`session-cross-contamination`](#session-cross-contamination)
- Reference: <https://atlas.mitre.org/mitigations/AML.M0031>
- Reference: <https://atlas.mitre.org/techniques/AML.T0080>

### per-user-authorisation

**Access data with the end user's permissions** (preventive, medium effort)

Tools act with the permissions of the requesting principal, not a shared service account, so the agent cannot return records its user may not see.

- Mitigates: [`sensitive-data-disclosure`](#sensitive-data-disclosure), [`session-cross-contamination`](#session-cross-contamination)
- Reference: <https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html>
- Reference: <https://atlas.mitre.org/mitigations/AML.M0027>
- Reference: <https://atlas.mitre.org/mitigations/AML.M0019>

### rag-source-vetting

**Vet, sign and scan retrieval sources** (preventive, medium effort)

Only approved sources are ingested into retrieval indexes, documents are scanned for embedded instructions at ingest, and each chunk keeps its provenance and access-control labels.

- Mitigates: [`rag-poisoning`](#rag-poisoning)
- Reference: <https://atlas.mitre.org/mitigations/AML.M0025>
- Reference: <https://atlas.mitre.org/mitigations/AML.M0007>
- Reference: <https://github.com/OWASP/www-project-top-10-for-large-language-model-applications/blob/main/2_0_vulns/LLM08_VectorAndEmbeddingWeaknesses.md>

### runtime-policy-enforcement

**Enforce policy outside the model** (preventive, medium effort)

Tool calls pass through a deterministic policy enforcement point that checks provenance, scope, approval state and limits before execution. Rules written into the prompt are advice to the model, not a control.

- Mitigates: [`direct-prompt-injection`](#direct-prompt-injection), [`excessive-agency`](#excessive-agency), [`approval-fatigue`](#approval-fatigue), [`hitl-bypass`](#hitl-bypass), [`system-prompt-leakage`](#system-prompt-leakage), [`agent-config-tampering`](#agent-config-tampering)
- Reference: <https://github.com/basitalisandhu/llm-agent-control-plane>
- Reference: <https://atlas.mitre.org/mitigations/AML.M0033>
- Reference: <https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf>

### sandboxed-execution

**Run code and shell tools in an ephemeral sandbox** (preventive, medium effort)

Exec tools run in a throwaway container or micro-VM with no host credentials, a read-only base image, resource limits and a default-deny network policy.

- Mitigates: [`ssrf-via-url-tool`](#ssrf-via-url-tool), [`unsandboxed-exec`](#unsandboxed-exec), [`insecure-output-handling`](#insecure-output-handling), [`malicious-file-input`](#malicious-file-input)
- Reference: <https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html>
- Reference: <https://atlas.mitre.org/mitigations/AML.M0032>
- Reference: <https://atlas.mitre.org/mitigations/AML.M0011>

### session-isolation

**Isolate memory and context per user and session** (preventive, medium effort)

Memory, caches and retrieval scopes are partitioned by user and session so content from one principal is never visible to another.

- Mitigates: [`memory-poisoning`](#memory-poisoning), [`session-cross-contamination`](#session-cross-contamination)
- Reference: <https://atlas.mitre.org/mitigations/AML.M0027>
- Reference: <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html>

### behavioural-monitoring

**Monitor agent behaviour for anomalies** (detective, high effort)

Tool-call sequences, volumes, recipients and spend are baselined and alerts fire on deviations such as new destinations, bursts of writes or repeated denied calls.

- Mitigates: [`missing-audit-trail`](#missing-audit-trail), [`no-rate-limits`](#no-rate-limits), [`denial-of-wallet`](#denial-of-wallet)
- Reference: <https://atlas.mitre.org/mitigations/AML.M0024>
- Reference: <https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf>

### untrusted-content-isolation

**Isolate untrusted content from the privileged agent** (preventive, high effort)

Untrusted documents are processed by a separate, tool-less model or a capability-restricted flow whose output is treated as data by the privileged agent (dual-model and CaMeL style designs).

- Mitigates: [`indirect-prompt-injection`](#indirect-prompt-injection), [`malicious-file-input`](#malicious-file-input)
- Reference: <https://simonwillison.net/2023/Apr/25/dual-llm-pattern/>
- Reference: <https://arxiv.org/abs/2503.18813>
- Reference: <https://atlas.mitre.org/mitigations/AML.M0032>

## Predicates

Rules in `applies_when` are built from these named predicates with `all`, `any` and `not`. Arguments are written `name(key=value)`; several values are separated with `|`.

| Predicate | Meaning |
|---|---|
| `agent_autonomy_in` |  |
| `agent_delegates_to_agent` |  |
| `agent_has_any_tool` |  |
| `agent_has_channel_kind` | An agent reads a channel of one of the given kinds (optionally only untrusted ones). |
| `agent_has_input_of_origin` | An agent reads a channel whose origin is one of the given values. |
| `agent_has_tool_kind` | An agent can call a tool of one of the given kinds. |
| `agent_memory_is` |  |
| `agent_model_unpinned` |  |
| `agent_reaches_sensitive_store` | An agent can reach, through a tool, a data store at or above the given sensitivity. |
| `approval_always_tool_count_at_least` | At least N reachable tools require approval on every call (fatigue risk). |
| `control_missing` | None of the given controls is listed in the system's controls. |
| `control_present` |  |
| `low_trust_principal_feeds_agent` | A principal with trust: low speaks on a channel an agent reads. |
| `store_sensitivity_at_least` |  |
| `third_party_tool` |  |
| `tool_auth_in` | A reachable tool authenticates with one of the given methods (optionally of given kinds). |
| `tool_kind_not_sandboxed` |  |
| `tool_kind_without_approval` | A reachable tool of the given kind needs no approval and its agent may act. |
| `tool_scope_broad` |  |
| `tool_unpinned` |  |
| `untrusted_channel_in_agent_inputs` | An agent reads at least one channel marked trusted: false. |
