# Threat register diff: `examples/finance-agent.yaml` to `examples/masoon-governed.yaml`

Residual risk score **90** (critical) to **27** (medium), change -63.

Controls added: `approval-fatigue-controls`, `argument-validation`, `audit-log`, `brokered-credentials`, `budget-caps`, `dlp-outbound`, `egress-allowlist`, `incident-response-playbook`, `input-provenance-tagging`, `kill-switch`, `least-privilege-tool-scopes`, `model-version-pinning`, `per-user-authorisation`, `rate-limiting`, `runtime-policy-enforcement`, `secrets-out-of-context`, `tool-integrity-pinning`

| Change | Threat | Before | After |
|---|---|---|---|
| removed | `credential-exfiltration-via-tool-args` Credential exfiltration through tool call arguments | 15 high | - |
| removed | `excessive-agency` Excessive agency on write, exec or payment tools | 12.9 high | - |
| removed | `missing-audit-trail` No tamper-evident audit trail of tool calls | 12 high | - |
| removed | `missing-kill-switch` No kill switch or credential revocation | 12 high | - |
| removed | `static-long-lived-credentials` Static long-lived credentials held by the agent | 12 high | - |
| removed | `hitl-bypass` Human-in-the-loop enforced only in the prompt | 11.1 medium | - |
| removed | `denial-of-wallet` Denial of wallet | 9.3 medium | - |
| removed | `no-rate-limits` No rate limits on tool calls | 9 medium | - |
| removed | `agent-config-tampering` Agent configuration tampering | 8 medium | - |
| removed | `supply-chain-unpinned` Unpinned model or tool versions | 8 medium | - |
| changed | `sensitive-data-disclosure` Sensitive data reachable by the model | 15 high | 3 low |
| changed | `data-exfiltration-via-messaging` Data exfiltration through messaging tools | 12.1 high | 3 low |
| changed | `indirect-prompt-injection` Indirect prompt injection via untrusted channel | 13.2 high | 7.7 medium |
| changed | `destructive-write-actions` Destructive actions through write tools | 8.9 medium | 3.9 low |
| changed | `system-prompt-leakage` System prompt and configuration leakage | 8 medium | 3.1 low |
| changed | `direct-prompt-injection` Direct prompt injection and jailbreak by a user | 9.7 medium | 5.1 low |
| changed | `hallucinated-actions` Acting on hallucinated facts or identifiers | 7 medium | 3 low |
| changed | `insecure-output-handling` Model output consumed without validation | 9 medium | 6.6 medium |
| changed | `session-cross-contamination` Memory leaks between users or sessions | 8 medium | 5.9 low |
| changed | `malicious-file-input` Malicious files and documents as input | 9 medium | 7 medium |

Unchanged threats: 0
