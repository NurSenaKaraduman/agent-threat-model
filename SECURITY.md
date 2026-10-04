# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting on this repository (Security tab, "Report a vulnerability") rather than a public issue. Include the version, a minimal system file that reproduces the problem and what you expected to happen.

You will get an acknowledgement within 7 days and a fix or a mitigation plan within 30 days for confirmed issues. Credit is given in the release notes unless you prefer otherwise.

## Scope

agent-threat-model reads YAML you provide, evaluates deterministic rules and writes reports. It makes no network calls and never executes content from the input file or the catalogue (rules are parsed into a fixed set of named predicates; there is no `eval`). Issues of interest include YAML parsing hazards, path handling in `--output`, SARIF or HTML output that could inject content into a viewer, and dependency vulnerabilities.

Findings produced by the tool are not themselves security vulnerabilities in the tool. If the catalogue misses a threat or scores one wrongly, open a normal issue.
