"""Reference identifiers used by the catalogue.

OWASP Top 10 for LLM Applications 2025 ids and titles are taken from the
project's source repository
(https://github.com/OWASP/www-project-top-10-for-large-language-model-applications).
OWASP Top 10 for Agentic Applications (2026) ids and titles are taken from the
OWASP GenAI Security Project crosswalk repository
(https://github.com/GenAI-Security-Project/crosswalk, file CROSSREF.md); please
check them against the published PDF. MITRE ATLAS technique ids and names are
taken from the ATLAS data distribution (https://github.com/mitre-atlas/atlas-data,
version 5.6.0). Only ids present here may be referenced by threats; the
catalogue loader rejects anything else.
"""

OWASP_LLM_2025: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

OWASP_LLM_URL = "https://genai.owasp.org/llm-top-10/"

OWASP_AGENTIC_2026: dict[str, str] = {
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse and Exploitation",
    "ASI03": "Identity and Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory and Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Agent Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}

OWASP_AGENTIC_URL = "https://github.com/GenAI-Security-Project/crosswalk/blob/main/CROSSREF.md"

ATLAS_TECHNIQUES: dict[str, str] = {
    "AML.T0010": "AI Supply Chain Compromise",
    "AML.T0010.005": "AI Supply Chain Compromise: AI Agent Tool",
    "AML.T0011.000": "User Execution: Unsafe AI Artifacts",
    "AML.T0025": "Exfiltration via Cyber Means",
    "AML.T0029": "Denial of AI Service",
    "AML.T0034": "Cost Harvesting",
    "AML.T0034.002": "Cost Harvesting: Agentic Resource Consumption",
    "AML.T0036": "Data from Information Repositories",
    "AML.T0050": "Command and Scripting Interpreter",
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0051.000": "LLM Prompt Injection: Direct",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0053": "AI Agent Tool Invocation",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0055": "Unsecured Credentials",
    "AML.T0056": "Extract LLM System Prompt",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0060": "Publish Hallucinated Entities",
    "AML.T0066": "Retrieval Content Crafting",
    "AML.T0067": "LLM Trusted Output Components Manipulation",
    "AML.T0069.002": "Discover LLM System Information: System Prompt",
    "AML.T0070": "RAG Poisoning",
    "AML.T0071": "False RAG Entry Injection",
    "AML.T0072": "Reverse Shell",
    "AML.T0073": "Impersonation",
    "AML.T0077": "LLM Response Rendering",
    "AML.T0080.000": "AI Agent Context Poisoning: Memory",
    "AML.T0081": "Modify AI Agent Configuration",
    "AML.T0083": "Credentials from AI Agent Configuration",
    "AML.T0084": "Discover AI Agent Configuration",
    "AML.T0084.001": "Discover AI Agent Configuration: Tool Definitions",
    "AML.T0085.000": "Data from AI Services: RAG Databases",
    "AML.T0086": "Exfiltration via AI Agent Tool Invocation",
    "AML.T0092": "Manipulate User LLM Chat History",
    "AML.T0098": "AI Agent Tool Credential Harvesting",
    "AML.T0099": "AI Agent Tool Data Poisoning",
    "AML.T0101": "Data Destruction via AI Agent Tool Invocation",
    "AML.T0104": "Publish Poisoned AI Agent Tool",
    "AML.T0105": "Escape to Host",
    "AML.T0109": "AI Supply Chain Rug Pull",
    "AML.T0110": "AI Agent Tool Poisoning",
}

ATLAS_URL = "https://atlas.mitre.org/techniques/"


def atlas_url(technique_id: str) -> str:
    return f"{ATLAS_URL}{technique_id}"
