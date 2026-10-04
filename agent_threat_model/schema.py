"""Input schema for agent-threat-model system descriptions.

The YAML file an operator writes is validated against the pydantic models in
this module. The same models are exported as JSON Schema to
``schema/system.schema.json`` so editors and CI can validate files without
importing the package.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

ID_PATTERN = r"^[a-z0-9][a-z0-9._-]*$"
IdStr = Annotated[str, Field(pattern=ID_PATTERN, min_length=1, max_length=64)]


class StrictModel(BaseModel):
    """Base model: unknown keys are errors so typos are caught early."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, use_enum_values=False)


class PrincipalKind(StrEnum):
    HUMAN = "human"
    SERVICE = "service"


class TrustLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Autonomy(StrEnum):
    SUGGEST = "suggest"
    ACT_WITH_APPROVAL = "act-with-approval"
    ACT = "act"


class Memory(StrEnum):
    NONE = "none"
    SESSION = "session"
    PERSISTENT = "persistent"


class ChannelKind(StrEnum):
    CHAT = "chat"
    EMAIL = "email"
    WEB = "web"
    DOCUMENT = "document"
    RAG = "rag"
    API = "api"
    FILE = "file"
    CLI = "cli"


class ChannelOrigin(StrEnum):
    USER = "user"
    THIRD_PARTY = "third-party"
    INTERNAL = "internal"


class ToolKind(StrEnum):
    READ = "read"
    WRITE = "write"
    EXEC = "exec"
    NETWORK = "network"
    PAYMENT = "payment"
    MESSAGING = "messaging"


class ToolAuth(StrEnum):
    NONE = "none"
    STATIC_KEY = "static-key"
    SHORT_LIVED = "short-lived"
    BROKERED = "brokered"


class Approval(StrEnum):
    NONE = "none"
    THRESHOLD = "threshold"
    ALWAYS = "always"


class ToolProvider(StrEnum):
    FIRST_PARTY = "first-party"
    THIRD_PARTY = "third-party"


class Sensitivity(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    REGULATED = "regulated"


SENSITIVITY_ORDER: dict[Sensitivity, int] = {
    Sensitivity.PUBLIC: 0,
    Sensitivity.INTERNAL: 1,
    Sensitivity.CONFIDENTIAL: 2,
    Sensitivity.REGULATED: 3,
}


class SystemInfo(StrictModel):
    name: str = Field(min_length=1, description="Human readable name of the system.")
    description: str = Field(default="", description="What the system does, in one paragraph.")
    owner: str = Field(default="", description="Team or person accountable for the system.")


class Principal(StrictModel):
    id: IdStr
    kind: PrincipalKind = Field(description="human or service")
    trust: TrustLevel = Field(
        description="How much the system trusts instructions from this principal."
    )
    channels: list[IdStr] = Field(
        default_factory=list,
        description="Channels this principal speaks through (used for diagrams and rules).",
    )
    description: str = ""


class Agent(StrictModel):
    id: IdStr
    model_provider: str = Field(
        default="", description="Free text, for example 'hosted LLM' or 'self-hosted model'."
    )
    autonomy: Autonomy = Field(description="suggest, act-with-approval or act")
    memory: Memory = Field(default=Memory.NONE, description="none, session or persistent")
    inputs: list[IdStr] = Field(default_factory=list, description="Channel ids the agent reads.")
    tools: list[IdStr] = Field(default_factory=list, description="Tool ids the agent may call.")
    delegates_to: list[IdStr] = Field(
        default_factory=list, description="Other agent ids this agent can send tasks to."
    )
    model_pinned: bool = Field(
        default=False, description="True when the model version is pinned and change-controlled."
    )
    description: str = ""


class Channel(StrictModel):
    id: IdStr
    kind: ChannelKind
    trusted: bool = Field(description="False when content may be attacker controlled.")
    origin: ChannelOrigin = Field(description="user, third-party or internal")
    description: str = ""


class Tool(StrictModel):
    id: IdStr
    kind: ToolKind
    target: str = Field(
        default="",
        description="What the tool touches. A data store id here links the tool to that store.",
    )
    scope: str = Field(default="", description="Free text describing the permission scope.")
    auth: ToolAuth = Field(description="none, static-key, short-lived or brokered")
    approval: Approval = Field(default=Approval.NONE, description="none, threshold or always")
    sandboxed: bool = False
    provider: ToolProvider = Field(
        default=ToolProvider.FIRST_PARTY,
        description="third-party when the tool and its description come from an external source.",
    )
    pinned: bool = Field(
        default=False, description="True when the tool version or description hash is pinned."
    )
    data_stores: list[IdStr] = Field(
        default_factory=list, description="Data store ids this tool can reach."
    )
    description: str = ""


class DataStore(StrictModel):
    id: IdStr
    sensitivity: Sensitivity
    description: str = ""


class AgentSystem(StrictModel):
    """Root document."""

    system: SystemInfo
    principals: list[Principal] = Field(default_factory=list)
    agents: list[Agent] = Field(min_length=1)
    channels: list[Channel] = Field(default_factory=list)
    tools: list[Tool] = Field(default_factory=list)
    data_stores: list[DataStore] = Field(default_factory=list)
    controls: list[IdStr] = Field(
        default_factory=list, description="Ids of catalogue controls already in place."
    )

    @model_validator(mode="after")
    def _check_references(self) -> AgentSystem:
        seen: dict[str, str] = {}
        for group_name, group in (
            ("principal", self.principals),
            ("agent", self.agents),
            ("channel", self.channels),
            ("tool", self.tools),
            ("data_store", self.data_stores),
        ):
            for element in group:
                if element.id in seen:
                    raise ValueError(
                        f"duplicate id '{element.id}' ({seen[element.id]} and {group_name})"
                    )
                seen[element.id] = group_name

        channel_ids = {c.id for c in self.channels}
        tool_ids = {t.id for t in self.tools}
        agent_ids = {a.id for a in self.agents}
        store_ids = {s.id for s in self.data_stores}
        problems: list[str] = []
        for agent in self.agents:
            for ref in agent.inputs:
                if ref not in channel_ids:
                    problems.append(f"agent '{agent.id}' input '{ref}' is not a channel id")
            for ref in agent.tools:
                if ref not in tool_ids:
                    problems.append(f"agent '{agent.id}' tool '{ref}' is not a tool id")
            for ref in agent.delegates_to:
                if ref not in agent_ids:
                    problems.append(f"agent '{agent.id}' delegates_to '{ref}' is not an agent id")
                if ref == agent.id:
                    problems.append(f"agent '{agent.id}' cannot delegate to itself")
        for principal in self.principals:
            for ref in principal.channels:
                if ref not in channel_ids:
                    problems.append(
                        f"principal '{principal.id}' channel '{ref}' is not a channel id"
                    )
        for tool in self.tools:
            for ref in tool.data_stores:
                if ref not in store_ids:
                    problems.append(f"tool '{tool.id}' data_store '{ref}' is not a data store id")
        seen_controls: set[str] = set()
        for control in self.controls:
            if control in seen_controls:
                problems.append(f"control '{control}' listed more than once")
            seen_controls.add(control)
        if problems:
            raise ValueError("; ".join(problems))
        return self

    # Convenience lookups -------------------------------------------------

    def agent(self, agent_id: str) -> Agent:
        return next(a for a in self.agents if a.id == agent_id)

    def channel(self, channel_id: str) -> Channel:
        return next(c for c in self.channels if c.id == channel_id)

    def tool(self, tool_id: str) -> Tool:
        return next(t for t in self.tools if t.id == tool_id)

    def store(self, store_id: str) -> DataStore:
        return next(s for s in self.data_stores if s.id == store_id)

    def tool_stores(self, tool: Tool) -> list[DataStore]:
        """Data stores a tool can reach: explicit links plus a target naming a store."""
        ids = list(tool.data_stores)
        if (
            tool.target
            and tool.target not in ids
            and any(s.id == tool.target for s in self.data_stores)
        ):
            ids.append(tool.target)
        return [self.store(i) for i in ids]

    def agents_using_tool(self, tool_id: str) -> list[Agent]:
        return [a for a in self.agents if tool_id in a.tools]

    def has_control(self, control_id: str) -> bool:
        return control_id in self.controls


def json_schema() -> dict[str, Any]:
    """Return the JSON Schema for the root document."""
    schema = AgentSystem.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["$id"] = (
        "https://raw.githubusercontent.com/basitalisandhu/agent-threat-model/main/"
        "schema/system.schema.json"
    )
    schema["title"] = "agent-threat-model system description"
    return schema
