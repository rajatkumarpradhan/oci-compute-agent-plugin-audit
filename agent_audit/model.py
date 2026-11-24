"""Data model and export loading for the compute agent plugin audit."""

from __future__ import annotations

import json
from dataclasses import dataclass

PROD_ENVIRONMENTS = {"prod", "production"}


class ExportError(ValueError):
    """Raised when an export file is malformed."""


@dataclass(frozen=True)
class Plugin:
    name: str
    enabled: bool = False
    status: str = "STOPPED"

    def is_running(self) -> bool:
        return self.enabled and self.status.upper() == "RUNNING"


@dataclass(frozen=True)
class Instance:
    name: str
    environment: str = "development"
    lifecycle_state: str = "RUNNING"
    plugins: tuple = ()

    def is_production(self) -> bool:
        return self.environment.lower() in PROD_ENVIRONMENTS

    def is_active(self) -> bool:
        return self.lifecycle_state.upper() != "TERMINATED"

    def plugin(self, name: str):
        for p in self.plugins:
            if p.name.lower() == name.lower():
                return p
        return None


def load_export(path: str):
    """Load a synthetic instance agent plugin export. Raises ExportError."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise ExportError(f"cannot read export: {exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("instances"), list):
        raise ExportError("export must be an object with an 'instances' list")
    instances = []
    for i, raw in enumerate(data["instances"]):
        if not isinstance(raw, dict) or not raw.get("name"):
            raise ExportError(f"instances[{i}] is missing a name")
        plugins = []
        for j, praw in enumerate(raw.get("plugins", [])):
            if not isinstance(praw, dict) or not praw.get("name"):
                raise ExportError(f"instances[{i}].plugins[{j}] is missing a name")
            plugins.append(Plugin(
                name=str(praw["name"]),
                enabled=bool(praw.get("enabled", False)),
                status=str(praw.get("status", "STOPPED")),
            ))
        instances.append(Instance(
            name=str(raw["name"]),
            environment=str(raw.get("environment", "development")),
            lifecycle_state=str(raw.get("lifecycle_state", "RUNNING")),
            plugins=tuple(plugins),
        ))
    return instances
