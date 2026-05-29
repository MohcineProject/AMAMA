"""Load and register in-process forensic modules from orchestrator config."""

from __future__ import annotations

import importlib
from typing import Any

from backbone.contracts.base_model import BaseForensicModule


def import_module_class(dotted_path: str) -> type[BaseForensicModule]:
    """Import a module class from a dotted path (e.g. models.disk.disk_module.DiskModule)."""
    if "." not in dotted_path:
        raise ValueError(f"Invalid module class path: {dotted_path!r}")
    module_name, class_name = dotted_path.rsplit(".", 1)
    module = importlib.import_module(module_name)
    cls = getattr(module, class_name)
    if not isinstance(cls, type) or not issubclass(cls, BaseForensicModule):
        raise TypeError(f"{dotted_path!r} must inherit BaseForensicModule")
    return cls


def load_modules(config: dict[str, Any]) -> dict[str, BaseForensicModule]:
    """
    Instantiate modules listed under config['modules'].

    Each entry:
      class: "package.module.ClassName"   # required
      kwargs: {}                          # optional constructor args
    """
    registry: dict[str, BaseForensicModule] = {}
    for entry in config.get("modules", []):
        if not entry:
            continue
        dotted = entry.get("class")
        if not dotted:
            raise ValueError("Each module entry must include a 'class' import path")
        cls = import_module_class(dotted)
        kwargs = entry.get("kwargs") or {}
        instance = cls(**kwargs)
        if instance.module_id in registry:
            raise ValueError(f"Duplicate module_id: {instance.module_id!r}")
        registry[instance.module_id] = instance
    return registry
