"""Load and register in-process forensic modules from orchestrator config."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from typing import Any

from backbone.contracts.base_model import BaseForensicModule


def _add_module_search_path(directory: Path) -> Path:
    """Insert a module root onto sys.path so ``import disk_module`` / ``scripts.*`` work."""
    resolved = directory.resolve()
    entry = str(resolved)
    if entry not in sys.path:
        sys.path.insert(0, entry)
    return resolved


def _resolve_module_path(path: str | Path, config_dir: Path) -> Path:
    p = Path(path)
    if p.is_absolute():
        return p.resolve()
    return (config_dir / p).resolve()


def import_module_class(
    dotted_path: str,
    *,
    search_path: str | Path | None = None,
) -> type[BaseForensicModule]:
    """Import a module class from a dotted path (e.g. disk_module.DiskModule)."""
    if "." not in dotted_path:
        raise ValueError(f"Invalid module class path: {dotted_path!r}")
    if search_path is not None:
        _add_module_search_path(Path(search_path))

    module_name, class_name = dotted_path.rsplit(".", 1)
    module = importlib.import_module(module_name)
    cls = getattr(module, class_name)
    if not isinstance(cls, type) or not issubclass(cls, BaseForensicModule):
        raise TypeError(f"{dotted_path!r} must inherit BaseForensicModule")
    return cls


def load_modules(
    config: dict[str, Any],
    *,
    config_dir: Path | str | None = None,
) -> dict[str, BaseForensicModule]:
    """
    Instantiate modules listed under config['modules'].

    Each entry:
      class: "disk_module.DiskModule"   # required — importable after path is set
      path: "../Modules/Disk/..."       # optional — module root on sys.path
      kwargs: {}                        # optional constructor args

    ``path`` is resolved relative to the orchestrator config file directory
    when not absolute.
    """
    base = Path(config_dir).resolve() if config_dir else Path.cwd()
    registry: dict[str, BaseForensicModule] = {}
    for entry in config.get("modules", []):
        if not entry:
            continue
        dotted = entry.get("class")
        if not dotted:
            raise ValueError("Each module entry must include a 'class' import path")

        search_path = entry.get("path")
        if search_path:
            _add_module_search_path(_resolve_module_path(search_path, base))

        cls = import_module_class(dotted)
        kwargs = entry.get("kwargs") or {}
        instance = cls(**kwargs)
        if instance.module_id in registry:
            raise ValueError(f"Duplicate module_id: {instance.module_id!r}")
        registry[instance.module_id] = instance
    return registry
