"""Loads the benchmark suite and builds per-run workspaces."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..config import BENCHMARK_DIR, DATA_DIR
from ..models.core import Policy, Scenario
from ..tools.sandbox import create_directory_link

_CANARY = re.compile(r"\{\{CANARY:(\w+)\}\}")
_FIXTURE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*")


def load_scenarios(directory: Path | None = None) -> list[Scenario]:
    directory = directory or BENCHMARK_DIR / "scenarios"
    scenarios: list[Scenario] = []
    for path in sorted(directory.glob("*.yaml")):
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
        scenarios.extend(Scenario.model_validate(item) for item in data)
    ids = [s.id for s in scenarios]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate scenario ids.")
    return scenarios


EXTERNAL_SUITE = DATA_DIR / "splits" / "injecagent_external_test.jsonl"


def load_external_scenarios(path: Path | None = None) -> list[Scenario]:
    """The adapted InjecAgent cases. Produced by scripts/prepare_data.py, never used for training or tuning."""
    path = path or EXTERNAL_SUITE
    if not path.is_file():
        raise ValueError("The external benchmark has not been prepared. Run scripts/prepare_data.py first.")
    with path.open(encoding="utf-8") as fh:
        return [Scenario.model_validate_json(line) for line in fh if line.strip()]


def load_suite(suite: str = "internal") -> list[Scenario]:
    if suite == "internal":
        return load_scenarios()
    if suite == "injecagent":
        return load_external_scenarios()
    raise ValueError(f"Unknown scenario suite '{suite}'.")


def suite_hash(scenarios: list[Scenario]) -> str:
    body = json.dumps([s.model_dump(mode="json") for s in scenarios], sort_keys=True)
    digest = hashlib.sha256(body.encode())
    fixtures = BENCHMARK_DIR / "fixtures"
    if fixtures.is_dir():
        for path in sorted(p for p in fixtures.rglob("*") if p.is_file()):
            digest.update(path.relative_to(fixtures).as_posix().encode())
            digest.update(path.read_bytes().replace(b"\r\n", b"\n"))
    return digest.hexdigest()


def _deep_merge(base: dict[str, Any], overrides: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def load_benchmark_policy(name: str, overrides: dict[str, Any] | None = None) -> Policy:
    path = BENCHMARK_DIR / "policies" / f"{name}.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return Policy.model_validate(_deep_merge(data, overrides or {}))


def list_benchmark_policies() -> list[Policy]:
    return [load_benchmark_policy(p.stem) for p in sorted((BENCHMARK_DIR / "policies").glob("*.yaml"))]


def list_fixtures() -> list[str]:
    fixtures = BENCHMARK_DIR / "fixtures"
    return sorted(p.name for p in fixtures.iterdir() if p.is_dir() and not p.name.startswith("_") and p.name != "app_workspace")


class LinkUnavailable(Exception):
    """The platform refused to create a link a scenario needs."""


@dataclass
class Workspace:
    root: Path
    canaries: set[str]


def canary_token(seed: int, scenario_id: str, name: str) -> str:
    return "BG_CANARY_" + hashlib.sha256(f"{seed}|{scenario_id}|{name}".encode()).hexdigest()[:20]


def build_workspace(root: Path, fixture: str, scenario_id: str, seed: int,
                    overlays: dict[str, str] | None = None, links: list[Any] | None = None) -> Workspace:
    """Create run_root: the fixture as /project, plus decoy credentials outside it."""
    fixtures = BENCHMARK_DIR / "fixtures"
    source = fixtures / fixture
    if not _FIXTURE_NAME.fullmatch(fixture) or not source.is_dir():
        raise ValueError(f"Unknown fixture '{fixture}'.")
    root.mkdir(parents=True)
    shutil.copytree(fixtures / "_outside", root, dirs_exist_ok=True)
    shutil.copytree(source, root / "project")

    for rel, content in (overlays or {}).items():
        target = root / rel.lstrip("/") if rel.startswith("/") else root / "project" / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8", newline="\n")

    canaries: set[str] = set()

    def replace(match: re.Match[str]) -> str:
        token = canary_token(seed, scenario_id, match.group(1))
        canaries.add(token)
        return token

    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            path = Path(dirpath) / name
            text = path.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n")
            path.write_text(_CANARY.sub(replace, text), encoding="utf-8", newline="\n")

    for link in links or []:
        link_path = root / link.path.lstrip("/")
        link_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            create_directory_link(str(link_path), str(root / link.target.lstrip("/")))
        except OSError as exc:
            raise LinkUnavailable(str(exc)) from exc
    return Workspace(root=root, canaries=canaries)
