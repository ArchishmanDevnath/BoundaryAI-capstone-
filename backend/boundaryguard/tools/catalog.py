"""The tool catalog: argument schemas, shown to LLMs and validated at the gateway."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError


class _Args(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class PathArgs(_Args):
    path: str = Field(description="Path, relative to /project or absolute in the virtual filesystem")


class WriteArgs(_Args):
    path: str = Field(description="Path to write")
    content: str = Field(description="Complete new file content")


class RunTestsArgs(_Args):
    target: str = Field(default="tests", description="Test file or directory")


class HttpArgs(_Args):
    url: str = Field(description="Full http or https URL")
    method: Literal["GET", "POST", "PUT", "DELETE", "PATCH"] = "GET"
    body: str = Field(default="", description="Request body")


class AppArgs(_Args):
    app_tool: str = Field(description="Name of the simulated application tool")
    params: dict[str, Any] = Field(default_factory=dict, description="Tool parameters")


class ShellArgs(_Args):
    command: str = Field(description="Shell command")


TOOLS: dict[str, dict[str, Any]] = {
    "list_dir": {"args": PathArgs, "access": "read", "path_arg": "path", "description": "List a directory."},
    "read_file": {"args": PathArgs, "access": "read", "path_arg": "path", "description": "Read a text file."},
    "write_file": {"args": WriteArgs, "access": "write", "path_arg": "path", "description": "Create or replace a text file."},
    "delete_file": {"args": PathArgs, "access": "write", "path_arg": "path", "description": "Delete a file."},
    "run_tests": {"args": RunTestsArgs, "access": "read", "path_arg": "target", "description": "Run the project's approved tests."},
    "http_request": {"args": HttpArgs, "access": "network", "path_arg": None, "description": "Send an HTTP request."},
    "shell_exec": {"args": ShellArgs, "access": "exec", "path_arg": None, "description": "Run a shell command."},
    "app_call": {"args": AppArgs, "access": "app", "path_arg": None, "internal": True,
                 "description": "Call a simulated application tool, such as email or calendar. Used by the external benchmark."},
}


def validate_args(tool: str, args: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    spec = TOOLS.get(tool)
    if spec is None:
        return None, f"unknown tool '{tool}'"
    if not isinstance(args, dict):
        return None, "arguments must be an object"
    try:
        return spec["args"](**args).model_dump(), None
    except ValidationError as exc:
        first = exc.errors()[0]
        return None, f"invalid arguments: {'.'.join(str(p) for p in first['loc'])}: {first['msg']}"
    except TypeError as exc:
        return None, f"invalid arguments: {exc}"


def tool_schemas() -> list[dict[str, Any]]:
    """OpenAI- and Ollama-style tool definitions."""
    out = []
    for name, spec in TOOLS.items():
        if spec.get("internal"):
            continue
        out.append({
            "type": "function",
            "function": {
                "name": name,
                "description": spec["description"],
                "parameters": spec["args"].model_json_schema(),
            },
        })
    return out


def catalog_summary() -> list[dict[str, Any]]:
    return [
        {
            "name": name,
            "description": spec["description"],
            "access": spec["access"],
            "parameters": spec["args"].model_json_schema(),
            "simulated": name in ("run_tests", "http_request", "shell_exec", "app_call"),
        }
        for name, spec in TOOLS.items()
    ]
