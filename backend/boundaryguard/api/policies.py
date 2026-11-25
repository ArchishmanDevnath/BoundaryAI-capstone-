"""Policy management. Benchmark policies are read-only, so edits cannot silently change results.

Policies are versioned and never physically deleted: runs record the hash of the policy they used, so the history has
to stay. "Delete" deactivates a policy, and "restore" makes any earlier version the active one again as a new version.
"""
from __future__ import annotations

import ipaddress
import re
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

from ..db.connection import to_json, utcnow
from ..experiments.scenarios import list_benchmark_policies
from ..models.core import Policy
from ..tools.catalog import TOOLS
from .state import AppState, get_state

router = APIRouter(prefix="/policies")

NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]*$")
METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}
HOST_PATTERN = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")
PATH_FIELDS = ("read_paths", "write_paths", "protected_paths", "approval_paths")


class PolicyWrite(BaseModel):
    name: str = Field(max_length=80)
    body: Policy

    @field_validator("name")
    @classmethod
    def _name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Give the policy a name.")
        if not NAME_PATTERN.match(value):
            raise ValueError("Use unaccented letters (A–Z), digits, spaces, dots, dashes or underscores, starting with a letter or digit.")
        return value


def _problem(message: str) -> HTTPException:
    return HTTPException(422, message)


def _validate(policy: Policy) -> None:
    """Reject rules that are syntactically valid but could never match, so a policy cannot fail silently."""
    unknown = [t for t in policy.allowed_tools + policy.prohibited_tools + policy.approval_tools if t not in TOOLS]
    if unknown:
        raise _problem(f"Unknown tools: {sorted(set(unknown))}")
    for field in PATH_FIELDS:
        for pattern in getattr(policy, field):
            if not pattern.strip():
                raise _problem(f"{field.replace('_', ' ').capitalize()}: empty entries are not allowed.")
            if not (pattern.startswith("/") or pattern.startswith("**")):
                raise _problem(f"{field.replace('_', ' ').capitalize()}: '{pattern}' must start with '/' (for example /project/src/**) "
                               "or '**' (for example **/.env*). Paths are matched against the sandbox's virtual paths.")
    for pattern in policy.prohibited_content:
        try:
            re.compile(pattern)
        except re.error as exc:
            raise _problem(f"Invalid content pattern '{pattern}': {exc}") from exc
    for host in policy.network.allowed_hosts:
        try:
            ipaddress.ip_address(host.strip("[]"))
            raise _problem(f"Allowed hosts: '{host}' is an IP address. IP addresses are always refused, so name the host instead.")
        except ValueError:
            pass
        if not HOST_PATTERN.match(host):
            raise _problem(f"Allowed hosts: '{host}' is not a host name. Write it in lower case without a scheme, port or path, "
                           "for example api.example.com.")
    bad_methods = [m for m in policy.network.allowed_methods if m not in METHODS]
    if bad_methods:
        raise _problem(f"Allowed methods: {bad_methods} are not supported. Use upper-case names from {sorted(METHODS)}.")


def _benchmark_rows() -> list[dict[str, Any]]:
    return [{"id": f"benchmark:{p.name}", "name": p.name, "version": 1, "body": p.model_dump(mode="json"),
             "hash": p.content_hash(), "active": True, "created_at": None, "read_only": True}
            for p in list_benchmark_policies()]


def _check_name_free(name: str, state: AppState) -> None:
    if name.lower() in {p.name.lower() for p in list_benchmark_policies()}:
        raise HTTPException(409, f"'{name}' is the name of a benchmark policy. Choose another name.")
    if state.db.scalar("SELECT 1 FROM policies WHERE lower(name)=lower(?) AND active=1", (name,)):
        raise HTTPException(409, "An active policy with this name already exists.")


def _insert_version(state: AppState, name: str, body: Policy, deactivate_id: str | None = None) -> str:
    new_id = uuid.uuid4().hex
    with state.db.transaction() as conn:
        version = conn.execute("SELECT COALESCE(MAX(version), 0) FROM policies WHERE name=?", (name,)).fetchone()[0] + 1
        if deactivate_id:
            conn.execute("UPDATE policies SET active=0 WHERE id=?", (deactivate_id,))
        conn.execute(
            "INSERT INTO policies (id, name, version, body, hash, active, created_at) VALUES (?,?,?,?,?,1,?)",
            (new_id, name, version, to_json(body.model_dump(mode="json")), body.content_hash(), utcnow()),
        )
    return new_id


@router.get("")
def list_policies(include_inactive: bool = False, state: AppState = Depends(get_state)) -> list[dict[str, Any]]:
    """Active policies, or with include_inactive every stored version, newest first within each name."""
    where = "" if include_inactive else " WHERE active=1"
    custom = state.db.query(f"SELECT * FROM policies{where} ORDER BY lower(name), version DESC")
    return _benchmark_rows() + [{**row, "read_only": False} for row in custom]


@router.get("/{policy_id}")
def get_policy(policy_id: str, state: AppState = Depends(get_state)) -> dict[str, Any]:
    if policy_id.startswith("benchmark:"):
        for row in _benchmark_rows():
            if row["id"] == policy_id:
                return row
        raise HTTPException(404, "Policy not found.")
    row = state.db.query_one("SELECT * FROM policies WHERE id=?", (policy_id,))
    if row is None:
        raise HTTPException(404, "Policy not found.")
    return {**row, "read_only": False}


@router.post("", status_code=201)
def create_policy(payload: PolicyWrite, state: AppState = Depends(get_state)) -> dict[str, Any]:
    body = payload.body.model_copy(update={"name": payload.name})
    _validate(body)
    _check_name_free(payload.name, state)
    return get_policy(_insert_version(state, payload.name, body), state)


@router.put("/{policy_id}")
def update_policy(policy_id: str, payload: PolicyWrite, state: AppState = Depends(get_state)) -> dict[str, Any]:
    """Saves a new version. Editing a version that is no longer active is refused, so a stale tab cannot overwrite a newer one."""
    if policy_id.startswith("benchmark:"):
        raise HTTPException(403, "Benchmark policies are read-only.")
    existing = state.db.query_one("SELECT * FROM policies WHERE id=?", (policy_id,))
    if existing is None:
        raise HTTPException(404, "Policy not found.")
    if not existing["active"]:
        raise HTTPException(409, "This version is no longer active: it was edited or deactivated elsewhere. Reload to see the current version.")
    body = payload.body.model_copy(update={"name": existing["name"]})
    _validate(body)
    if body.content_hash() == existing["hash"]:
        raise HTTPException(409, "Nothing changed, so no new version was saved.")
    return get_policy(_insert_version(state, existing["name"], body, deactivate_id=policy_id), state)


@router.post("/{policy_id}/restore")
def restore_policy(policy_id: str, state: AppState = Depends(get_state)) -> dict[str, Any]:
    """Make an earlier version current again. It is saved as a new version, so the history itself never changes."""
    if policy_id.startswith("benchmark:"):
        raise HTTPException(403, "Benchmark policies are read-only.")
    row = state.db.query_one("SELECT * FROM policies WHERE id=?", (policy_id,))
    if row is None:
        raise HTTPException(404, "Policy not found.")
    if row["active"]:
        raise HTTPException(409, "This version is already the active one.")
    current = state.db.query_one("SELECT id FROM policies WHERE name=? AND active=1", (row["name"],))
    body = Policy.model_validate(row["body"])
    return get_policy(_insert_version(state, row["name"], body, deactivate_id=current["id"] if current else None), state)


@router.delete("/{policy_id}", status_code=204)
def delete_policy(policy_id: str, state: AppState = Depends(get_state)) -> None:
    """Deactivates the policy. Its versions stay in the history, and it can be restored."""
    if policy_id.startswith("benchmark:"):
        raise HTTPException(403, "Benchmark policies are read-only.")
    cursor = state.db.execute("UPDATE policies SET active=0 WHERE id=? AND active=1", (policy_id,))
    if cursor.rowcount == 0:
        raise HTTPException(404, "No active policy with this id. It may already be deactivated.")
