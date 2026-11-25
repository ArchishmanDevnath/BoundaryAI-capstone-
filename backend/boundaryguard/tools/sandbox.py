"""The sandbox floor: a chroot-style virtual filesystem under a throwaway run_root.

The floor is always on, including for the unprotected configuration. It decides where a
path lands, never whether the agent may use it. That second question belongs to policy.

Virtual paths look like /project/src/a.py. The floor emulates what a real NTFS volume does
with alias forms (streams, trailing dots, case differences, 8.3 names), so an unprotected
agent can really fall for them, and results are the same on every operating system.
"""
from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

RESERVED_DEVICE_NAMES = {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} | {f"LPT{i}" for i in range(1, 10)}
_SHORT_NAME = re.compile(r"^(?P<stem>[^~]+)~(?P<n>\d+)(?P<ext>\.[^.]*)?$")
MAX_PATH_LEN = 1024


class FloorRefused(Exception):
    """The floor cannot map this path to anything inside the sandbox."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ResolvedPath:
    raw: str
    virtual: str  # after lexical normalization and alias emulation, before following links
    real_virtual: str | None  # after following links, None if the target left run_root
    real_path: str | None  # real OS path, None if the target left run_root
    inside: bool
    exists: bool


def is_link_like(path: str) -> bool:
    return os.path.islink(path) or os.path.isjunction(path)


class Sandbox:
    def __init__(self, run_root: str | Path, cwd: str = "/project"):
        self.run_root = os.path.realpath(str(run_root))
        self.cwd = cwd

    # -- lexical mapping -------------------------------------------------
    def _components(self, raw: str) -> list[str]:
        if not isinstance(raw, str) or not raw:
            raise FloorRefused("empty_path")
        if len(raw) > MAX_PATH_LEN:
            raise FloorRefused("path_too_long")
        if any(ord(c) < 32 for c in raw):
            raise FloorRefused("control_character")
        path = raw.replace("\\", "/")
        # Device-namespace prefixes such as \\?\ and \\.\ are dropped, then the remainder maps normally.
        path = re.sub(r"^//[?.]/", "/", path)
        drive = re.match(r"^/?([A-Za-z]):(.*)$", path)
        if drive:
            # A Windows drive maps to /<drive> in the virtual tree, where nothing exists.
            path = f"/{drive.group(1).lower()}/{drive.group(2)}"
        if not path.startswith("/"):
            path = f"{self.cwd}/{path}"
        parts: list[str] = []
        for comp in path.split("/"):
            if comp in ("", "."):
                continue
            if comp == "..":
                if parts:
                    parts.pop()
                continue
            comp = comp.split(":", 1)[0]  # NTFS stream: name:stream:$DATA addresses the file name
            stripped = comp.rstrip(". ")  # NTFS ignores trailing dots and spaces
            if stripped == "":
                continue
            if stripped.split(".", 1)[0].upper() in RESERVED_DEVICE_NAMES:
                raise FloorRefused("device_name")
            parts.append(stripped)
        return parts

    def _match_entry(self, directory: str, name: str) -> str | None:
        """Find a directory entry the way NTFS would: exact, then case-insensitive, then 8.3."""
        try:
            entries = sorted(os.listdir(directory))
        except OSError:
            return None
        if name in entries:
            return name
        lowered = name.lower()
        for entry in entries:
            if entry.lower() == lowered:
                return entry
        short = _SHORT_NAME.match(name)
        if short:
            stem = short.group("stem").lower()
            ext = (short.group("ext") or "").lower()
            matches = [e for e in entries if e.lower().lstrip(".").startswith(stem)
                       and (not ext or e.lower().endswith(ext))]
            index = int(short.group("n")) - 1
            if 0 <= index < len(matches):
                return matches[index]
        return None

    def resolve(self, raw: str) -> ResolvedPath:
        parts = self._components(raw)
        current = self.run_root
        actual: list[str] = []
        for idx, part in enumerate(parts):
            entry = self._match_entry(current, part)
            if entry is None:
                actual.extend(parts[idx:])
                break
            actual.append(entry)
            current = os.path.join(current, entry)
        virtual = "/" + "/".join(actual)
        joined = os.path.join(self.run_root, *actual) if actual else self.run_root
        real = os.path.realpath(joined)
        inside = real == self.run_root or real.startswith(self.run_root + os.sep)
        if not inside:
            return ResolvedPath(raw, virtual, None, None, False, False)
        rel = os.path.relpath(real, self.run_root).replace(os.sep, "/")
        real_virtual = "/" if rel == "." else "/" + rel
        return ResolvedPath(raw, virtual, real_virtual, real, True, os.path.lexists(real))

    # -- workspace snapshots ----------------------------------------------
    def snapshot(self) -> dict[str, str]:
        """Hash every regular file below run_root without following links."""
        out: dict[str, str] = {}
        for dirpath, dirnames, filenames in os.walk(self.run_root, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if not is_link_like(os.path.join(dirpath, d)))
            for name in sorted(filenames):
                full = os.path.join(dirpath, name)
                if is_link_like(full):
                    continue
                rel = "/" + os.path.relpath(full, self.run_root).replace(os.sep, "/")
                with open(full, "rb") as fh:
                    out[rel] = hashlib.sha256(fh.read()).hexdigest()
        return out

    def read_virtual(self, virtual: str) -> str | None:
        """Read a file for the post-run completion check. Not reachable from the agent."""
        try:
            resolved = self.resolve(virtual)
        except FloorRefused:
            return None
        if not resolved.inside or not resolved.real_path or not os.path.isfile(resolved.real_path):
            return None
        with open(resolved.real_path, encoding="utf-8", errors="replace") as fh:
            return fh.read()


def safe_rmtree(path: str | Path, allowed_parent: str | Path) -> None:
    """Delete a run directory. Links are unlinked, never followed. Refuses to leave allowed_parent."""
    target = os.path.realpath(str(path))
    parent = os.path.realpath(str(allowed_parent))
    if not target.startswith(parent + os.sep):
        raise ValueError(f"refusing to delete {target}: outside {parent}")
    _remove_tree(target)


def _remove_tree(directory: str) -> None:
    for entry in os.scandir(directory):
        full = entry.path
        if os.path.isjunction(full):
            os.rmdir(full)  # removes the junction only
        elif entry.is_symlink():
            if os.path.isdir(full) and os.name == "nt":
                os.rmdir(full)
            else:
                os.unlink(full)
        elif entry.is_dir(follow_symlinks=False):
            _remove_tree(full)
        else:
            try:
                os.unlink(full)
            except PermissionError:
                os.chmod(full, stat.S_IWRITE)
                os.unlink(full)
    os.rmdir(directory)


def create_directory_link(link_path: str, target_path: str) -> str:
    """Create a directory link. Symlink first, then a Windows junction. Returns the kind created."""
    try:
        os.symlink(target_path, link_path, target_is_directory=os.path.isdir(target_path))
        return "symlink"
    except (OSError, NotImplementedError):
        if os.name != "nt" or not os.path.isdir(target_path):
            raise
    import _winapi

    _winapi.CreateJunction(target_path, link_path)
    return "junction"
