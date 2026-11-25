"""Filesystem and URL boundary tests. No LLM is involved."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from boundaryguard.guard.canonical import canonicalize
from boundaryguard.guard.paths import glob_match, suspicious_form
from boundaryguard.guard.policy_engine import PolicyEngine, RunState
from boundaryguard.guard.urls import parse_url
from boundaryguard.models.core import Decision
from boundaryguard.tools.sandbox import FloorRefused, Sandbox, create_directory_link, safe_rmtree

from conftest import standard_policy

ALIAS_FORMS = [
    (".env::$DATA", "ntfs_stream"),
    (".env:hidden", "ntfs_stream"),
    (".env.", "trailing_dot_or_space"),
    (".env ", "trailing_dot_or_space"),
    ("secrets/API_KE~1.TXT", "short_name"),
    ("SECRET~1/api_keys.txt", "short_name"),
    ("\\\\?\\C:\\Windows\\system.ini", "unc_or_device_prefix"),
    ("\\\\.\\C:\\x", "unc_or_device_prefix"),
    ("\\\\server\\share\\x", "unc_or_device_prefix"),
    ("//server/share/x", "unc_or_device_prefix"),
    ("C:\\Windows\\win.ini", "drive_path"),
    ("C:relative.txt", "drive_path"),
    ("NUL", "device_name"),
    ("src/CON.txt", "device_name"),
    ("com1", "device_name"),
    ("a\x00b", "control_character"),
    ("a\nb", "control_character"),
    ("%2e%2e/.env", "percent_encoding"),
    ("..%2f.env", "percent_encoding"),
    ("\uff0eenv", "unicode_variant"),
    ("\uff0e\uff0e/.env", "unicode_variant"),
]


@pytest.mark.parametrize("raw,code", ALIAS_FORMS)
def test_suspicious_forms_are_flagged(raw, code):
    assert suspicious_form(raw) == code


@pytest.mark.parametrize("raw", ["src/app.py", "./src/app.py", "tests/test_app.py", "../project/src/app.py",
                                 "src\\app.py", "/project/README.md", "a.b.c/d_e-f.txt"])
def test_ordinary_paths_are_not_flagged(raw):
    assert suspicious_form(raw) is None


@pytest.mark.parametrize("raw", [
    ".env", "./.env", ".ENV", ".EnV", "src/../.env", "../project/.env", "/project/.env", "/project/./.env",
    "..\\project\\.env", "secrets/api_keys.txt", "SECRETS/API_KEYS.TXT", "src/../secrets/api_keys.txt",
    "../../home/dev/.ssh/id_rsa", "/home/dev/.ssh/id_rsa", "../../../../../../home/dev/.ssh/id_rsa",
    "/etc/passwd", "../etc/passwd", "/ETC/PASSWD",
    ".env::$DATA", ".env.", "secrets/API_KE~1.TXT", "%2e%2e/.env", "\uff0eenv", "C:\\Windows\\win.ini",
    "\\\\?\\C:\\x", "NUL",
])
def test_policy_blocks_every_protected_route(world, raw):
    action = canonicalize("read_file", {"path": raw}, Sandbox(world))
    result = PolicyEngine(standard_policy()).evaluate(action, RunState())
    assert result.verdict is Decision.BLOCK
    assert result.rule_id in {"PATH_PROTECTED", "PATH_SUSPICIOUS_FORM", "PATH_NOT_READABLE", "PATH_ESCAPE"}


@pytest.mark.parametrize("raw", ["src/app.py", "./README.md", "src/../README.md", "/project/config/prod_settings.yaml"])
def test_policy_allows_permitted_reads(world, raw):
    action = canonicalize("read_file", {"path": raw}, Sandbox(world))
    assert PolicyEngine(standard_policy()).evaluate(action, RunState()).verdict is Decision.ALLOW


def test_floor_clamps_traversal_at_virtual_root(world):
    resolved = Sandbox(world).resolve("../../../../../../../../etc/passwd")
    assert resolved.virtual == "/etc/passwd"
    assert resolved.inside and resolved.exists
    assert os.path.realpath(resolved.real_path).startswith(os.path.realpath(world))


@pytest.mark.parametrize("raw,expected", [
    (".env::$DATA", "/project/.env"),
    (".env.", "/project/.env"),
    (".ENV", "/project/.env"),
    ("secrets/API_KE~1.TXT", "/project/secrets/api_keys.txt"),
])
def test_floor_emulates_ntfs_aliases(world, raw, expected):
    assert Sandbox(world).resolve(raw).real_virtual == expected


@pytest.mark.parametrize("raw", ["NUL", "src/CON.txt", "a\x00b", ""])
def test_floor_refuses_devices_and_control_characters(world, raw):
    with pytest.raises(FloorRefused):
        Sandbox(world).resolve(raw)


def test_drive_paths_cannot_reach_host(world):
    host_windows = "C:\\Windows\\win.ini"
    resolved = Sandbox(world).resolve(host_windows)
    assert resolved.inside and not resolved.exists
    assert resolved.real_path.startswith(os.path.realpath(world))


def _link_or_skip(link: Path, target: Path) -> str:
    try:
        return create_directory_link(str(link), str(target))
    except OSError as exc:
        pytest.skip(f"Directory links unavailable here: {exc}")


def test_link_inside_sandbox_is_evaluated_at_its_real_target(world):
    _link_or_skip(world / "project" / "vendor_keys", world / "home" / "dev" / ".ssh")
    sandbox = Sandbox(world)
    resolved = sandbox.resolve("vendor_keys/id_rsa")
    assert resolved.virtual == "/project/vendor_keys/id_rsa"
    assert resolved.real_virtual == "/home/dev/.ssh/id_rsa"
    action = canonicalize("read_file", {"path": "vendor_keys/id_rsa"}, sandbox)
    result = PolicyEngine(standard_policy()).evaluate(action, RunState())
    assert result.verdict is Decision.BLOCK and result.rule_id == "PATH_PROTECTED"


def test_link_out_of_sandbox_is_refused_by_floor_and_policy(world, tmp_path):
    _link_or_skip(world / "project" / "escape", tmp_path / "host_outside")
    sandbox = Sandbox(world)
    resolved = sandbox.resolve("escape/sentinel.txt")
    assert resolved.inside is False and resolved.real_path is None
    action = canonicalize("read_file", {"path": "escape/sentinel.txt"}, sandbox)
    result = PolicyEngine(standard_policy()).evaluate(action, RunState())
    assert result.verdict is Decision.BLOCK and result.rule_id == "PATH_ESCAPE"


def test_symlink_when_privileges_allow(world, tmp_path):
    link = world / "project" / "sym"
    try:
        os.symlink(tmp_path / "host_outside", link, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"True symlinks need elevated privileges on this machine: {exc}")
    assert Sandbox(world).resolve("sym/sentinel.txt").inside is False


def test_cleanup_does_not_follow_links(world, tmp_path):
    _link_or_skip(world / "project" / "escape", tmp_path / "host_outside")
    safe_rmtree(world, tmp_path)
    assert not world.exists()
    assert (tmp_path / "host_outside" / "sentinel.txt").read_text() == "HOST_SECRET"


def test_cleanup_refuses_paths_outside_parent(world, tmp_path):
    with pytest.raises(ValueError):
        safe_rmtree(tmp_path / "host_outside", world)
    assert (tmp_path / "host_outside" / "sentinel.txt").exists()


@pytest.mark.parametrize("pattern,path,expected", [
    ("**/.env*", "/project/.env", True),
    ("**/.env*", "/project/sub/.env.local", True),
    ("**/.env*", "/project/env.txt", False),
    ("/home/**", "/home", True),
    ("/home/**", "/home/dev/x", True),
    ("/home/**", "/homestead/x", False),
    ("/project/src/**", "/project/src/a/b.py", True),
    ("/project/src/**", "/project/srcx/a.py", False),
    ("/project/*.md", "/project/README.md", True),
    ("/project/*.md", "/project/docs/README.md", False),
    ("**/SECRETS/**", "/project/secrets/a.txt", True),
])
def test_glob_semantics(pattern, path, expected):
    assert glob_match(pattern, path) is expected


@pytest.mark.parametrize("url,violation", [
    ("ftp://api.internal.test/x", "bad_scheme"),
    ("file:///etc/passwd", "bad_scheme"),
    ("gopher://x.test", "bad_scheme"),
    ("javascript:alert(1)", "bad_scheme"),
    ("http://api.internal.test@evil.test/", "userinfo_in_url"),
    ("http://user:pw@api.internal.test/", "userinfo_in_url"),
    ("http://127.0.0.1/", "ip_literal"),
    ("http://[::1]/", "ip_literal"),
    ("http://2130706433/", "ip_literal"),
    ("http://0x7f.0.0.1/", "ip_literal"),
    ("http://017700000001/", "ip_literal"),
    ("http://169.254.169.254/latest/meta-data", "ip_literal"),
    ("http://api%2einternal.test/", "encoded_or_unicode_host"),
    ("http://xn--80ak6aa92e.test/", "punycode_host"),
    ("http://api.internal.test./", "malformed_host"),
    ("http://api.internal.test:8080/", "non_default_port"),
    ("http://api.internal.test\\@evil.test/", "illegal_character"),
    ("http://api internal.test/", "illegal_character"),
    ("", "empty_url"),
])
def test_bad_urls_are_rejected(url, violation):
    assert parse_url(url).violation == violation


@pytest.mark.parametrize("url", ["http://api.internal.test.evil.test/", "http://evil.test/api.internal.test",
                                 "https://notapi.internal.test/", "https://api.internal.test.attacker.test/x?y=1"])
def test_lookalike_hosts_fail_the_exact_allowlist(world, url):
    action = canonicalize("http_request", {"url": url, "method": "GET", "body": ""}, Sandbox(world))
    result = PolicyEngine(standard_policy()).evaluate(action, RunState())
    assert result.rule_id == "NET_HOST_NOT_ALLOWED"


def test_allowed_host_passes(world):
    action = canonicalize("http_request", {"url": "https://API.internal.test/v1?x=1", "method": "GET", "body": ""}, Sandbox(world))
    assert PolicyEngine(standard_policy()).evaluate(action, RunState()).verdict is Decision.ALLOW
