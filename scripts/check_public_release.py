#!/usr/bin/env python3
"""Fail-closed checks for Git index blobs and untracked public-release files."""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


MAX_FILE_SIZE = 2 * 1024 * 1024
ALLOWED_TEXT_CONTROLS = frozenset(b"\t\n\r")


@dataclass(frozen=True, slots=True)
class Finding:
    path: str
    rule: str
    message: str


@dataclass(frozen=True, slots=True)
class Candidate:
    path: Path
    source: str
    mode: str | None = None
    object_id: str | None = None


@dataclass(frozen=True, slots=True)
class DenyRule:
    kind: str
    expression: str
    pattern: re.Pattern[str] | None = None

    def matches(self, content: str) -> bool:
        if self.kind == "literal":
            return self.expression in content
        assert self.pattern is not None
        return self.pattern.search(content) is not None


class ReleaseCheckError(Exception):
    def __init__(self, finding: Finding) -> None:
        super().__init__(finding.message)
        self.finding = finding


PRIVATE_KEY_HEADER = re.compile(r"-----BEGIN [A-Z0-9 -]*PRIVATE KEY-----")
PUTTY_PRIVATE_KEY_HEADER = "PuTTY-User" + "-Key-File-"
ACTIVATION_CODE = re.compile(r"GBF-[0-9a-fA-F]{32}(?![0-9a-fA-F])")
HIGH_CONFIDENCE_TOKEN = re.compile(
    r"(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16}|xoxb-[A-Za-z0-9-]{20,})"
)
IPV4_CANDIDATE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IPV6_CANDIDATE = re.compile(
    r"(?<![0-9A-Za-z_:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Za-z_:])"
)
EMAIL_ADDRESS = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?![A-Za-z0-9.-])"
)
URL_CREDENTIALS = re.compile(
    r"\b[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@", re.IGNORECASE
)
WINDOWS_USER_PATH = re.compile(
    r"(?<![A-Za-z0-9])C:(?:\\+|/+)Users(?:\\+|/+)([^\\/\s\"']+)", re.IGNORECASE
)
UNIX_USER_PATH = re.compile(r"(?<![A-Za-z0-9])/(?:Users|home)/([^/\s\"']+)")
EXAMPLE_EMAIL_DOMAINS = ("example.com", "example.net", "example.org", "example.invalid")
DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
)
IPV6_DOCUMENTATION_NETWORK = ipaddress.ip_network("2001:db8::/32")
FORBIDDEN_DIRECTORIES = frozenset(
    {
        "runtime",
        "live-state",
        "build",
        "dist",
        "release",
        ".go-cache",
        "go-cache",
        ".gradle",
        ".idea",
        "__pycache__",
        ".pytest_cache",
        ".venv",
    }
)
FORBIDDEN_FILENAMES = frozenset(
    {"state.json", "known_hosts", "authorized_keys", ".release-deny.local"}
)
FORBIDDEN_FILENAME_PREFIXES = ("id_ed25519", "id_rsa", "id_ecdsa")
FORBIDDEN_EXTENSIONS = frozenset(
    {
        ".key",
        ".pem",
        ".p12",
        ".pfx",
        ".jks",
        ".keystore",
        ".log",
        ".exe",
        ".msi",
        ".apk",
        ".zip",
    }
)


def is_forbidden_filename(name: str) -> bool:
    folded = name.casefold()
    is_private_env = (folded == ".env" or folded.startswith(".env.")) and not folded.endswith(
        ".example"
    )
    return (
        is_private_env
        or folded in FORBIDDEN_FILENAMES
        or folded.startswith(FORBIDDEN_FILENAME_PREFIXES)
        or (folded.startswith("deployment-history-") and folded.endswith(".json"))
    )


def contains_global_ipv4(content: str) -> bool:
    for match in IPV4_CANDIDATE.finditer(content):
        try:
            address = ipaddress.ip_address(match.group())
        except ValueError:
            continue
        if any(address in network for network in DOCUMENTATION_NETWORKS):
            continue
        if address.is_global and not address.is_multicast:
            return True
    return False


def contains_global_ipv6(content: str) -> bool:
    for match in IPV6_CANDIDATE.finditer(content):
        try:
            address = ipaddress.ip_address(match.group())
        except ValueError:
            continue
        if not isinstance(address, ipaddress.IPv6Address):
            continue
        if address in IPV6_DOCUMENTATION_NETWORK:
            continue
        if address.is_global and not address.is_multicast:
            return True
    return False


def contains_real_email(content: str) -> bool:
    for match in EMAIL_ADDRESS.finditer(content):
        domain = match.group(1).casefold()
        if not any(
            domain == example or domain.endswith("." + example)
            for example in EXAMPLE_EMAIL_DOMAINS
        ):
            return True
    return False


def contains_nonexample_user_path(content: str, pattern: re.Pattern[str]) -> bool:
    return any(match.group(1).casefold() != "deploy" for match in pattern.finditer(content))


def has_binary_control_bytes(content: bytes) -> bool:
    return any(
        (byte < 32 and byte not in ALLOWED_TEXT_CONTROLS) or byte == 127
        for byte in content
    )


def release_error(path: Path | str, rule: str, message: str) -> ReleaseCheckError:
    path_text = path.as_posix() if isinstance(path, Path) else path
    return ReleaseCheckError(Finding(path_text, rule, message))


def run_git(repo: Path, arguments: Sequence[str], message: str) -> bytes:
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=repo,
            capture_output=True,
            check=False,
        )
    except OSError as error:
        raise release_error(".", "git-unavailable", "Git could not be started") from error
    if completed.returncode != 0:
        raise release_error(".", "git-command-failed", message)
    return completed.stdout


def decode_git_text(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise release_error(".", "git-output-invalid", "Git returned invalid UTF-8 output") from error


def validate_relative_path(name: str) -> Path:
    relative = Path(name)
    if relative.is_absolute() or relative.drive or ".." in relative.parts:
        raise release_error(".", "path-escape", "Git candidate escapes the repository root")
    return relative


def verify_git_top_level(repo: Path) -> None:
    raw_top_level = run_git(
        repo,
        ["rev-parse", "--show-toplevel"],
        "Git top-level discovery failed",
    )
    top_level_text = decode_git_text(raw_top_level).strip()
    try:
        top_level = Path(top_level_text).resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise release_error(
            ".", "git-top-level-invalid", "Git returned an invalid top-level path"
        ) from error
    if os.path.normcase(str(top_level)) != os.path.normcase(str(repo)):
        raise release_error(
            ".", "repository-not-top-level", "repository argument is not the Git top level"
        )


def git_candidates(repo: Path) -> list[Candidate]:
    index_output = run_git(
        repo,
        ["ls-files", "--stage", "-z"],
        "Git index enumeration failed",
    )
    untracked_output = run_git(
        repo,
        ["ls-files", "--others", "--exclude-standard", "-z"],
        "Git untracked-file enumeration failed",
    )

    candidates: list[Candidate] = []
    for record in decode_git_text(index_output).split("\0"):
        if not record:
            continue
        try:
            metadata, name = record.split("\t", 1)
            mode, object_id, _stage_number = metadata.split(" ")
        except ValueError as error:
            raise release_error(".", "git-output-invalid", "Git returned an invalid index entry") from error
        if not re.fullmatch(r"[0-9a-f]{40,64}", object_id):
            raise release_error(
                ".", "git-output-invalid", "Git returned an invalid object identifier"
            )
        candidates.append(Candidate(validate_relative_path(name), "index", mode, object_id))

    for name in decode_git_text(untracked_output).split("\0"):
        if name:
            candidates.append(Candidate(validate_relative_path(name), "worktree"))
    return candidates


def index_tree_oid(repo: Path) -> str:
    object_id = decode_git_text(
        run_git(repo, ["write-tree"], "Git index identity check failed")
    ).strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", object_id):
        raise release_error(".", "git-output-invalid", "Git returned an invalid tree identifier")
    return object_id


def read_index_blob(repo: Path, candidate: Candidate) -> bytes:
    assert candidate.object_id is not None
    try:
        process = subprocess.Popen(
            ["git", "cat-file", "blob", candidate.object_id],
            cwd=repo,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError as error:
        raise release_error(candidate.path, "git-unavailable", "Git could not be started") from error
    assert process.stdout is not None
    try:
        raw_content = process.stdout.read(MAX_FILE_SIZE + 1)
    except OSError as error:
        process.kill()
        process.wait()
        raise release_error(
            candidate.path, "git-command-failed", "Git index blob could not be read"
        ) from error
    if len(raw_content) > MAX_FILE_SIZE:
        process.kill()
        process.wait()
        return raw_content
    if process.wait() != 0:
        raise release_error(
            candidate.path, "git-command-failed", "Git index blob could not be read"
        )
    return raw_content


def path_has_link_or_reparse_point(repo: Path, relative: Path) -> bool:
    cursor = repo
    for part in relative.parts:
        cursor = cursor / part
        try:
            status = cursor.lstat()
        except OSError as error:
            raise release_error(
                relative, "file-read-failed", "release candidate could not be read"
            ) from error
        attributes = getattr(status, "st_file_attributes", 0)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        if stat.S_ISLNK(status.st_mode) or attributes & reparse_flag:
            return True
    return False


def same_file_state(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    )


def read_worktree_candidate(repo: Path, relative: Path) -> tuple[bytes | None, Finding | None]:
    relative_text = relative.as_posix()
    candidate = repo / relative
    if path_has_link_or_reparse_point(repo, relative):
        return None, Finding(
            relative_text,
            "symbolic-link",
            "symbolic links and reparse points are not allowed in a public release",
        )
    try:
        resolved_candidate = candidate.resolve(strict=True)
        before_path = candidate.lstat()
    except (OSError, RuntimeError) as error:
        raise release_error(
            relative, "file-read-failed", "release candidate could not be read"
        ) from error
    if not resolved_candidate.is_relative_to(repo):
        return None, Finding(
            relative_text,
            "path-escape",
            "release candidate resolves outside the repository root",
        )
    if not stat.S_ISREG(before_path.st_mode):
        return None, Finding(
            relative_text,
            "special-file",
            "non-regular files are not allowed in a public release",
        )

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(candidate, flags)
    except OSError as error:
        raise release_error(
            relative, "file-read-failed", "release candidate could not be read"
        ) from error
    try:
        before_handle = os.fstat(descriptor)
        if not stat.S_ISREG(before_handle.st_mode):
            return None, Finding(
                relative_text,
                "special-file",
                "non-regular files are not allowed in a public release",
            )
        chunks: list[bytes] = []
        remaining = MAX_FILE_SIZE + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw_content = b"".join(chunks)
        after_handle = os.fstat(descriptor)
    except OSError as error:
        raise release_error(
            relative, "file-read-failed", "release candidate could not be read"
        ) from error
    finally:
        os.close(descriptor)

    try:
        after_path = candidate.stat()
        no_link_after = not path_has_link_or_reparse_point(repo, relative)
        resolved_after = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise release_error(
            relative, "file-changed", "release candidate changed while being read"
        ) from error
    if (
        not same_file_state(before_handle, after_handle)
        or not same_file_state(before_path, after_path)
        or (before_handle.st_dev, before_handle.st_ino) != (after_path.st_dev, after_path.st_ino)
        or not no_link_after
        or resolved_after != resolved_candidate
    ):
        raise release_error(relative, "file-changed", "release candidate changed while being read")
    return raw_content, None


def load_local_deny_rules(repo: Path) -> list[DenyRule]:
    relative = Path(".release-deny.local")
    deny_path = repo / relative
    try:
        deny_path.lstat()
    except FileNotFoundError:
        return []
    except OSError as error:
        raise release_error(
            ".", "local-deny-unavailable", "local release deny file could not be read"
        ) from error
    try:
        raw_content, finding = read_worktree_candidate(repo, relative)
    except ReleaseCheckError as error:
        raise release_error(
            ".", "local-deny-unavailable", "local release deny file could not be read"
        ) from error
    if finding is not None or raw_content is None or len(raw_content) > MAX_FILE_SIZE:
        raise release_error(
            ".", "local-deny-unavailable", "local release deny file could not be read"
        )
    if b"\0" in raw_content or has_binary_control_bytes(raw_content):
        raise release_error(
            ".", "local-deny-invalid", "local release deny file must contain text rules"
        )
    try:
        content = raw_content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise release_error(
            ".", "local-deny-invalid", "local release deny file must be UTF-8"
        ) from error

    rules: list[DenyRule] = []
    for line in content.splitlines():
        if not line or line.startswith("#"):
            continue
        kind, separator, expression = line.partition(":")
        if separator != ":" or kind not in {"literal", "regex"} or not expression:
            raise release_error(
                ".", "local-deny-invalid", "local release deny file has an invalid rule"
            )
        if kind == "literal":
            rules.append(DenyRule(kind, expression))
            continue
        try:
            pattern = re.compile(expression)
        except re.error as error:
            raise release_error(
                ".", "local-deny-invalid", "local release deny file has an invalid regex"
            ) from error
        rules.append(DenyRule(kind, expression, pattern))
    return rules


def path_findings(relative: Path, mode: str | None) -> list[Finding]:
    relative_text = relative.as_posix()
    findings: list[Finding] = []
    if mode == "120000":
        findings.append(
            Finding(relative_text, "symbolic-link", "symbolic links are not allowed in a public release")
        )
    elif mode is not None and mode not in {"100644", "100755"}:
        findings.append(
            Finding(relative_text, "special-file", "non-regular index entries are not allowed")
        )
    if any(part.casefold() in FORBIDDEN_DIRECTORIES for part in relative.parts[:-1]):
        findings.append(
            Finding(
                relative_text,
                "forbidden-directory",
                "release candidate is inside a forbidden directory",
            )
        )
    if is_forbidden_filename(relative.name):
        findings.append(
            Finding(relative_text, "forbidden-filename", "release candidate has a forbidden filename")
        )
    if relative.suffix.casefold() in FORBIDDEN_EXTENSIONS:
        findings.append(
            Finding(relative_text, "forbidden-extension", "release candidate has a forbidden extension")
        )
    return findings


def content_findings(
    relative: Path, raw_content: bytes, deny_rules: Sequence[DenyRule] = ()
) -> list[Finding]:
    relative_text = relative.as_posix()
    if len(raw_content) > MAX_FILE_SIZE:
        return [
            Finding(relative_text, "oversized-file", "release candidate exceeds the 2 MiB size limit")
        ]
    if b"\0" in raw_content or has_binary_control_bytes(raw_content):
        return [
            Finding(relative_text, "binary-file", "unknown binary release candidate is not allowed")
        ]
    try:
        content = raw_content.decode("utf-8")
    except UnicodeDecodeError:
        return [
            Finding(relative_text, "binary-file", "unknown binary release candidate is not allowed")
        ]

    findings: list[Finding] = []
    if PRIVATE_KEY_HEADER.search(content):
        findings.append(Finding(relative_text, "private-key", "private key material is not allowed"))
    if PUTTY_PRIVATE_KEY_HEADER in content:
        findings.append(
            Finding(relative_text, "putty-private-key", "PuTTY private key material is not allowed")
        )
    if ACTIVATION_CODE.search(content):
        findings.append(
            Finding(relative_text, "activation-code", "production activation code is not allowed")
        )
    if HIGH_CONFIDENCE_TOKEN.search(content):
        findings.append(
            Finding(
                relative_text,
                "high-confidence-token",
                "high-confidence access token is not allowed",
            )
        )
    if contains_global_ipv4(content):
        findings.append(
            Finding(relative_text, "global-ipv4", "globally routable IPv4 address is not allowed")
        )
    if contains_global_ipv6(content):
        findings.append(
            Finding(relative_text, "global-ipv6", "globally routable IPv6 address is not allowed")
        )
    if contains_real_email(content):
        findings.append(
            Finding(relative_text, "email-address", "non-example email address is not allowed")
        )
    if URL_CREDENTIALS.search(content):
        findings.append(
            Finding(relative_text, "url-credentials", "URL-embedded credentials are not allowed")
        )
    if contains_nonexample_user_path(content, WINDOWS_USER_PATH):
        findings.append(
            Finding(relative_text, "windows-user-path", "Windows user profile path is not allowed")
        )
    if contains_nonexample_user_path(content, UNIX_USER_PATH):
        findings.append(
            Finding(relative_text, "unix-user-path", "Unix user home path is not allowed")
        )
    if any(rule.matches(content) for rule in deny_rules):
        findings.append(
            Finding(relative_text, "local-deny", "content matches a local release deny rule")
        )
    return findings


def check_repository(repo: Path) -> list[Finding]:
    findings: list[Finding] = []
    verify_git_top_level(repo)
    deny_rules = load_local_deny_rules(repo)
    initial_index_tree = index_tree_oid(repo)
    for candidate in git_candidates(repo):
        candidate_path_findings = path_findings(candidate.path, candidate.mode)
        findings.extend(candidate_path_findings)
        if any(item.rule in {"symbolic-link", "special-file"} for item in candidate_path_findings):
            continue
        if candidate.source == "index":
            raw_content = read_index_blob(repo, candidate)
        else:
            raw_content, worktree_finding = read_worktree_candidate(repo, candidate.path)
            if worktree_finding is not None:
                findings.append(worktree_finding)
                continue
            assert raw_content is not None
        findings.extend(content_findings(candidate.path, raw_content, deny_rules))
    if index_tree_oid(repo) != initial_index_tree:
        raise release_error(".", "index-changed", "Git index changed during the release check")
    return findings


def escape_field(value: str) -> str:
    return value.encode("ascii", "backslashreplace").decode("ascii").replace("\t", "\\t").replace(
        "\r", "\\r"
    ).replace("\n", "\\n")


def print_finding(finding: Finding) -> None:
    print(
        "\t".join(
            escape_field(value) for value in (finding.path, finding.rule, finding.message)
        )
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=(
            "Optional ignored .release-deny.local rules use literal:<value> or "
            "regex:<pattern>, one UTF-8 rule per line."
        ),
    )
    parser.add_argument(
        "--repo",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="Git repository top level (defaults to the parent of this script directory)",
    )
    args = parser.parse_args(argv)
    try:
        repo = args.repo.resolve(strict=True)
    except (OSError, RuntimeError):
        print_finding(Finding(".", "repository-unavailable", "repository root could not be resolved"))
        return 2
    try:
        findings = check_repository(repo)
    except ReleaseCheckError as error:
        print_finding(error.finding)
        return 2
    if findings:
        for finding in findings:
            print_finding(finding)
        return 1
    print("public release check passed")
    return 0


def cli() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="backslashreplace")
    try:
        return main()
    except Exception:
        print_finding(Finding(".", "internal-error", "public release check failed unexpectedly"))
        return 2


if __name__ == "__main__":
    raise SystemExit(cli())
