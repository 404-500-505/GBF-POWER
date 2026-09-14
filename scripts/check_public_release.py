#!/usr/bin/env python3
"""Fail-closed checks for files that Git would include in a public release."""

from __future__ import annotations

import argparse
import ipaddress
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


@dataclass(frozen=True, slots=True)
class Finding:
    path: str
    rule: str
    message: str


class ReleaseCheckError(Exception):
    def __init__(self, finding: Finding) -> None:
        super().__init__(finding.message)
        self.finding = finding


PRIVATE_KEY_HEADER = re.compile(r"-----BEGIN [A-Z0-9 -]*PRIVATE KEY-----")
ACTIVATION_CODE = re.compile(r"GBF-[0-9a-fA-F]{32}(?![0-9a-fA-F])")
IPV4_CANDIDATE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
EMAIL_ADDRESS = re.compile(
    r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?![A-Za-z0-9.-])"
)
WINDOWS_USER_PATH = re.compile(
    r"(?<![A-Za-z0-9])C:\\+Users\\+[^\\/\s\"']+", re.IGNORECASE
)
EXAMPLE_EMAIL_DOMAINS = ("example.com", "example.net", "example.org", "example.invalid")
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
FORBIDDEN_FILENAMES = frozenset({"state.json", "known_hosts"})
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
MAX_FILE_SIZE = 2 * 1024 * 1024
MAX_TEXT_SIZE = 1024 * 1024
ALLOWED_TEXT_CONTROLS = frozenset(b"\t\n\r")


def is_forbidden_filename(name: str) -> bool:
    folded = name.casefold()
    return (
        folded in FORBIDDEN_FILENAMES
        or folded.startswith(FORBIDDEN_FILENAME_PREFIXES)
        or (folded.startswith("deployment-history-") and folded.endswith(".json"))
    )


DOCUMENTATION_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
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


def contains_real_email(content: str) -> bool:
    for match in EMAIL_ADDRESS.finditer(content):
        domain = match.group(1).casefold()
        if not any(
            domain == example or domain.endswith("." + example)
            for example in EXAMPLE_EMAIL_DOMAINS
        ):
            return True
    return False


def has_binary_control_bytes(content: bytes) -> bool:
    return any(
        (byte < 32 and byte not in ALLOWED_TEXT_CONTROLS) or byte == 127
        for byte in content
    )


def path_has_link_or_reparse_point(repo: Path, relative: Path) -> bool:
    cursor = repo
    for part in relative.parts:
        cursor = cursor / part
        try:
            status = cursor.lstat()
        except OSError as error:
            raise ReleaseCheckError(
                Finding(
                    relative.as_posix(),
                    "file-read-failed",
                    "release candidate could not be read",
                )
            ) from error
        attributes = getattr(status, "st_file_attributes", 0)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        if stat.S_ISLNK(status.st_mode) or attributes & reparse_flag:
            return True
    return False


def git_candidates(repo: Path) -> list[Path]:
    try:
        completed = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=repo,
            capture_output=True,
            check=False,
        )
    except OSError as error:
        raise ReleaseCheckError(
            Finding(".", "git-unavailable", "Git could not be started")
        ) from error
    if completed.returncode != 0:
        raise ReleaseCheckError(
            Finding(".", "git-command-failed", "Git candidate enumeration failed")
        )
    try:
        names = completed.stdout.decode("utf-8").split("\0")
    except UnicodeDecodeError as error:
        raise ReleaseCheckError(
            Finding(".", "git-output-invalid", "Git returned an invalid candidate list")
        ) from error

    candidates: list[Path] = []
    for name in names:
        if not name:
            continue
        relative = Path(name)
        if relative.is_absolute() or relative.drive or ".." in relative.parts:
            raise ReleaseCheckError(
                Finding(".", "path-escape", "Git candidate escapes the repository root")
            )
        candidates.append(repo / relative)
    return candidates


def check_repository(repo: Path) -> list[Finding]:
    findings: list[Finding] = []
    resolved_repo = repo.resolve()
    for candidate in git_candidates(repo):
        relative = candidate.relative_to(repo)
        relative_text = relative.as_posix()
        has_link = path_has_link_or_reparse_point(repo, relative)
        if has_link:
            findings.append(
                Finding(
                    relative_text,
                    "symbolic-link",
                    "symbolic links are not allowed in a public release",
                )
            )
            continue
        try:
            resolved_candidate = candidate.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise ReleaseCheckError(
                Finding(relative_text, "file-read-failed", "release candidate could not be read")
            ) from error
        if not resolved_candidate.is_relative_to(resolved_repo):
            findings.append(
                Finding(
                    relative_text,
                    "path-escape",
                    "release candidate resolves outside the repository root",
                )
            )
            continue
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
                Finding(
                    relative_text,
                    "forbidden-filename",
                    "release candidate has a forbidden filename",
                )
            )
        if relative.suffix.casefold() in FORBIDDEN_EXTENSIONS:
            findings.append(
                Finding(
                    relative_text,
                    "forbidden-extension",
                    "release candidate has a forbidden extension",
                )
            )
        try:
            size = candidate.stat().st_size
        except OSError as error:
            raise ReleaseCheckError(
                Finding(relative_text, "file-read-failed", "release candidate could not be read")
            ) from error
        if size > MAX_FILE_SIZE:
            findings.append(
                Finding(
                    relative_text,
                    "oversized-file",
                    "release candidate exceeds the 2 MiB size limit",
                )
            )
            continue
        is_license_file = relative.name.casefold() == "license" or relative.name.casefold().startswith(
            "license."
        )
        if size > MAX_TEXT_SIZE and not is_license_file:
            findings.append(
                Finding(
                    relative_text,
                    "oversized-text",
                    "text release candidate exceeds the 1 MiB size limit",
                )
            )
            continue
        try:
            raw_content = candidate.read_bytes()
        except OSError as error:
            raise ReleaseCheckError(
                Finding(relative_text, "file-read-failed", "release candidate could not be read")
            ) from error
        if b"\0" in raw_content or has_binary_control_bytes(raw_content):
            findings.append(
                Finding(
                    relative_text,
                    "binary-file",
                    "unknown binary release candidate is not allowed",
                )
            )
            continue
        try:
            content = raw_content.decode("utf-8")
        except UnicodeDecodeError:
            findings.append(
                Finding(
                    relative_text,
                    "binary-file",
                    "unknown binary release candidate is not allowed",
                )
            )
            continue
        if PRIVATE_KEY_HEADER.search(content):
            findings.append(
                Finding(
                    relative_text,
                    "private-key",
                    "private key material is not allowed",
                )
            )
        if ACTIVATION_CODE.search(content):
            findings.append(
                Finding(
                    relative_text,
                    "activation-code",
                    "production activation code is not allowed",
                )
            )
        if contains_global_ipv4(content):
            findings.append(
                Finding(
                    relative_text,
                    "global-ipv4",
                    "globally routable IPv4 address is not allowed",
                )
            )
        if contains_real_email(content):
            findings.append(
                Finding(
                    relative_text,
                    "email-address",
                    "non-example email address is not allowed",
                )
            )
        if WINDOWS_USER_PATH.search(content):
            findings.append(
                Finding(
                    relative_text,
                    "windows-user-path",
                    "Windows user profile path is not allowed",
                )
            )
    return findings


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repo",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (defaults to the parent of this script directory)",
    )
    args = parser.parse_args(argv)
    try:
        repo = args.repo.resolve(strict=True)
    except (OSError, RuntimeError):
        finding = Finding(
            ".",
            "repository-unavailable",
            "repository root could not be resolved",
        )
        print(f"{finding.path}\t{finding.rule}\t{finding.message}")
        return 2
    try:
        findings = check_repository(repo)
    except ReleaseCheckError as error:
        finding = error.finding
        print(f"{finding.path}\t{finding.rule}\t{finding.message}")
        return 2
    if findings:
        for finding in findings:
            print(f"{finding.path}\t{finding.rule}\t{finding.message}")
        return 1
    print("public release check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
