from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CHECKER = PROJECT_ROOT / "scripts" / "check_public_release.py"
SAFE_FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "safe" / "config.json"


class PublicReleaseCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary_directory.name)
        self._git("init", "--quiet")

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _git(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", *args],
            cwd=self.repo,
            text=True,
            capture_output=True,
            check=True,
        )

    def _run_checker(
        self, repo: Path | None = None, *, env: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(CHECKER), "--repo", str(repo or self.repo)],
            text=True,
            capture_output=True,
            check=False,
            env=env,
        )

    def _write(self, relative_path: str, content: str | bytes) -> Path:
        path = self.repo / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        return path

    def _assert_rejected(self, result: subprocess.CompletedProcess[str], rule: str) -> None:
        self.assertEqual(1, result.returncode, result.stdout + result.stderr)
        self.assertIn(f"\t{rule}\t", result.stdout)
        self.assertEqual("", result.stderr)

    def test_safe_git_candidates_pass(self) -> None:
        shutil.copyfile(SAFE_FIXTURE, self.repo / "config.json")

        result = self._run_checker()

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual("public release check passed\n", result.stdout)
        self.assertEqual("", result.stderr)

    def test_private_key_header_is_rejected_without_echoing_secret(self) -> None:
        secrets = [
            "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
            "-----BEGIN " + "RSA PRIVATE KEY-----",
            "-----BEGIN " + "EC PRIVATE KEY-----",
            "-----BEGIN " + "DSA PRIVATE KEY-----",
            "-----BEGIN " + "PRIVATE KEY-----",
            "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----",
        ]
        for index, secret in enumerate(secrets):
            self._write(f"secret-{index}.txt", secret + "\nprivate-data")

        result = self._run_checker()

        self._assert_rejected(result, "private-key")
        for index, secret in enumerate(secrets):
            self.assertIn(f"secret-{index}.txt\tprivate-key\t", result.stdout)
            self.assertNotIn(secret, result.stdout)

    def test_production_activation_code_is_rejected_without_echoing_it(self) -> None:
        activation_code = "GBF-" + "0123456789abcdef" * 2
        self._write("settings.json", '{"code": "' + activation_code + '"}')

        result = self._run_checker()

        self._assert_rejected(result, "activation-code")
        self.assertNotIn(activation_code, result.stdout)

    def test_activation_code_with_non_hex_suffix_is_still_rejected(self) -> None:
        activation_code = "GBF-" + "abcdef0123456789" * 2
        self._write("settings.txt", activation_code + "_production")

        result = self._run_checker()

        self._assert_rejected(result, "activation-code")
        self.assertNotIn(activation_code, result.stdout)

    def test_globally_routable_ipv4_address_is_rejected(self) -> None:
        address = "8." + "8.8.8"
        self._write("endpoint.txt", "server=" + address)

        result = self._run_checker()

        self._assert_rejected(result, "global-ipv4")
        self.assertNotIn(address, result.stdout)

    def test_non_public_ipv4_addresses_are_allowed(self) -> None:
        addresses = [
            "192.0.2.10",
            "198.51.100.20",
            "203.0.113.30",
            "127.0.0.1",
            "10.0.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "240.0.0.1",
        ]
        self._write("addresses.txt", "\n".join(addresses))

        result = self._run_checker()

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_real_email_address_is_rejected_without_echoing_it(self) -> None:
        email = "person" + "@" + "acme.test"
        self._write("contact.txt", "contact=" + email)

        result = self._run_checker()

        self._assert_rejected(result, "email-address")
        self.assertNotIn(email, result.stdout)

    def test_reserved_example_email_addresses_are_allowed(self) -> None:
        examples = [
            "maintainer" + "@" + domain
            for domain in ("example.com", "example.net", "example.org", "example.invalid")
        ]
        self._write("contacts.txt", "\n".join(examples))

        result = self._run_checker()

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_windows_user_profile_path_is_rejected_without_echoing_it(self) -> None:
        user_path = "C:" + "\\Users\\alice\\project"
        self._write("notes.txt", "path=" + user_path)

        result = self._run_checker()

        self._assert_rejected(result, "windows-user-path")
        self.assertNotIn(user_path, result.stdout)

    def test_json_escaped_windows_user_profile_path_is_rejected(self) -> None:
        escaped_path = "C:" + "\\\\" + "Users" + "\\\\" + "alice\\\\project"
        self._write("settings.json", '{"path": "' + escaped_path + '"}')

        result = self._run_checker()

        self._assert_rejected(result, "windows-user-path")
        self.assertNotIn(escaped_path, result.stdout)

    def test_forbidden_directories_are_rejected_when_git_tracks_them(self) -> None:
        directories = [
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
        ]
        for directory in directories:
            path = self._write(f"nested/{directory}/payload.txt", "safe")
            self._git("add", "-f", "--", str(path.relative_to(self.repo)))

        result = self._run_checker()

        self._assert_rejected(result, "forbidden-directory")
        for directory in directories:
            self.assertIn(f"nested/{directory}/payload.txt", result.stdout)

    def test_forbidden_filenames_are_rejected_when_git_tracks_them(self) -> None:
        names = [
            "state.json",
            "known_hosts",
            "id_ed25519",
            "id_ed25519.pub",
            "id_rsa_backup",
            "id_ecdsa-old",
            "deployment-history-production.json",
        ]
        for name in names:
            path = self._write(f"config/{name}", "safe")
            self._git("add", "-f", "--", str(path.relative_to(self.repo)))

        result = self._run_checker()

        self._assert_rejected(result, "forbidden-filename")
        for name in names:
            self.assertIn(f"config/{name}", result.stdout)

    def test_forbidden_extensions_are_rejected_when_git_tracks_them(self) -> None:
        extensions = [
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
        ]
        for index, extension in enumerate(extensions):
            path = self._write(f"artifacts/file-{index}{extension}", "safe")
            self._git("add", "-f", "--", str(path.relative_to(self.repo)))

        result = self._run_checker()

        self._assert_rejected(result, "forbidden-extension")
        for index, extension in enumerate(extensions):
            self.assertIn(f"artifacts/file-{index}{extension}", result.stdout)

    def test_file_larger_than_two_mib_is_rejected(self) -> None:
        self._write("large.txt", b"x" * (2 * 1024 * 1024 + 1))

        result = self._run_checker()

        self._assert_rejected(result, "oversized-file")

    def test_regular_text_larger_than_one_mib_is_rejected(self) -> None:
        self._write("large.txt", b"x" * (1024 * 1024 + 1))

        result = self._run_checker()

        self._assert_rejected(result, "oversized-text")

    def test_license_may_exceed_regular_text_limit(self) -> None:
        self._write("LICENSE", b"x" * (1024 * 1024 + 1))

        result = self._run_checker()

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_nul_binary_file_is_rejected(self) -> None:
        self._write("unknown.bin", b"prefix\x00suffix")

        result = self._run_checker()

        self._assert_rejected(result, "binary-file")

    def test_control_byte_binary_without_nul_is_rejected(self) -> None:
        self._write("unknown.bin", b"\x01\x02\x03\x04")

        result = self._run_checker()

        self._assert_rejected(result, "binary-file")

    def test_symbolic_link_is_rejected_when_supported(self) -> None:
        target = self._write("target.txt", "safe")
        link = self.repo / "link.txt"
        try:
            link.symlink_to(target.name)
        except OSError as error:
            self.skipTest(f"symbolic links are unavailable: {error}")

        result = self._run_checker()

        self._assert_rejected(result, "symbolic-link")

    def test_symlinked_parent_that_escapes_repo_is_rejected_when_supported(self) -> None:
        tracked = self._write("linked/payload.txt", "safe")
        self._git("add", "--", "linked/payload.txt")
        tracked.unlink()
        tracked.parent.rmdir()
        with tempfile.TemporaryDirectory() as outside_directory:
            outside = Path(outside_directory)
            (outside / "payload.txt").write_text("safe", encoding="utf-8")
            linked_directory = self.repo / "linked"
            try:
                linked_directory.symlink_to(outside, target_is_directory=True)
            except OSError as error:
                self.skipTest(f"directory symbolic links are unavailable: {error}")

            result = self._run_checker()

        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertRegex(result.stdout, r"\t(?:symbolic-link|path-escape)\t")

    def test_uninitialized_directory_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self._run_checker(Path(directory))

        self.assertEqual(2, result.returncode, result.stdout + result.stderr)
        self.assertIn("\tgit-command-failed\t", result.stdout)
        self.assertEqual("", result.stderr)

    def test_unresolvable_repository_root_fails_closed(self) -> None:
        missing_repo = self.repo / "missing-repository"

        result = self._run_checker(missing_repo)

        self.assertEqual(2, result.returncode, result.stdout + result.stderr)
        self.assertIn("\trepository-unavailable\t", result.stdout)
        self.assertEqual("", result.stderr)

    def test_missing_git_executable_fails_closed(self) -> None:
        empty_path = self.repo / "empty-path"
        empty_path.mkdir()
        env = {**os.environ, "PATH": str(empty_path)}

        result = self._run_checker(env=env)

        self.assertEqual(2, result.returncode, result.stdout + result.stderr)
        self.assertIn("\tgit-unavailable\t", result.stdout)
        self.assertEqual("", result.stderr)

    def test_git_command_failure_fails_closed(self) -> None:
        (self.repo / ".git" / "index").write_bytes(b"invalid-index")

        result = self._run_checker()

        self.assertEqual(2, result.returncode, result.stdout + result.stderr)
        self.assertIn("\tgit-command-failed\t", result.stdout)
        self.assertEqual("", result.stderr)

    def test_ignored_file_is_not_scanned(self) -> None:
        secret = "-----BEGIN " + "RSA PRIVATE KEY-----"
        self._write(".gitignore", "ignored/\n")
        self._write("ignored/secret.txt", secret)

        result = self._run_checker()

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_candidate_that_cannot_be_read_fails_closed(self) -> None:
        candidate = self._write("missing.txt", "safe")
        self._git("add", "--", candidate.name)
        candidate.unlink()

        result = self._run_checker()

        self.assertEqual(2, result.returncode, result.stdout + result.stderr)
        self.assertIn("missing.txt\tfile-read-failed\t", result.stdout)
        self.assertEqual("", result.stderr)


if __name__ == "__main__":
    unittest.main()
