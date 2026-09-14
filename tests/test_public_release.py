from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CHECKER = PROJECT_ROOT / "scripts" / "check_public_release.py"
WRAPPER = PROJECT_ROOT / "scripts" / "check-public-release.ps1"
SAFE_FIXTURE = PROJECT_ROOT / "tests" / "fixtures" / "safe" / "config.json"
WRAPPER_STARTUP_ERROR = b"public release check failed: startup error\n"
CHECKER_SPEC = importlib.util.spec_from_file_location("public_release_checker", CHECKER)
assert CHECKER_SPEC is not None and CHECKER_SPEC.loader is not None
CHECKER_MODULE = importlib.util.module_from_spec(CHECKER_SPEC)
sys.modules[CHECKER_SPEC.name] = CHECKER_MODULE
CHECKER_SPEC.loader.exec_module(CHECKER_MODULE)


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

    def test_staged_sensitive_blob_is_scanned_after_worktree_is_made_safe(self) -> None:
        secret = "-----BEGIN " + "RSA PRIVATE KEY-----"
        candidate = self._write("staged.txt", secret)
        self._git("add", "--", candidate.name)
        candidate.write_text("safe worktree replacement", encoding="utf-8")

        result = self._run_checker()

        self._assert_rejected(result, "private-key")
        self.assertNotIn(secret, result.stdout)

    def test_staged_safe_blob_is_used_when_worktree_contains_a_secret(self) -> None:
        candidate = self._write("staged.txt", "safe staged content")
        self._git("add", "--", candidate.name)
        candidate.write_text("-----BEGIN " + "RSA PRIVATE KEY-----", encoding="utf-8")

        result = self._run_checker()

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_case_distinct_index_entries_are_both_scanned_when_supported(self) -> None:
        self._git("config", "core.ignorecase", "false")
        secret = "-----BEGIN " + "DSA PRIVATE KEY-----"
        secret_object = subprocess.run(
            ["git", "hash-object", "-w", "--stdin"],
            cwd=self.repo,
            input=secret,
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
        safe_object = subprocess.run(
            ["git", "hash-object", "-w", "--stdin"],
            cwd=self.repo,
            input="safe",
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
        self._git("update-index", "--add", "--cacheinfo", f"100644,{secret_object},Case.TXT")
        self._git("update-index", "--add", "--cacheinfo", f"100644,{safe_object},case.txt")
        names = self._git("ls-files").stdout.splitlines()
        if names != ["Case.TXT", "case.txt"]:
            self.skipTest("Git index does not support case-distinct paths")

        result = self._run_checker()

        self._assert_rejected(result, "private-key")
        self.assertIn("Case.TXT\tprivate-key\t", result.stdout)

    def test_oversized_index_blob_is_rejected_after_worktree_removal(self) -> None:
        candidate = self._write("large-index.txt", b"x" * (2 * 1024 * 1024 + 1))
        self._git("add", "--", candidate.name)
        candidate.unlink()

        result = self._run_checker()

        self._assert_rejected(result, "oversized-file")

    def test_symbolic_link_mode_in_index_is_rejected(self) -> None:
        object_id = subprocess.run(
            ["git", "hash-object", "-w", "--stdin"],
            cwd=self.repo,
            input="target.txt",
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
        self._git("update-index", "--add", "--cacheinfo", f"120000,{object_id},link.txt")

        result = self._run_checker()

        self._assert_rejected(result, "symbolic-link")

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

    def test_putty_private_key_header_is_rejected(self) -> None:
        header = "PuTTY-User" + "-Key-File-3: ssh-rsa"
        self._write("putty.txt", header)

        result = self._run_checker()

        self._assert_rejected(result, "putty-private-key")
        self.assertNotIn(header, result.stdout)

    def test_ssh_ed25519_public_key_is_allowed(self) -> None:
        public_key = "ssh-" + "ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDemoOnly deploy@example.com"
        self._write("public-key.txt", public_key)

        result = self._run_checker()

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_url_with_embedded_credentials_is_rejected(self) -> None:
        url = "https://" + "alice:s3cret@" + "example.com/api"
        self._write("endpoint.txt", "url=" + url)

        result = self._run_checker()

        self._assert_rejected(result, "url-credentials")
        self.assertNotIn(url, result.stdout)

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

    def test_high_confidence_token_prefixes_are_rejected(self) -> None:
        tokens = [
            "ghp" + "_" + "A" * 36,
            "github" + "_pat_" + "B" * 30,
            "AK" + "IA" + "C" * 16,
            "xox" + "b-" + "123456789012-123456789012-" + "D" * 24,
        ]
        for index, token in enumerate(tokens):
            self._write(f"token-{index}.txt", token)

        result = self._run_checker()

        self._assert_rejected(result, "high-confidence-token")
        for index, token in enumerate(tokens):
            self.assertIn(f"token-{index}.txt\thigh-confidence-token\t", result.stdout)
            self.assertNotIn(token, result.stdout)

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

    def test_globally_routable_ipv6_address_is_rejected(self) -> None:
        address = "2606:4700:4700:" + ":1111"
        self._write("ipv6.txt", "endpoint=" + address)

        result = self._run_checker()

        self._assert_rejected(result, "global-ipv6")
        self.assertNotIn(address, result.stdout)

    def test_documentation_and_local_ipv6_addresses_are_allowed(self) -> None:
        addresses = ["2001:db8::1", "::1", "fd00::1", "fe80::1", "::", "100::1", "ff02::1"]
        self._write("safe-ipv6.txt", "\n".join(addresses))

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

    def test_forward_slash_windows_and_unix_user_paths_are_rejected(self) -> None:
        paths = [
            ("windows.txt", "C:" + "/Users/" + "alice/project", "windows-user-path"),
            ("macos.txt", "/Users/" + "alice/project", "unix-user-path"),
            ("linux.txt", "/home/" + "alice/project", "unix-user-path"),
        ]
        for filename, user_path, _rule in paths:
            self._write(filename, user_path)

        result = self._run_checker()

        self.assertEqual(1, result.returncode, result.stdout + result.stderr)
        for filename, user_path, rule in paths:
            self.assertIn(f"{filename}\t{rule}\t", result.stdout)
            self.assertNotIn(user_path, result.stdout)

    def test_explicit_deploy_example_user_paths_are_allowed(self) -> None:
        paths = ["C:/Users/deploy/project", "/Users/deploy/project", "/home/deploy/project"]
        self._write("deploy-paths.txt", "\n".join(paths))

        result = self._run_checker()

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

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
            "authorized_keys",
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

    def test_env_files_are_rejected_but_example_variants_are_allowed(self) -> None:
        rejected = [".env", ".env.local", ".env.production.secret"]
        allowed = [".env.example", ".env.local.example"]
        for name in rejected + allowed:
            path = self._write(name, "SAFE_PLACEHOLDER=true")
            self._git("add", "-f", "--", str(path.relative_to(self.repo)))

        result = self._run_checker()

        self._assert_rejected(result, "forbidden-filename")
        for name in rejected:
            self.assertIn(f"{name}\tforbidden-filename\t", result.stdout)
        for name in allowed:
            self.assertNotIn(f"{name}\t", result.stdout)

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

    def test_text_up_to_two_mib_is_allowed(self) -> None:
        self._write("large.txt", b"x" * (2 * 1024 * 1024))

        result = self._run_checker()

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_license_up_to_two_mib_is_allowed(self) -> None:
        self._write("LICENSE", b"x" * (2 * 1024 * 1024))

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

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO creation is unavailable")
    def test_fifo_is_rejected_without_being_opened(self) -> None:
        fifo = self.repo / "pipe"
        os.mkfifo(fifo)

        result = self._run_checker()

        self._assert_rejected(result, "special-file")

    @unittest.skipUnless(os.name == "nt", "Windows junctions are unavailable")
    def test_windows_junction_is_rejected_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as target_directory:
            target = Path(target_directory)
            (target / "payload.txt").write_text("safe", encoding="utf-8")
            junction = self.repo / "junction"
            created = subprocess.run(
                ["cmd.exe", "/d", "/c", "mklink", "/J", str(junction), str(target)],
                capture_output=True,
                check=False,
            )
            if created.returncode != 0:
                self.skipTest("Windows junction creation is unavailable")
            try:
                result = self._run_checker()
            finally:
                os.rmdir(junction)

        self.assertEqual(1, result.returncode, result.stdout + result.stderr)
        self.assertRegex(result.stdout, r"\t(?:symbolic-link|special-file)\t")

    def test_index_blob_does_not_follow_symlinked_worktree_parent_when_supported(self) -> None:
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

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_uninitialized_directory_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self._run_checker(Path(directory))

        self.assertEqual(2, result.returncode, result.stdout + result.stderr)
        self.assertIn("\tgit-command-failed\t", result.stdout)
        self.assertEqual("", result.stderr)

    def test_repo_argument_must_be_exact_git_top_level(self) -> None:
        subdirectory = self.repo / "nested"
        subdirectory.mkdir()

        result = self._run_checker(subdirectory)

        self.assertEqual(2, result.returncode, result.stdout + result.stderr)
        self.assertIn("\trepository-not-top-level\t", result.stdout)
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

    def test_gbk_console_escapes_emoji_path_without_traceback(self) -> None:
        filename = "unsafe-\U0001f600.pem"
        candidate = self._write(filename, "safe")
        self._git("add", "-f", "--", candidate.name)
        env = {**os.environ, "PYTHONIOENCODING": "gbk"}

        result = subprocess.run(
            [sys.executable, str(CHECKER), "--repo", str(self.repo)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=env,
        )

        self.assertEqual(1, result.returncode, result.stdout + result.stderr)
        self.assertIn(b"unsafe-\\U0001f600.pem", result.stdout)
        self.assertNotIn(str(self.repo).encode(), result.stdout + result.stderr)
        self.assertNotIn(b"Traceback", result.stdout + result.stderr)
        self.assertEqual(b"", result.stderr)

    @unittest.skipUnless(shutil.which("pwsh"), "PowerShell is unavailable")
    def test_wrapper_reports_missing_python_without_powershell_traceback(self) -> None:
        pwsh = shutil.which("pwsh")
        assert pwsh is not None
        empty_path = self.repo / "empty-path"
        empty_path.mkdir()
        env = {**os.environ, "PATH": str(empty_path)}

        result = subprocess.run(
            [pwsh, "-NoProfile", "-File", str(WRAPPER)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=env,
        )

        self.assertEqual(2, result.returncode, result.stdout + result.stderr)
        self.assertEqual(WRAPPER_STARTUP_ERROR, result.stderr)
        self.assertNotIn(b"CommandNotFoundException", result.stdout + result.stderr)

    def test_wrapper_sanitizes_missing_checker_on_available_powershell_editions(self) -> None:
        scripts = self.repo / "scripts"
        scripts.mkdir()
        local_wrapper = scripts / WRAPPER.name
        shutil.copyfile(WRAPPER, local_wrapper)
        executables = [
            executable
            for name in ("pwsh", "powershell.exe")
            if (executable := shutil.which(name)) is not None
        ]
        if not executables:
            self.skipTest("PowerShell is unavailable")

        for executable in executables:
            with self.subTest(executable=executable):
                result = subprocess.run(
                    [
                        executable,
                        "-NoProfile",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-File",
                        str(local_wrapper),
                    ],
                    cwd=self.repo,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(2, result.returncode, result.stdout + result.stderr)
                self.assertEqual(b"", result.stdout)
                self.assertEqual(WRAPPER_STARTUP_ERROR, result.stderr)
                self.assertNotIn(str(self.repo).encode(), result.stdout + result.stderr)
                self.assertNotIn(b"Resolve-Path", result.stdout + result.stderr)

    def test_wrapper_runs_on_available_powershell_editions(self) -> None:
        scripts = self.repo / "scripts"
        scripts.mkdir()
        local_checker = scripts / CHECKER.name
        local_wrapper = scripts / WRAPPER.name
        shutil.copyfile(CHECKER, local_checker)
        shutil.copyfile(WRAPPER, local_wrapper)
        self._git("add", "--", "scripts")
        executables = [
            executable
            for name in ("pwsh", "powershell.exe")
            if (executable := shutil.which(name)) is not None
        ]
        if not executables:
            self.skipTest("PowerShell is unavailable")

        for executable in executables:
            with self.subTest(executable=executable):
                result = subprocess.run(
                    [
                        executable,
                        "-NoProfile",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-File",
                        str(local_wrapper),
                    ],
                    cwd=self.repo,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                self.assertEqual([b"public release check passed"], result.stdout.splitlines())
                self.assertEqual(b"", result.stderr)

    def test_wrapper_treats_brackets_in_repository_path_literally(self) -> None:
        repositories = self.repo / "repositories"
        literal_repo = repositories / "repo[1]"
        wildcard_sibling = repositories / "repo1"
        for repository in (literal_repo, wildcard_sibling):
            (repository / "scripts").mkdir(parents=True)
            subprocess.run(
                ["git", "init", "--quiet"],
                cwd=repository,
                capture_output=True,
                check=True,
            )
        local_checker = literal_repo / "scripts" / CHECKER.name
        local_wrapper = literal_repo / "scripts" / WRAPPER.name
        shutil.copyfile(CHECKER, local_checker)
        shutil.copyfile(WRAPPER, local_wrapper)
        secret = "-----BEGIN " + "RSA PRIVATE KEY-----"
        (literal_repo / "secret.txt").write_text(secret, encoding="utf-8")
        subprocess.run(
            ["git", "add", "--", "scripts", "secret.txt"],
            cwd=literal_repo,
            capture_output=True,
            check=True,
        )
        executables = [
            executable
            for name in ("pwsh", "powershell.exe")
            if (executable := shutil.which(name)) is not None
        ]
        if not executables:
            self.skipTest("PowerShell is unavailable")

        for executable in executables:
            with self.subTest(executable=executable):
                result = subprocess.run(
                    [
                        executable,
                        "-NoProfile",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-File",
                        str(local_wrapper),
                    ],
                    cwd=literal_repo,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                )
                self.assertEqual(1, result.returncode, result.stdout + result.stderr)
                self.assertIn(b"secret.txt\tprivate-key\t", result.stdout)
                self.assertNotIn(secret.encode(), result.stdout + result.stderr)
                self.assertEqual(b"", result.stderr)

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

    def test_local_release_deny_literal_and_regex_are_applied(self) -> None:
        marker = "INTERNAL_" + "MARKER_42"
        self._write(".gitignore", ".release-deny.local\n")
        self._write(
            ".release-deny.local",
            "literal:" + marker + "\n" + r"regex:customer-[0-9]{4}" + "\n",
        )
        self._write("literal.txt", marker)
        self._write("regex.txt", "customer-1234")

        result = self._run_checker()

        self._assert_rejected(result, "local-deny")
        self.assertIn("literal.txt\tlocal-deny\t", result.stdout)
        self.assertIn("regex.txt\tlocal-deny\t", result.stdout)
        self.assertNotIn(marker, result.stdout)

    def test_invalid_local_release_deny_file_fails_closed(self) -> None:
        self._write(".gitignore", ".release-deny.local\n")
        self._write(".release-deny.local", "unsupported:value\n")

        result = self._run_checker()

        self.assertEqual(2, result.returncode, result.stdout + result.stderr)
        self.assertIn("\tlocal-deny-invalid\t", result.stdout)
        self.assertEqual("", result.stderr)

    def test_staged_candidate_is_read_from_index_when_worktree_is_missing(self) -> None:
        candidate = self._write("missing.txt", "safe")
        self._git("add", "--", candidate.name)
        candidate.unlink()

        result = self._run_checker()

        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_missing_untracked_candidate_read_fails_closed(self) -> None:
        with self.assertRaises(CHECKER_MODULE.ReleaseCheckError) as captured:
            CHECKER_MODULE.read_worktree_candidate(self.repo, Path("missing-untracked.txt"))

        self.assertEqual("file-read-failed", captured.exception.finding.rule)

    def test_initial_tree_is_scanned_during_index_aba_change(self) -> None:
        secret = "-----BEGIN " + "RSA PRIVATE KEY-----"
        candidate = self._write("aba.txt", secret)
        self._git("add", "--", candidate.name)
        secret_object = self._git("rev-parse", ":aba.txt").stdout.strip()
        original_git_candidates = CHECKER_MODULE.git_candidates

        def replace_index_then_restore(repo: Path, *arguments: str):
            candidate.write_text("safe replacement", encoding="utf-8")
            self._git("add", "--", candidate.name)
            candidates = original_git_candidates(repo, *arguments)
            self._git(
                "update-index",
                "--cacheinfo",
                f"100644,{secret_object},{candidate.name}",
            )
            return candidates

        with mock.patch.object(
            CHECKER_MODULE, "git_candidates", side_effect=replace_index_then_restore
        ):
            findings = CHECKER_MODULE.check_repository(self.repo)

        self.assertIn(
            ("aba.txt", "private-key"),
            [(finding.path, finding.rule) for finding in findings],
        )

    def test_index_tree_change_fails_closed(self) -> None:
        with mock.patch.object(
            CHECKER_MODULE, "index_tree_oid", side_effect=["a" * 40, "b" * 40]
        ):
            with mock.patch.object(CHECKER_MODULE, "git_candidates", return_value=[]):
                with self.assertRaises(CHECKER_MODULE.ReleaseCheckError) as captured:
                    CHECKER_MODULE.check_repository(self.repo)

        self.assertEqual("index-changed", captured.exception.finding.rule)


if __name__ == "__main__":
    unittest.main()
