import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import tempfile
import threading
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
HOST_PATH = ROOT / "desktop" / "windows_host.py"
WINDOWS_REQUIREMENTS = ROOT / "requirements-windows.txt"
BUILD_SCRIPT = ROOT / "packaging" / "windows" / "build.ps1"
INSTALLER_SCRIPT = ROOT / "packaging" / "windows" / "installer.iss"
CONSOLE_SPEC = ROOT / "packaging" / "windows" / "console.spec"
SUPERVISOR_SPEC = ROOT / "packaging" / "windows" / "supervisor.spec"
WORKFLOW = ROOT / ".github" / "workflows" / "windows-release.yml"
MAC_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
UNSIGNED_NOTICE = ROOT / "packaging" / "windows" / "UNSIGNED_BUILD_NOTICE.txt"
CHINESE_LANGUAGE = (
    ROOT / "packaging" / "windows" / "languages" / "ChineseSimplified.isl"
)
INNO_LICENSE = ROOT / "licenses" / "Inno-Setup-License.txt"


def load_host():
    spec = importlib.util.spec_from_file_location("windows_host_contract", HOST_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class WindowsHostContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.host = load_host()

    def test_host_imports_on_non_windows_for_contract_checks(self):
        self.assertEqual(self.host.PORT_START, 9600)
        self.assertEqual(self.host.PORT_END, 9609)

    def test_user_object_key_accepts_only_sid_shape(self):
        first = self.host.user_object_key("S-1-5-21-100-200-300-1001")
        second = self.host.user_object_key("S-1-5-21-100-200-300-1001")
        self.assertEqual(first, second)
        self.assertRegex(first, r"^[0-9a-f]{24}$")
        with self.assertRaises(ValueError):
            self.host.user_object_key("alice")
        with self.assertRaises(ValueError):
            self.host.user_object_key("S-not-a-real-sid")

    def test_activation_parser_is_strict_and_bounded(self):
        self.assertEqual(self.host.parse_activation(b'{"action":"open"}'), "open")
        for bad in (
            b"",
            b"not json",
            b'{"action":"shell"}',
            b'{"action":"open","command":"calc"}',
            b"x" * (self.host.PIPE_BYTES + 1),
        ):
            with self.subTest(payload=bad[:40]):
                self.assertIsNone(self.host.parse_activation(bad))

    def test_runtime_paths_are_under_local_app_data(self):
        root, logs = self.host.runtime_paths(r"C:\Users\example\AppData\Local")
        self.assertEqual(root.name, "总控台")
        self.assertEqual(logs, root / "logs")

    def test_cli_actions_support_activation_and_background_start(self):
        self.assertEqual(self.host.parse_args(["--restart"]).action, "restart")
        self.assertEqual(self.host.parse_args(["--quit"]).action, "quit")
        self.assertEqual(
            self.host.parse_args(["--runtime-check"]).action, "runtime-check")
        background = self.host.parse_args(["--background"])
        self.assertTrue(background.background)
        self.assertEqual(background.action, "open")

    def test_runtime_check_failure_is_a_headless_nonzero_exit(self):
        with mock.patch.object(
            self.host, "runtime_check", side_effect=RuntimeError("broken bundle")
        ):
            self.assertEqual(self.host.main(["--runtime-check"]), 1)

    @unittest.skipUnless(os.name == "nt", "requires real Windows pywin32 ACLs")
    def test_real_windows_api_protects_a_private_directory(self):
        from console_platform.windows_security import private_path_is_secure

        api = self.host.WindowsApi()
        with tempfile.TemporaryDirectory(prefix="local-ops-host-acl-test-") as path:
            api.protect_directory(Path(path))
            self.assertIs(private_path_is_secure(path), True)

    @unittest.skipUnless(os.name == "nt", "requires real Windows mutexes")
    def test_real_windows_single_instance_acquires_unique_probe_mutex(self):
        api = self.host.WindowsApi()
        instance = self.host.SingleInstance(api)
        suffix = f"{os.getpid()}-{time.time_ns()}"
        instance.mutex_name = rf"Local\LocalOpsHostTest-{suffix}"
        instance.installer_mutex_name = rf"Local\LocalOpsHostTestInstaller-{suffix}"
        try:
            self.assertTrue(instance.acquire())
            self.assertFalse(instance.already_running)
        finally:
            instance.close()

    @unittest.skipUnless(os.name == "nt", "requires real Windows pywin32")
    def test_all_direct_windows_host_pywin32_attributes_exist(self):
        api = self.host.WindowsApi()
        source = HOST_PATH.read_text(encoding="utf-8")
        references = set(re.findall(
            r"(?:self\.api|self|api)\."
            r"(win32(?:api|con|event|file|pipe|security)|winerror)\."
            r"([A-Za-z_][A-Za-z0-9_]*)",
            source,
        ))
        self.assertTrue(references)
        for module_name, attribute_name in sorted(references):
            with self.subTest(module=module_name, attribute=attribute_name):
                self.assertTrue(
                    hasattr(getattr(api, module_name), attribute_name),
                    f"{module_name}.{attribute_name} is absent in locked pywin32",
                )

    def test_host_contract_keeps_http_and_supervised_apps_separate(self):
        source = HOST_PATH.read_text(encoding="utf-8")
        self.assertIn("class ServerController", source)
        self.assertIn("server.shutdown()", source)
        self.assertNotIn("TerminateJobObject", source)
        self.assertNotIn("taskkill", source.lower())
        self.assertIn("受管应用继续运行", source)
        self.assertIn("Local\\LocalOpsTray-", source)
        self.assertIn(r"\\.\pipe\LocalOpsTray-", source)
        self.assertIn("DACL allowing only the current user and LocalSystem", source)
        self.assertIn("self.win32file.FILE_ALL_ACCESS", source)
        self.assertNotIn("self.win32con.FILE_ALL_ACCESS", source)
        self.assertIn("self.api.winerror.ERROR_ALREADY_EXISTS", source)
        self.assertNotIn("self.api.win32con.ERROR_ALREADY_EXISTS", source)
        self.assertIn("PIPE_REJECT_REMOTE_CLIENTS", source)
        self.assertIn("FILE_FLAG_FIRST_PIPE_INSTANCE", source)
        self.assertIn("self.action_lock", source)
        self.assertIn("Join the same readiness event", source)
        for label in ("打开总控台", "启动总控台", "停止总控台", "重新启动总控台", "退出"):
            self.assertIn(label, source)

    def test_stop_waits_for_an_inflight_bind(self):
        controller = self.host.ServerController()

        class FakeServer:
            def __init__(self):
                self.stopped = False

            def shutdown(self):
                self.stopped = True

        server = FakeServer()

        def finish_bind():
            time.sleep(0.01)
            with controller._lock:
                controller._server = server
            controller._ready.set()

        thread = threading.Thread(target=finish_bind)
        controller._thread = thread
        thread.start()
        controller.stop(timeout=1.0)
        thread.join()
        self.assertTrue(server.stopped)

    def test_tray_stop_cancels_api_restart_after_shutdown_before_start(self):
        controller = self.host.ServerController()
        server_exit = threading.Event()
        first_shutdown = threading.Event()
        second_shutdown = threading.Event()

        class BlockingServer:
            def __init__(self):
                self._lock = threading.Lock()
                self.shutdown_calls = 0

            def shutdown(self):
                with self._lock:
                    self.shutdown_calls += 1
                    shutdown_calls = self.shutdown_calls
                first_shutdown.set()
                if shutdown_calls >= 2:
                    second_shutdown.set()

        server = BlockingServer()
        http_thread = threading.Thread(
            target=lambda: server_exit.wait(2.0), name="fake-console-http"
        )
        http_thread.start()
        controller._server = server
        controller._thread = http_thread
        controller._generation = 7
        controller._stop_epoch = 3
        controller._port = 9600
        controller._last_port = 9600
        controller._ready.set()

        existing_threads = set(threading.enumerate())
        with mock.patch.object(self.host.time, "sleep", return_value=None), mock.patch.object(
            controller, "start"
        ) as start_mock:
            controller._schedule_embedded_restart(server, 9600, 7, 3)
            self.assertTrue(first_shutdown.wait(1.0))
            restart_thread = next(
                thread
                for thread in threading.enumerate()
                if thread not in existing_threads
                and thread.name == "console-api-restart"
            )

            stop_errors = []

            def tray_stop():
                try:
                    controller.stop(timeout=2.0)
                except BaseException as exc:
                    stop_errors.append(exc)

            stop_thread = threading.Thread(target=tray_stop, name="fake-tray-stop")
            stop_thread.start()
            self.assertTrue(second_shutdown.wait(1.0))
            with controller._lock:
                self.assertEqual(controller._stop_epoch, 4)
            server_exit.set()
            stop_thread.join(2.0)
            restart_thread.join(2.0)

        self.assertFalse(stop_thread.is_alive())
        self.assertFalse(restart_thread.is_alive())
        self.assertEqual(stop_errors, [])
        start_mock.assert_not_called()

    def test_api_restart_starts_normally_without_newer_stop(self):
        controller = self.host.ServerController()
        server_exit = threading.Event()
        replacement_started = threading.Event()

        class FakeServer:
            def shutdown(self):
                server_exit.set()

        server = FakeServer()
        http_thread = threading.Thread(
            target=lambda: server_exit.wait(2.0), name="fake-console-http"
        )
        http_thread.start()
        controller._server = server
        controller._thread = http_thread
        controller._generation = 11
        controller._stop_epoch = 5

        def record_start(**_kwargs):
            replacement_started.set()
            return 9600

        existing_threads = set(threading.enumerate())
        with mock.patch.object(self.host.time, "sleep", return_value=None), mock.patch.object(
            controller, "start", side_effect=record_start
        ) as start_mock:
            controller._schedule_embedded_restart(server, 9600, 11, 5)
            self.assertTrue(replacement_started.wait(1.0))
            restart_threads = [
                thread
                for thread in threading.enumerate()
                if thread not in existing_threads
                and thread.name == "console-api-restart"
            ]
            for restart_thread in restart_threads:
                restart_thread.join(1.0)

        http_thread.join(1.0)
        start_mock.assert_called_once_with(
            preferred_port=9600, _expected_stop_epoch=5
        )


class WindowsReleaseManifestTests(unittest.TestCase):
    def test_python_sources_parse(self):
        ast.parse(HOST_PATH.read_text(encoding="utf-8"), filename=str(HOST_PATH))

    def test_windows_dependencies_are_exactly_pinned(self):
        logical_lines = []
        pending = ""
        for raw_line in WINDOWS_REQUIREMENTS.read_text(
            encoding="utf-8"
        ).splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            pending = f"{pending} {line}".strip()
            if pending.endswith("\\"):
                pending = pending[:-1].strip()
                continue
            logical_lines.append(pending)
            pending = ""
        self.assertFalse(pending, "unterminated requirement continuation")
        expected = {
            "pillow",
            "psutil",
            "pystray",
            "pywin32",
            "pyinstaller",
            "altgraph",
            "packaging",
            "pefile",
            "pyinstaller-hooks-contrib",
            "pywin32-ctypes",
            "setuptools",
            "six",
        }
        actual = set()
        for line in logical_lines:
            with self.subTest(requirement=line):
                match = re.fullmatch(
                    r"([A-Za-z0-9_.-]+)==[A-Za-z0-9_.+!-]+ "
                    r"--hash=sha256:([0-9a-f]{64})",
                    line,
                )
                self.assertIsNotNone(match)
                actual.add(match.group(1).lower())
        self.assertEqual(actual, expected)

    def test_main_spec_is_onedir_windowed_and_carries_runtime_data(self):
        text = CONSOLE_SPEC.read_text(encoding="utf-8")
        self.assertIn('name="总控台"', text)
        self.assertIn("console=False", text)
        self.assertIn("disable_windowed_traceback=True", text)
        self.assertIn("COLLECT(", text)
        self.assertIn('ROOT / "static"', text)
        self.assertIn('ROOT / "VERSION"', text)
        self.assertIn('ROOT / "licenses"', text)
        self.assertIn('ROOT / "ASSET_PROVENANCE.md"', text)
        self.assertIn("exclude_binaries=True", text)
        self.assertIn('"server"', text)
        self.assertIn('"supervisor_client"', text)
        self.assertIn('"console_platform.windows"', text)
        self.assertIn('"console_platform.wsl_host"', text)
        self.assertIn('"console_platform.windows_security"', text)
        self.assertIn('"tkinter.filedialog"', text)
        self.assertNotIn('excludes=["tkinter"', text)
        # PyInstaller's target_arch switch is macOS-only.  Windows x64 is
        # enforced by build.ps1's interpreter probe and the Inno constraints.
        self.assertNotIn("target_arch", text)

    def test_packaged_runtime_check_requires_the_file_picker(self):
        text = (ROOT / "desktop" / "windows_host.py").read_text(
            encoding="utf-8")
        self.assertIn('__import__("tkinter.filedialog"', text)
        self.assertIn("bundled Windows file picker is incomplete", text)
        self.assertIn('TemporaryDirectory(prefix="local-ops-runtime-check-")', text)
        self.assertIn("temporary Windows DACL self-check failed", text)
        self.assertIn("LocalOpsRuntimeCheck-", text)
        self.assertIn("temporary Windows mutex self-check collided", text)

    def test_supervisor_spec_is_single_file_and_source_is_mandatory(self):
        spec = SUPERVISOR_SPEC.read_text(encoding="utf-8")
        build = BUILD_SCRIPT.read_text(encoding="utf-8")
        self.assertIn('ROOT / "supervisor.py"', spec)
        # Unlike the windowed tray host, the durable supervisor is a console
        # subsystem executable.  CREATE_NEW_CONSOLE can then allocate the
        # hidden private console used for targeted CTRL_BREAK delivery.
        self.assertIn("console=True", spec)
        self.assertNotIn("console=False", spec)
        self.assertNotIn("COLLECT(", spec)
        self.assertNotIn("target_arch", spec)
        for module in (
            "supervisor_windows", "psutil", "pywintypes", "win32api",
            "win32con", "win32file", "win32job", "win32pipe",
            "win32process", "win32security",
        ):
            with self.subTest(module=module):
                self.assertIn(f'"{module}"', spec)
        self.assertIn("Required release source is missing", build)
        self.assertIn("console-supervisor-$SupervisorVersion.exe", build)
        self.assertIn("SUPERVISOR_VERSION", build)
        self.assertIn("Supervisor implementation/client version mismatch", build)
        self.assertIn(
            "Invoke-FrozenRuntimeCheck -Executable $SupervisorExe", build
        )
        self.assertIn("The frozen $Label failed", build)

    def test_build_requires_real_helper_and_emits_hash_manifest(self):
        text = BUILD_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("RuntimeInformation]::OSArchitecture", text)
        self.assertIn("$NativeOsArchitecture -ne 'X64'", text)
        self.assertIn("$RequiredPythonVersion = '3.12.10'", text)
        self.assertIn("$CandidateVersion -ne $RequiredPythonVersion", text)
        self.assertIn("Label = 'py -3.12'", text)
        self.assertIn("wsl-helper-x86_64", text)
        self.assertIn("statically linked WSL helper is required", text)
        self.assertIn("release-manifest.json", text)
        self.assertIn("Get-FileHash -Algorithm SHA256", text)
        self.assertIn("SHA256SUMS.txt", text)
        self.assertIn("foreach ($ArtifactPath in $ArtifactPaths)", text)
        self.assertNotIn("$Artifact.FullName", text)
        self.assertIn("WslHelperSha256", text)
        self.assertIn("little-endian ELF64 x86-64", text)
        self.assertIn("_internal", text)
        self.assertIn('console-supervisor-$SupervisorVersion.exe', text)
        self.assertIn("supervisorVersion = $SupervisorVersion", text)
        self.assertIn("helperVersion = $WslHelperVersion", text)
        self.assertIn("Version = $WslHelperVersion", text)
        self.assertIn("appVersion = $Version", text)
        self.assertIn("$BundledSupervisorHash", text)
        self.assertIn("$BundledHelperHash", text)
        self.assertIn("SPDX-2.3", text)
        self.assertIn("local-ops-windows-x64.spdx.json", text)
        self.assertIn("pip freeze --all", text)
        self.assertIn("--require-hashes", text)
        self.assertIn("windows-python-dependencies.txt", text)
        self.assertIn("-m venv --clear", text)
        self.assertIn("signatureStatus = 'unsigned-internal-test'", text)
        self.assertIn("Authenticode insertion contract", text)
        self.assertIn("--runtime-check", text)
        self.assertIn("dependency/runtime smoke test", text)
        self.assertIn("WaitForExit($TimeoutSeconds * 1000)", text)
        self.assertIn("Stop-Process -Id $Process.Id -Force", text)
        self.assertIn("function Get-ReleaseRelativePath", text)
        self.assertNotIn("[System.IO.Path]::GetRelativePath", text)
        self.assertIn("Release manifest does not cover every installed", text)
        self.assertIn("$RequiredInnoSetupVersion = '6.7.3'", text)
        self.assertIn("function Get-InnoSetupVersion", text)
        self.assertIn("Programs\\Inno Setup 6\\ISCC.exe", text)
        self.assertIn("DisplayVersion", text)
        self.assertIn("innoSetupVersion = $InnoSetupVersion", text)
        self.assertIn("RequiredChineseLanguageHash", text)
        self.assertIn("chineseTranslationCommit = $ChineseLanguageCommit", text)
        self.assertIn("SPDXRef-Package-InnoSetupChineseSimplified", text)
        self.assertIn("[System.Text.UTF8Encoding]::new($true)", text)
        self.assertIn("installer-utf8.iss", text)

    def test_installer_is_per_user_and_preserves_application_data(self):
        text = INSTALLER_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("DefaultDirName={localappdata}\\Programs", text)
        self.assertIn("PrivilegesRequired=lowest", text)
        self.assertIn("Flags: unchecked", text)
        self.assertIn("AppMutex=Local\\LocalOpsTrayInstallerGuard", text)
        self.assertIn("function InitializeSetup(): Boolean", text)
        self.assertIn("procedure CurUninstallStepChanged", text)
        self.assertIn("usAppMutexCheck", text)
        self.assertIn("Exec(AppExe, '--quit'", text)
        self.assertNotIn("function PrepareToInstall", text)
        self.assertLess(
            text.index("RequestTrayExit(InstalledAppExe())"),
            text.index("procedure CurUninstallStepChanged"),
        )
        self.assertIn("ArchitecturesAllowed=x64os", text)
        self.assertIn("ArchitecturesInstallIn64BitMode=x64os", text)
        self.assertIn("InfoBeforeFile={#SourceDir}\\UNSIGNED_BUILD_NOTICE.txt", text)
        self.assertNotRegex(text, r"(?m)^.*UninstallDelete.*localappdata.*总控台")

    def test_installer_vendors_pinned_chinese_language_input(self):
        installer = INSTALLER_SCRIPT.read_text(encoding="utf-8")
        language = CHINESE_LANGUAGE.read_text(encoding="utf-8")
        build_script = BUILD_SCRIPT.read_text(encoding="utf-8")
        provenance = CHINESE_LANGUAGE.with_name("README.md").read_text(
            encoding="utf-8"
        )
        language_hash = hashlib.sha256(CHINESE_LANGUAGE.read_bytes()).hexdigest()
        self.assertIn("/DLanguageDir=path", installer)
        self.assertIn('{#LanguageDir}\\ChineseSimplified.isl', installer)
        self.assertIn("Inno Setup version 6.5.0+", language)
        self.assertIn("Maintainer: Zhenghan Yang (Kira)", language)
        self.assertIn("5680c948e1de07e71cbd27cad7d4f5e75223afba", provenance)
        self.assertIn(language_hash, build_script)
        self.assertIn(language_hash, provenance)
        self.assertIn("Inno Setup License", INNO_LICENSE.read_text(encoding="utf-8"))

    def test_unsigned_notice_explains_smartscreen_integrity_and_upgrade(self):
        text = UNSIGNED_NOTICE.read_text(encoding="utf-8")
        self.assertIn("SmartScreen", text)
        self.assertIn("SHA256SUMS.txt", text)
        self.assertIn("更多信息", text)
        self.assertIn("仍要运行", text)
        self.assertIn("覆盖升级", text)
        self.assertIn("supervisor", text)
        self.assertIn("spdx.json", text)

    def test_workflow_builds_helper_before_windows_package(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("x86_64-unknown-linux-musl", text)
        self.assertIn("--locked", text)
        self.assertIn("readelf -l", text)
        self.assertIn("readelf -d", text)
        self.assertIn("must not contain a dynamic interpreter", text)
        self.assertIn("must not depend on shared libraries", text)
        self.assertIn("needs: [wsl-helper, windows-test]", text)
        self.assertIn("runs-on: windows-2025", text)
        self.assertIn("packaging/windows/build.ps1", text)
        self.assertIn("toolchain: 1.88.0", text)
        self.assertNotIn("toolchain: stable", text)
        self.assertIn("wsl-helper-x86_64.sha256", text)
        self.assertIn("WslHelperSha256", text)
        self.assertIn(
            "Could not read the supervisor implementation version from source",
            text,
        )
        self.assertNotIn(
            "Could not read the supervisor protocol version from source",
            text,
        )
        self.assertIn("Release manifest supervisor version mismatch", text)
        self.assertIn("Release manifest WSL helper version mismatch", text)
        self.assertIn("Windows SBOM is not a valid SPDX 2.3 document", text)
        self.assertIn("Release manifest path escapes the application root", text)
        self.assertIn("Installed file hash mismatch", text)
        self.assertIn("Installed application file is absent from release manifest", text)
        self.assertIn("Release manifest Inno Setup version mismatch", text)
        self.assertIn("Install pinned Inno Setup 6.7.3", text)
        self.assertIn("releases/download/is-6_7_3/innosetup-6.7.3.exe", text)
        self.assertIn(
            "9c73c3bae7ed48d44112a0f48e66742c00090bdb5bef71d9d3c056c66e97b732",
            text,
        )
        self.assertIn("Get-AuthenticodeSignature", text)
        self.assertIn("Pyrsys B\\.V\\.", text)
        self.assertIn("'/CURRENTUSER'", text)
        self.assertIn("--require-hashes", text)
        self.assertIn("local-ops-windows-x64.spdx.json", text)
        self.assertIn("windows-python-dependencies.txt", text)
        self.assertIn("UNSIGNED_BUILD_NOTICE.txt", text)
        self.assertIn(
            "node --test tests/js/i18n.test.mjs tests/js/ports.test.mjs",
            text,
        )
        self.assertIn("node --check $_.FullName", text)

    def test_macos_and_windows_ci_are_both_present(self):
        mac = MAC_WORKFLOW.read_text(encoding="utf-8")
        windows = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("runs-on: macos-15", mac)
        self.assertIn("make check PYTHON=python", mac)
        self.assertIn("runs-on: windows-2025", windows)
        self.assertIn('python-version: "3.12.10"', windows)
        self.assertNotIn('python-version: "3.12"', windows)
        self.assertIn('python -m unittest discover -s tests -p "test_*.py" -v', windows)


if __name__ == "__main__":
    unittest.main()
