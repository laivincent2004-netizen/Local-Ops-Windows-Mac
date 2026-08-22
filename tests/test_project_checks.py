import unittest
from unittest import mock

from tools import check_project


class JavaScriptBindingCheckTests(unittest.TestCase):
    def test_missing_shared_callable_import_is_reported(self):
        source = """
            import { post } from './core.js';
            function removeApp() {
              post('/prepare');
              return del('/api/apps/one');
            }
        """
        self.assertEqual(
            check_project.find_unbound_shared_calls(
                source, {"post", "del"}),
            ["del"],
        )

    def test_import_alias_local_declaration_comments_and_strings_are_allowed(self):
        source = """
            import { del as remove, post } from './core.js';
            function del() { return remove('/local'); }
            // missing('/comment-only')
            const example = "missing('/string-only')";
            post('/prepare');
            del();
        """
        self.assertEqual(
            check_project.find_unbound_shared_calls(
                source, {"post", "del", "missing"}),
            [],
        )

    def test_core_callable_exports_include_functions_and_arrow_functions(self):
        source = """
            export function regular() {}
            export async function later() {}
            export const arrow = value => value;
            export const grouped = (value, other) => value + other;
            export const data = {};
        """
        self.assertEqual(
            check_project.javascript_exported_callables(source),
            {"regular", "later", "arrow", "grouped"},
        )

    def test_project_modules_have_no_unbound_core_calls(self):
        detail = check_project.check_javascript_bindings()
        self.assertIn("公共可调用导出", detail)


class RequiredFileCheckTests(unittest.TestCase):
    def test_untracked_user_plan_is_not_required_by_ci(self):
        class CheckoutWithoutPlan:
            def __init__(self):
                self.checked = []

            def __truediv__(self, name):
                self.checked.append(name)
                return mock.Mock(is_file=mock.Mock(return_value=True))

        checkout = CheckoutWithoutPlan()
        with mock.patch.object(check_project, "ROOT", checkout):
            detail = check_project.check_required_files()

        self.assertNotIn("PLAN.md", checkout.checked)
        self.assertIn("个必要文件", detail)


class JavaScriptRuntimeCheckTests(unittest.TestCase):
    def _run_summary(self, output):
        with (
            mock.patch.object(check_project.shutil, "which", return_value="node"),
            mock.patch.object(check_project, "command_output", return_value=output),
        ):
            return check_project.check_javascript_tests()

    def test_accepts_legacy_tap_summary(self):
        self.assertEqual(self._run_summary("# tests 7\n# pass 7\n# fail 0\n"),
                         "7 个测试")

    def test_accepts_node_24_spec_summary(self):
        self.assertEqual(self._run_summary("ℹ tests 7\nℹ pass 7\nℹ fail 0\n"),
                         "7 个测试")

    def test_rejects_failed_spec_summary(self):
        with self.assertRaises(check_project.CheckError):
            self._run_summary("ℹ tests 7\nℹ pass 6\nℹ fail 1\n")


class RequirementLockCheckTests(unittest.TestCase):
    HASH = "a" * 64

    def test_windows_hash_lock_parses_logical_continuations(self):
        entries = check_project.parse_locked_requirements(
            """
            # exact Windows wheel
            demo-package==1.2.3 \\
                --hash=sha256:{hash_value}
            second==4.5.6 \\
                --hash=sha256:{hash_value}
            """.format(hash_value=self.HASH),
            filename="requirements-windows.txt",
            require_hashes=True,
        )
        self.assertEqual(len(entries), 2)
        self.assertIn("demo-package==1.2.3 --hash=sha256:", entries[0])

    def test_windows_lock_rejects_missing_or_malformed_hashes(self):
        for text in (
            "demo==1.0\n",
            "demo==1.0 --hash=sha256:not-a-hash\n",
            "demo>=1.0 --hash=sha256:" + self.HASH + "\n",
        ):
            with self.subTest(text=text), self.assertRaises(
                check_project.CheckError
            ):
                check_project.parse_locked_requirements(
                    text,
                    filename="requirements-windows.txt",
                    require_hashes=True,
                )

    def test_unterminated_requirement_continuation_is_rejected(self):
        with self.assertRaises(check_project.CheckError):
            check_project.parse_locked_requirements(
                "demo==1.0 \\",
                filename="requirements-windows.txt",
                require_hashes=True,
            )

    def test_development_lock_can_remain_bare_exact_versions(self):
        self.assertEqual(
            check_project.parse_locked_requirements(
                "ruff==0.13.0\n",
                filename="requirements-dev.txt",
            ),
            ["ruff==0.13.0"],
        )


if __name__ == "__main__":
    unittest.main()
