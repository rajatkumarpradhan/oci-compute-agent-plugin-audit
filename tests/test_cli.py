import io
import unittest
from contextlib import redirect_stderr, redirect_stdout

from agent_audit.cli import main


class TestCli(unittest.TestCase):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_messy_exit_2(self):
        code, out, _ = self.run_cli("samples/instances_messy.json")
        self.assertEqual(code, 2)
        self.assertIn("AGP001", out)
        self.assertIn("prod-db-1", out)

    def test_clean_exit_0(self):
        code, out, _ = self.run_cli("samples/instances_clean.json")
        self.assertEqual(code, 0)
        self.assertIn("clean, no findings", out)

    def test_error_exit_3(self):
        code, _, err = self.run_cli("README.md")
        self.assertEqual(code, 3)
        self.assertIn("export error", err)

    def test_terminated_excluded_from_count(self):
        code, out, _ = self.run_cli("samples/instances_messy.json")
        self.assertIn("3 active instance(s)", out)
        self.assertNotIn("old-terminated]", out)


if __name__ == "__main__":
    unittest.main()
