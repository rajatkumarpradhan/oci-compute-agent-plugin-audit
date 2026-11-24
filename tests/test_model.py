import unittest

from agent_audit.model import (ExportError, Instance, Plugin, load_export)

SAMPLE = "samples/instances_messy.json"


class TestLoad(unittest.TestCase):
    def test_load_ok(self):
        insts = load_export(SAMPLE)
        self.assertEqual(len(insts), 4)
        self.assertEqual(insts[0].name, "prod-web-1")

    def test_rejects_bad_json(self):
        with self.assertRaises(ExportError):
            load_export("README.md")

    def test_rejects_missing_file(self):
        with self.assertRaises(ExportError):
            load_export("does-not-exist.json")

    def test_defaults(self):
        inst = Instance(name="x")
        self.assertEqual(inst.environment, "development")
        self.assertFalse(inst.is_production())
        self.assertTrue(inst.is_active())

    def test_plugin_lookup_case_insensitive(self):
        inst = Instance(name="x", plugins=(Plugin(name="Bastion", enabled=True),))
        self.assertIsNotNone(inst.plugin("bastion"))
        self.assertIsNone(inst.plugin("Management Agent"))

    def test_plugin_running_requires_enabled(self):
        p = Plugin(name="Bastion", enabled=True, status="RUNNING")
        self.assertTrue(p.is_running())
        p2 = Plugin(name="Bastion", enabled=False, status="RUNNING")
        self.assertFalse(p2.is_running())

    def test_terminated_not_active(self):
        inst = Instance(name="x", lifecycle_state="TERMINATED")
        self.assertFalse(inst.is_active())


if __name__ == "__main__":
    unittest.main()
