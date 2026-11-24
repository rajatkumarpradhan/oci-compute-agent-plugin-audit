import unittest

from agent_audit.model import Instance, Plugin
from agent_audit.rules import (
    exit_code,
    rule_instance_monitoring_disabled,
    rule_log_monitoring_disabled,
    rule_osms_disabled,
    rule_plugin_not_running,
    rule_prod_bastion_disabled,
    rule_vuln_scan_disabled,
    run_all,
)


def inst(name="i1", environment="production", state="RUNNING", plugins=()):
    return Instance(name=name, environment=environment,
                    lifecycle_state=state, plugins=tuple(plugins))


class TestAgp001(unittest.TestCase):
    def test_fires_prod_no_bastion(self):
        out = rule_prod_bastion_disabled([inst()])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, "HIGH")

    def test_quiet_dev(self):
        out = rule_prod_bastion_disabled([inst(environment="development")])
        self.assertEqual(out, [])

    def test_quiet_when_enabled(self):
        p = Plugin(name="Bastion", enabled=True, status="RUNNING")
        self.assertEqual(rule_prod_bastion_disabled([inst(plugins=(p,))]), [])

    def test_skips_terminated(self):
        out = rule_prod_bastion_disabled([inst(state="TERMINATED")])
        self.assertEqual(out, [])


class TestAgp002(unittest.TestCase):
    def test_prod_high(self):
        out = rule_vuln_scan_disabled([inst()])
        self.assertEqual(out[0].severity, "HIGH")

    def test_dev_medium(self):
        out = rule_vuln_scan_disabled([inst(environment="development")])
        self.assertEqual(out[0].severity, "MEDIUM")


class TestMediumLowRules(unittest.TestCase):
    def test_osms(self):
        out = rule_osms_disabled([inst()])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].rule, "AGP003")

    def test_logs(self):
        out = rule_log_monitoring_disabled([inst()])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].rule, "AGP004")

    def test_monitoring_low(self):
        out = rule_instance_monitoring_disabled([inst()])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, "LOW")

    def test_enabled_not_running(self):
        p = Plugin(name="Bastion", enabled=True, status="STOPPED")
        out = rule_plugin_not_running([inst(plugins=(p,))])
        self.assertEqual(len(out), 1)

    def test_disabled_not_flagged_as_stopped(self):
        p = Plugin(name="Bastion", enabled=False, status="STOPPED")
        out = rule_plugin_not_running([inst(plugins=(p,))])
        self.assertEqual(out, [])


class TestRunAll(unittest.TestCase):
    def test_sorted_high_first(self):
        findings = run_all([inst()])
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertTrue(all(f.severity != "HIGH" for f in findings[2:]))

    def test_exit_codes(self):
        self.assertEqual(exit_code([]), 0)
        high = run_all([inst()])
        self.assertEqual(exit_code(high), 2)


if __name__ == "__main__":
    unittest.main()
