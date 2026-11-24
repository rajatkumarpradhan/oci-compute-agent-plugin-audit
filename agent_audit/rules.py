"""Posture rules for OCI Compute instance agent plugins.

Every rule takes the loaded instances and returns Finding objects. Rules skip
TERMINATED instances: auditing a dead instance's plugins is noise.
"""

from __future__ import annotations

from dataclasses import dataclass

BASTION = "Bastion"
VULN_SCAN = "Vulnerability Scanning"
OSMS = "OS Management Service Agent"
LOG_MONITORING = "Custom Logs Monitoring"
INSTANCE_MONITORING = "Compute Instance Monitoring"


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    target: str
    detail: str


def _missing_or_disabled(inst, plugin_name):
    p = inst.plugin(plugin_name)
    return p is None or not p.enabled


def rule_prod_bastion_disabled(instances):
    out = []
    for inst in instances:
        if not inst.is_active() or not inst.is_production():
            continue
        if _missing_or_disabled(inst, BASTION):
            out.append(Finding("AGP001", "HIGH", inst.name,
                "production instance has the Bastion agent plugin disabled; "
                "managed just-in-time SSH through OCI Bastion is unavailable"))
    return out


def rule_vuln_scan_disabled(instances):
    out = []
    for inst in instances:
        if not inst.is_active():
            continue
        if _missing_or_disabled(inst, VULN_SCAN):
            sev = "HIGH" if inst.is_production() else "MEDIUM"
            out.append(Finding("AGP002", sev, inst.name,
                "Vulnerability Scanning plugin is not enabled; the instance is "
                "invisible to OCI Vulnerability Scanning Service host scans"))
    return out


def rule_osms_disabled(instances):
    out = []
    for inst in instances:
        if not inst.is_active():
            continue
        if _missing_or_disabled(inst, OSMS):
            out.append(Finding("AGP003", "MEDIUM", inst.name,
                "OS Management Service Agent is disabled; managed patching and "
                "package inventory through OS Management Hub will not run"))
    return out


def rule_log_monitoring_disabled(instances):
    out = []
    for inst in instances:
        if not inst.is_active():
            continue
        if _missing_or_disabled(inst, LOG_MONITORING):
            out.append(Finding("AGP004", "MEDIUM", inst.name,
                "Custom Logs Monitoring plugin is disabled; Logging agent "
                "configurations cannot collect logs from this instance"))
    return out


def rule_instance_monitoring_disabled(instances):
    out = []
    for inst in instances:
        if not inst.is_active():
            continue
        if _missing_or_disabled(inst, INSTANCE_MONITORING):
            out.append(Finding("AGP005", "LOW", inst.name,
                "Compute Instance Monitoring plugin is disabled; Monitoring "
                "loses OS-level metrics such as memory and disk usage"))
    return out


def rule_plugin_not_running(instances):
    out = []
    for inst in instances:
        if not inst.is_active():
            continue
        for p in inst.plugins:
            if p.enabled and p.status.upper() not in ("RUNNING",):
                out.append(Finding("AGP006", "LOW", inst.name,
                    f"plugin '{p.name}' is enabled but reports status "
                    f"{p.status}; agent may be stopped or the plugin failed"))
    return out


ALL_RULES = (
    rule_prod_bastion_disabled,
    rule_vuln_scan_disabled,
    rule_osms_disabled,
    rule_log_monitoring_disabled,
    rule_instance_monitoring_disabled,
    rule_plugin_not_running,
)


def run_all(instances):
    findings = []
    for rule in ALL_RULES:
        findings.extend(rule(instances))
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings.sort(key=lambda f: (order.get(f.severity, 3), f.rule, f.target))
    return findings


def exit_code(findings) -> int:
    if any(f.severity == "HIGH" for f in findings):
        return 2
    return 1 if findings else 0
