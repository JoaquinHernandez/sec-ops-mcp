import os
import subprocess
import shutil

GTFOBINS_HIGH_RISK = {
    "find", "vim", "nano", "cp", "mv", "bash", "sh", "env", 
    "awk", "sed", "python", "perl", "tar", "zip", "less", "more"
}

def audit_linux_privesc_vectors(deep_scan: bool = False):
    findings = []
    
    # 1. SUID Binary Audit
    suid_binaries = []
    try:
        result = subprocess.run(
            ["find", "/usr", "/bin", "/sbin", "-perm", "-4000", "-type", "f"],
            capture_output=True, text=True, timeout=10
        )
        suid_binaries = result.stdout.strip().splitlines()
    except Exception:
        pass

    for binary in suid_binaries:
        base = os.path.basename(binary)
        if base in GTFOBINS_HIGH_RISK:
            findings.append({
                "category": "SUID_GTFOBINS_RISK",
                "severity": "HIGH",
                "target": binary,
                "description": f"Binary '{base}' has SUID bit set and is known to allow shell breakout/arbitrary file operations.",
                "remediation": f"Remove SUID bit: chmod u-s {binary}"
            })

    # 2. Capabilities Check
    if shutil.which("getcap"):
        try:
            cap_res = subprocess.run(
                ["getcap", "-r", "/usr", "/bin"],
                capture_output=True, text=True, timeout=10
            )
            for line in cap_res.stdout.strip().splitlines():
                if any(c in line for c in ["cap_setuid", "cap_dac_override", "cap_sys_admin"]):
                    findings.append({
                        "category": "DANGEROUS_CAPABILITY",
                        "severity": "HIGH",
                        "target": line,
                        "description": "File holds elevated Linux capabilities bypassing standard DAC.",
                        "remediation": "Audit and strip unused capabilities with setcap -r."
                    })
        except Exception:
            pass

    # 3. Writable Cron Directories
    cron_paths = ["/etc/crontab", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly"]
    for cp in cron_paths:
        if os.path.exists(cp) and os.access(cp, os.W_OK):
            findings.append({
                "category": "WRITABLE_CRON",
                "severity": "CRITICAL",
                "target": cp,
                "description": f"Cron location '{cp}' is writable by the current unprivileged context.",
                "remediation": f"Restore root ownership: chown root:root {cp} && chmod 755 {cp}"
            })

    return {
        "module": "PrivScope (Linux)",
        "total_issues": len(findings),
        "issues": findings
    }
