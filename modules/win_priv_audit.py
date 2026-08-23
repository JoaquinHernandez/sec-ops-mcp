import subprocess
import json

def audit_windows_privesc_vectors():
    findings = []

    # 1. Check AlwaysInstallElevated in Registry
    for hive in ["HKCU", "HKLM"]:
        cmd = f'reg query "{hive}\\Software\\Policies\\Microsoft\\Windows\\Installer" /v AlwaysInstallElevated'
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            if "0x1" in out.stdout:
                findings.append({
                    "category": "ALWAYS_INSTALL_ELEVATED",
                    "severity": "CRITICAL",
                    "hive": hive,
                    "description": "AlwaysInstallElevated is set to 1. Unprivileged users can execute MSI packages with SYSTEM privileges.",
                    "remediation": f"Set {hive}\\Software\\Policies\\Microsoft\\Windows\\Installer\\AlwaysInstallElevated to 0."
                })
        except Exception:
            pass

    # 2. Check Unquoted Service Paths
    ps_unquoted = """
    Get-CimInstance win32_service | Where-Object {
        $_.PathName -notmatch '^"' -and $_.PathName -match '\s' -and$_.PathName -notmatch '^C:\\\\Windows'
    } | Select-Object Name, PathName, StartName | ConvertTo-Json
    """
    try:
        out = subprocess.run(["powershell", "-Command", ps_unquoted], capture_output=True, text=True)
        if out.stdout.strip():
            raw_svcs = json.loads(out.stdout)
            if isinstance(raw_svcs, dict):
                raw_svcs = [raw_svcs]
            for svc in raw_svcs:
                findings.append({
                    "category": "UNQUOTED_SERVICE_PATH",
                    "severity": "MEDIUM",
                    "service_name": svc.get("Name"),
                    "path": svc.get("PathName"),
                    "account": svc.get("StartName"),
                    "description": "Service binary path contains spaces and lacks enclosing quotes, permitting binary planting.",
                    "remediation": "Enclose service ImagePath in quotation marks."
                })
    except Exception:
        pass

    return {
        "module": "WinScope (Windows)",
        "total_issues": len(findings),
        "issues": findings
    }
