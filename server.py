"""
SecOps MCP Server - Enterprise Defensive Security & Posture Auditing
Integrates QuantumGuard (PQC), PrivScope (Linux), and WinScope (Windows).
"""

import json
import platform
from typing import Optional
from mcp.server.fastmcp import FastMCP

from modules.quantum_scan import audit_pqc_readiness, scan_tls_cipher_suites
from modules.linux_priv_audit import audit_linux_privesc_vectors
from modules.win_priv_audit import audit_windows_privesc_vectors

mcp = FastMCP("sec-ops-mcp")

@mcp.tool()
def scan_pqc_readiness(target_dir: str = "/etc/ssl") -> str:
    """
    [QuantumGuard] Scans local certificates and cryptographic key stores to assess
    readiness for Post-Quantum Cryptography (PQC). Identifies vulnerable classical
    key lengths (RSA < 3072, ECC curves) and checks for hybrid/PQC-ready algorithms (ML-KEM, ML-DSA).
    """
    report = audit_pqc_readiness(target_dir)
    return json.dumps(report, indent=2)

@mcp.tool()
def scan_tls_quantum_posture(hostname: str, port: int = 443) -> str:
    """
    [QuantumGuard] Probes a network endpoint's TLS configuration to check if it supports
    quantum-resistant key exchanges (e.g., X25519Kyber768, SecP256r1Kyber768Draft00)
    versus legacy classical exchanges.
    """
    report = scan_tls_cipher_suites(hostname, port)
    return json.dumps(report, indent=2)

@mcp.tool()
def audit_linux_posture(deep_scan: bool = False) -> str:
    """
    [PrivScope] Audits Linux systems for defensive misconfigurations and escalation vectors:
    - SUID/SGID binaries (cross-referenced against GTFOBins catalog).
    - Insecure Sudo permissions and NOPASSWD rules.
    - Linux file capabilities (cap_setuid, cap_dac_override).
    - Writable cron entries and world-writable service binaries.
    """
    if platform.system().lower() != "linux":
        return json.dumps({"error": f"PrivScope requires a Linux OS. Detected: {platform.system()}"})
    
    report = audit_linux_privesc_vectors(deep_scan=deep_scan)
    return json.dumps(report, indent=2)

@mcp.tool()
def audit_windows_posture() -> str:
    """
    [WinScope] Audits Windows systems for privilege escalation vectors:
    - Unquoted service paths containing spaces.
    - Writable service binaries and weak folder DACLs.
    - AlwaysInstallElevated registry configurations.
    - Autostart / Run key hijack vectors.
    """
    if platform.system().lower() != "windows":
        return json.dumps({"error": f"WinScope requires Windows. Detected: {platform.system()}"})
    
    report = audit_windows_privesc_vectors()
    return json.dumps(report, indent=2)

if __name__ == "__main__":
    mcp.run()
