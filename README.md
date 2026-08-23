# sec-ops-mcp
# SecOps MCP Server (`sec-ops-mcp`)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MCP Version](https://img.shields.io/badge/MCP-FastMCP-brightgreen.svg)](https://github.com/modelcontextprotocol)

**SecOps MCP** is an enterprise-grade Model Context Protocol server that arms LLMs and AI agents with direct diagnostic capabilities for defensive security posture assessments, privilege escalation surface auditing, and Post-Quantum Cryptography (PQC) readiness checks.

---

## 🛠️ Integrated Tooling Modules

| Module | Scope | Key Diagnostic Capabilities |
| :--- | :--- | :--- |
| **QuantumGuard** | PQC & Modern Cryptography | Scans x509 cert chains for classical vs. PQC algorithms (FIPS 203/204), evaluates Shor's vulnerability risks on RSA/ECC, and probes TLS endpoints for hybrid key exchange support. |
| **PrivScope** | Linux Privilege Surface | Identifies dangerous SUID/SGID binaries (GTFOBins mapped), unauthorized `cap_setuid`/`cap_dac_override` capabilities, and writable scheduled task matrices. |
| **WinScope** | Windows Privilege Surface | Audits `AlwaysInstallElevated` registry bypasses, unquoted service paths running under SYSTEM, and misconfigured service binary DACLs. |

---

## 🚀 Quickstart

### Prerequisites
- Python 3.10+
- `pip` / `venv`

### Installation

```bash
git clone [https://github.com/JoaquinHernandez/sec-ops-mcp.git](https://github.com/JoaquinHernandez/sec-ops-mcp.git)
cd sec-ops-mcp
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

---

## ⚙️ Client Integration

Add this MCP server definition to your client configuration:

### Claude Desktop (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "secops-scanner": {
      "command": "/absolute/path/to/sec-ops-mcp/.venv/bin/python",
      "args": ["/absolute/path/to/sec-ops-mcp/server.py"]
    }
  }
}
```

### Cursor / Local MCP Agents

```json
{
  "mcpServers": {
    "secops-scanner": {
      "command": "python",
      "args": ["./server.py"],
      "cwd": "/absolute/path/to/sec-ops-mcp"
    }
  }
}
```

---

## 📋 Available MCP Tools

* **`scan_pqc_readiness(target_dir)`**: Evaluates local certificate stores against NIST PQC migration guidelines.
* **`scan_tls_quantum_posture(hostname, port)`**: Connects to TLS services to check for post-quantum hybrid key exchange suites.
* **`audit_linux_posture(deep_scan)`**: Scans Linux hosts for SUID escalation vectors and capability leaks.
* **`audit_windows_posture()`**: Scans Windows registry and service tables for privilege escalation flaws.

---

## 🔒 Security & Defense-in-Depth Notes

This MCP server is built specifically for **read-only posture assessment and hardening verification**. It performs passive analysis and structured reporting, enabling autonomous defensive assistants to guide engineers through remediation workflows without generating offensive payloads.
