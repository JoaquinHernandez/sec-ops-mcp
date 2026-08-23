import os
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec

PQC_STANDARDS = ["ML-KEM", "ML-DSA", "SLH-DSA", "Kyber", "Dilithium", "Falcon", "SPHINCS+"]

def audit_pqc_readiness(cert_dir: str):
    findings = []
    if not os.path.exists(cert_dir):
        return {"status": "error", "message": f"Directory not found: {cert_dir}"}

    for root, _, files in os.walk(cert_dir):
        for f in files:
            if f.endswith((".crt", ".pem", ".cer")):
                path = os.path.join(root, f)
                try:
                    with open(path, "rb") as cert_file:
                        cert = x509.load_pem_x509_certificate(cert_file.read(), default_backend())
                        pub_key = cert.public_key()
                        
                        sig_algo = cert.signature_algorithm_oid._name
                        key_type = type(pub_key).__name__
                        quantum_status = "VULNERABLE_CLASSICAL"
                        
                        if isinstance(pub_key, rsa.RSAPublicKey):
                            key_size = pub_key.key_size
                            note = f"RSA {key_size}-bit (Vulnerable to Shor's Algorithm)"
                        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                            note = f"ECC Curve {pub_key.curve.name} (Vulnerable to Shor's Algorithm)"
                        else:
                            note = f"Key type: {key_type}"

                        findings.append({
                            "certificate": f,
                            "path": path,
                            "key_type": key_type,
                            "signature_algo": sig_algo,
                            "quantum_posture": quantum_status,
                            "assessment": note,
                            "remediation": "Migrate to NIST PQC FIPS standards (FIPS 203 ML-KEM, FIPS 204 ML-DSA)."
                        })
                except Exception:
                    continue

    return {
        "module": "QuantumGuard",
        "scanned_path": cert_dir,
        "total_certificates_audited": len(findings),
        "findings": findings
    }

def scan_tls_cipher_suites(hostname: str, port: int = 443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cipher = ssock.cipher()
                version = ssock.version()
                
                # Check for hybrid / PQC indicators in negotiated handshake
                cipher_name = cipher[0] if cipher else "Unknown"
                is_pqc = any(pqc in cipher_name for pqc in PQC_STANDARDS)
                
                return {
                    "module": "QuantumGuard TLS Scanner",
                    "target": f"{hostname}:{port}",
                    "tls_version": version,
                    "negotiated_cipher": cipher_name,
                    "pqc_hybrid_enabled": is_pqc,
                    "verdict": "PQC-Ready" if is_pqc else "Classical Cryptography (Transition Required)"
                }
    except Exception as e:
        return {"target": f"{hostname}:{port}", "error": str(e)}
