#!/usr/bin/env python3
"""Check TLS protocol support and certificate metadata for a host."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import socket
import ssl
import sys

VERSIONS = [
    ("TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
    ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
    ("TLSv1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
    ("TLSv1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
]


def _context(version) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if version is not None:
        ctx.minimum_version = version
        ctx.maximum_version = version
    return ctx


def probe(host: str, port: int = 443, timeout: float = 5.0) -> dict:
    supported = {}
    for name, version in VERSIONS:
        if version is None:
            supported[name] = False
            continue
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with _context(version).wrap_socket(raw) as tls:
                    tls.do_handshake()
            supported[name] = True
        except (ssl.SSLError, OSError):
            supported[name] = False

    cert = {}
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with _context(None).wrap_socket(raw) as tls:
                cert = tls.getpeercert() or {}
    except (ssl.SSLError, OSError):
        pass
    return {"supported": supported, "cert": cert}


def grade(supported: dict, cert: dict, now: dt.date | None = None):
    now = now or dt.date.today()
    findings = []
    if supported.get("TLSv1.0") or supported.get("TLSv1.1"):
        findings.append({"issue": "legacy-tls", "severity": "high",
                         "detail": "TLS 1.0/1.1 accepted; disable them."})
    if not supported.get("TLSv1.2"):
        findings.append({"issue": "missing-tls12", "severity": "high",
                         "detail": "TLS 1.2 not accepted."})
    if not supported.get("TLSv1.3"):
        findings.append({"issue": "no-tls13", "severity": "medium",
                         "detail": "TLS 1.3 not offered."})
    expiry = cert.get("notAfter")
    if expiry:
        try:
            expiry_date = dt.datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z").date()
            days = (expiry_date - now).days
            if days < 0:
                findings.append({"issue": "expired", "severity": "high",
                                 "detail": f"certificate expired {abs(days)} days ago"})
            elif days < 30:
                findings.append({"issue": "expires-soon", "severity": "medium",
                                 "detail": f"certificate expires in {days} days"})
        except ValueError:
            pass
    else:
        findings.append({"issue": "no-certificate", "severity": "medium",
                         "detail": "certificate could not be read"})
    score = 100
    for finding in findings:
        score -= 30 if finding["severity"] == "high" else 10
    return max(0, score), findings


def render(host: str, port: int, supported: dict, cert: dict, score: int, findings) -> str:
    lines = [f"{host}:{port}", f"score: {score}/100", "protocols:"]
    for name, _ in VERSIONS:
        lines.append(f"  {name:<8} {'accepted' if supported.get(name) else 'rejected'}")
    if cert:
        subject = ", ".join("=".join(part) for rdn in cert.get("subject", ()) for part in rdn)
        lines.append(f"subject: {subject or '-'}")
        lines.append(f"issuer:  {cert.get('issuer', '-')}")
        lines.append(f"expires: {cert.get('notAfter', '-')}")
    lines.append("findings:" if findings else "findings: none")
    for finding in findings:
        lines.append(f"  [{finding['severity']}] {finding['issue']}: {finding['detail']}")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Check TLS configuration of a host")
    parser.add_argument("host")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    try:
        data = probe(args.host, args.port, args.timeout)
    except OSError as exc:
        print(f"connection failed: {exc}", file=sys.stderr)
        return 2
    if not any(data["supported"].values()):
        print("no TLS handshake succeeded", file=sys.stderr)
        return 2

    score, findings = grade(data["supported"], data["cert"])
    if args.json:
        print(json.dumps({"host": args.host, "port": args.port, "score": score,
                          "supported": data["supported"], "cert": data["cert"],
                          "findings": findings}, indent=2))
    else:
        print(render(args.host, args.port, data["supported"], data["cert"], score, findings))
    return 0 if not findings else 1


if __name__ == "__main__":
    sys.exit(main())
