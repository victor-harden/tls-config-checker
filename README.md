# tls-config-checker

Probe a TLS endpoint to see which protocol versions it accepts, read the
certificate's subject and expiry, and score the configuration. Useful before and
after a hardening change on infrastructure you operate.

## Features

- Tests TLS 1.0, 1.1, 1.2 and 1.3 availability.
- Reads certificate subject, issuer and expiry date.
- Score with clear findings (legacy protocols enabled, certificate expiring soon).
- JSON output, configurable port and timeout.
- Pure grading functions covered by unit tests; no network needed for the suite.

## Installation

```bash
git clone https://github.com/victor-harden/tls-config-checker.git
cd tls-config-checker
```

## Usage

```bash
python3 tls_check.py example.com
python3 tls_check.py example.com --port 8443 --json
python3 tls_check.py 127.0.0.1 --timeout 3
```

Exit codes: `0` good configuration, `1` findings, `2` connection error.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Scope

Probe only hosts you own or are authorized to test. A TLS handshake is not
intrusive, but authorization still applies.

## License

MIT — see [LICENSE](LICENSE).
