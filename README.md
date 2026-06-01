# Ottergate

Ottergate is a Go-based DNS and HTTP/HTTPS egress gateway designed to restrict and filter network access for untrusted code execution sandboxes.

This project is a Go port of the original Node.js implementation: [zonzon](https://github.com/opensecurity/zonzon).

---

## How it works

```
[ Sandbox Client ] ---> ( Ottergate ) ---> [ Public Internet ]
```

1. **System Call Isolation**: Your sandbox runtime (e.g., gVisor / `runsc`) isolates the OS kernel.
2. **Network Egress Containment**: Ottergate intercepts and filters DNS and HTTP/HTTPS traffic to prevent SSRF and exfiltration.

---

## Features

- **DNS Interception**: Serves local DNS mappings or forwards permitted queries to upstream resolvers.
- **SSRF Protection**: Blocks private RFC 1918 subnets and cloud provider metadata services (`169.254.169.254`).
- **Egress Filtering**: Restricts outbound connections to specific IP addresses and wildcard domains (e.g., `*.endpoint.ltd`).
- **L7 Proxying & mTLS**: Proxies HTTP/HTTPS (via SNI) traffic, injects custom headers, and validates server certificates / upstream client certificates (mTLS).
- **Secret Encryption**: Decrypts sensitive configuration headers in memory using AES-256-GCM.

---

## Quick Start

### 1. Build and Launch
```bash
docker compose build
docker compose up -d
```

### 2. Run Tests
Runs syntax checks, Go unit tests, proxy integration tests, and sandbox verification:
```bash
./tests/run_all_tests.sh
```

---

## Configuration

Configurations are stored in `config/config.json`:

```json
{
  "port": 53,
  "httpPort": 80,
  "httpsPort": 443,
  "fallbackDns": "1.1.1.1",
  "firewall": {
    "defaultPolicy": "deny",
    "allowlist_domains": [
      "*.openai.com",
      "*.github.com"
    ],
    "blocklist_domains": [
      "*.malicious-domain.example",
      "malicious-domain.example"
    ],
    "allowlist_ips": [
      "127.0.0.1",
      "172.21.0.100"
    ],
    "blocklist_ips": [
      "169.254.169.254",
      "100.100.100.200"
    ],
    "allowlist_ranges": [
      "0.0.0.0/0",
      "127.0.0.0/8"
    ],
    "blocklist_ranges": [
      "10.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16",
      "127.0.0.0/8",
      "169.254.0.0/16"
    ]
  }
}
```

---

## License

Apache License 2.0.
