# Phinehas SDKs

> **The Spear: Active Defense & Threat Severance Middleware**  
> Terminate automated reconnaissance crawlers, malicious probes, and exploit scripts before they reach application logic.

This repository (`github.com/phinehas-hq/sdks`) contains the multi-language client SDKs and the shared compliance engine for the Phinehas security platform.

---

## 1. Architecture Overview

```
sdks/
├── compliance/                      # Canonical JSON test suites (SSOT)
│   ├── rfc8615_vectors.json         # RFC 8615 negative lookahead test cases
│   ├── normalization_vectors.json   # Anti-bypass path normalization vectors
│   └── explicit_traps.json          # Default blacklist signatures (CMS, DBs, Dumps)
│
└── packages/
    ├── js/                          # Node.js / TypeScript (Yarn Workspaces)
    │   └── packages/
    │       ├── core/                # Core engine, normalizer, BanStore, LRU
    │       ├── node/                # Express & raw HTTP middleware (@phinehas/node)
    │       ├── nestjs/              # NestJS middleware module (@phinehas/nestjs)
    │       └── next/                # Next.js Edge/Server guard (@phinehas/next)
    │
    ├── python/                      # Python SDK (FastAPI, Starlette) via uv
    ├── go/                          # Golang SDK (net/http, Gin, Chi)
    └── php/                         # PHP SDK (Laravel 11, Symfony) via Composer
```

---

## 2. Core Security Mechanism

1. **Active TCP Severance:** Terminates underlying TCP sockets immediately (`req.socket.destroy()`, ASGI disconnect, or Go hijack `Close()`) to starve attacker tools of diagnostic feedback.
2. **RFC 8615-Compliant Wildcard Trapping:** Protects sensitive dotfiles (`.env`, `.git`, `.aws`, `.kube`) while safely exempting standard `.well-known` endpoints:
   ```regex
   ^\/\.(?!well-known(\/|$))[a-zA-Z0-9_\-\.]+
   ```
3. **Deterministic Anti-Bypass Normalization:** Request paths pass through a 6-stage sanitization pipeline (Hex URL decoding, backslash conversion, duplicate slash collapsing, directory traversal resolution, lowercasing, trailing slash removal) before rule matching.
4. **Zero-Allocation Pluggable Persistence:** In-memory LRU cache ($O(1)$, capped to 25k entries) or distributed Redis sync with L1 read shielding.

---

## 3. Package Management & Standards

* **Node.js:** Managed with **Yarn** (`yarn workspaces`).
* **Python:** Managed with **`uv`** and `pyproject.toml`.
* **Go:** Standard Go Modules (`go.mod`).
* **PHP:** Composer (`composer.json`).
* **Compliance Suite:** Shared JSON test vectors in `/compliance` ensure 100% behavioral parity across all language implementations.

---

## 4. Contributing & License

All SDKs are released under the [Apache-2.0](LICENSE) License.  
Maintained by [Phinehas HQ](https://github.com/phinehas-hq).
