# OWASP ASVS 4.0.3, Level 2: self-assessment

Our own assessment, chapter by chapter, with where each answer can be checked. It is not an independent
audit (one is planned). "Partly" and "No" are listed with what would close them.

| Chapter | Status | Evidence | Gap |
|---|---|---|---|
| V1 Architecture, design, threat modelling | Yes | `THREAT-MODEL.md`; components split by trust (gateway, engine, key service) with network policies; failover protocol model-checked (`formal/Failover.tla`) | |
| V2 Authentication | Partly | API keys stored only as SHA-256 digests; SSO tokens (OIDC RS256/ES256, issuer, audience, expiry checked; `tools/sso_e2e.py` against Keycloak); approvers sign with their own Ed25519 key or a passkey (WebAuthn); failed-auth slow-down per address | the browser pages (approve, enroll) use keys and passkeys, not an OIDC browser login; API keys do not expire on their own (rotate by replacing the callers file) |
| V3 Session management | N/A | no cookies or server sessions: every request carries its own key or token; agent sessions are short-lived (≤ 8 h), bound to a passkey-approved manifest and revocable | |
| V4 Access control | Yes | deny by default (unknown identity, malformed request, engine down: DENY); per-identity allowed actions; an action's identity must be the caller's own (gateway and engine); admin-only endpoints; approvers cannot approve their own requests | |
| V5 Validation, sanitisation, encoding | Yes | JSON objects only, re-encoded by the gateway; strict HTTP parser (no chunked, no duplicate lengths, header/body limits; fuzzed in CI); field types and lengths checked (`actions.py`); no input reaches a shell, SQL or a template | |
| V6 Stored cryptography | Yes | Ed25519 (grants, audit, approvals; Wycheproof vectors pass in Python and Rust; weak and mixed-order keys refused; strict verification), AES-256-GCM per-record keys wrapped by a KEK; KEK rotation; keys owner-only (0600), KEK kept in memory in Kubernetes | engine signing-key rotation is a manual procedure (`OPERATIONS.md`) |
| V7 Error handling and logging | Yes | every decision, approval, freeze, promotion signed into a hash-chained log; errors return generic messages; only a network prefix of a caller's address is kept; OCSF export to a SIEM that forwards only verified records (`siem.py`) | |
| V8 Data protection | Partly | record contents never pass through the engine (keys are released by the key service); budgets per 24 h / 7 d / 28 d | the audit log is not encrypted at rest by the application (use encrypted volumes; it holds identities and resource names, not record contents) |
| V9 Communication | Yes | TLS 1.3 only at the gateway (testssl: no older protocol offered); mutual TLS between engines and the key service and between key-service nodes; replication refuses plain HTTP off loopback | |
| V10 Malicious code | Yes | SBOMs, signed images (cosign) and build provenance on every release; cargo-deny, cargo-audit, pip-audit, bandit, Semgrep, CodeQL, OpenSSF Scorecard in CI; JSON-only model files (no pickle) | |
| V11 Business logic | Yes | rate limits, data budgets, burst freezes on irreversible actions, two-person rules, undo windows, crown-jewel rules; the server's clock, never the caller's | |
| V12 Files and resources | N/A | no file uploads; the script-integrity check takes script text and never executes it | |
| V13 API and web service | Yes | `openapi.yaml`; OWASP ZAP API scan (117 checks pass; one false positive documented); content types enforced; query strings refused except one documented read | |
| V14 Configuration | Yes | containers run as non-root with a read-only root filesystem, all capabilities dropped, seccomp RuntimeDefault; Helm chart clean in kube-linter and checkov (remaining: pin images by digest, supported via `image.digests`); security headers and a strict CSP on the pages | |

How to re-check: `pytest tests`, `tools/security_scan.py` (testssl + ZAP), `tools/sso_e2e.py`, `tools/k8s_e2e.py`,
`kube-linter lint` / `checkov` on `helm template` output, and TLC on `formal/Failover.tla`.
