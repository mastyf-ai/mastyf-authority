# SOC 2 and ISO 27001: how Mastyf Authority supports your controls

SOC 2 is a report on an organisation, not on a piece of software. When you run Authority yourself, it
becomes part of **your** controls, and your auditor tests how you run it. This page lists the Trust Services
Criteria it helps with, the evidence it produces, and what stays your responsibility.

Evidence for a period, in one signed file:

```
authority evidence --state /var/lib/authority --policy policy.json --since 2026-10-01 --until 2027-01-01 --out evidence.zip
authority evidence-verify evidence.zip --public-key authority.pub.pem
```

It contains the audit-log verification result, decision counts, every approval, freeze and failover, an
access review of every identity, and fingerprints of the policy, model and callers files. Every line comes
from the signed, hash-chained audit log, and the bundle's manifest is signed, so a changed file is caught.

| Criterion | What Authority does | Evidence | Your part |
|---|---|---|---|
| CC6.1 Logical access | deny by default; one caller key or SSO token per identity; per-identity allowed actions; data keys released only for approved actions | `access_review.csv`, `config.json`, `THREAT-MODEL.md` | issue and revoke caller keys; connect your identity provider |
| CC6.2 / CC6.3 Authorise, review, remove access | sensitive actions need a named approver, never the requester; approvals signed with the approver's own key or passkey | `approvals.csv`, `access_review.csv` | periodic access review using the bundle; remove leavers from the policy and IdP |
| CC6.6 Boundary protection | TLS 1.3 at the gateway; mTLS to the key service; network policies in the Helm chart | `tools/security_scan.py` output, Helm values | network design around it |
| CC6.7 Data in transit and movement | data budgets per identity (24 h, 7 d, 28 d), enforced by the key service | key-service journal (budget refusals), `config.json` (the policy that sets the budgets) | set budgets (`authority learn`) |
| CC6.8 Malicious software | signed images, SBOMs, provenance; dependency and code scanning in CI | release assets, CI logs | verify signatures before deploying (`cosign verify`) |
| CC7.2 Monitoring | every decision signed into the audit log; OCSF export to your SIEM; Prometheus metrics and alerts | SIEM records, `deploy/monitoring` | watch the alerts; keep SIEM retention |
| CC7.3 / CC7.4 Incident evaluation and response | freezes, burst freezes, undo windows; every freeze and unfreeze recorded with reason and operator | `freezes.csv` | an incident process and on-call |
| CC8.1 Change management | policy, model and callers fingerprints; policy version in every decision; signed releases | `config.json` across periods | review policy changes before deploying them |
| A1.1 / A1.2 Availability | hot standby, gateway failover, key-service cluster; tested under constant faults | `failovers.csv`, `artifacts/partition_chaos*.json`, `OPERATIONS.md` | run at least two engines and three key-service nodes; backups |
| A1.3 Recovery | snapshots plus audit-log replay; verification at start | `OPERATIONS.md` (Backup and restore) | test a restore each quarter |
| C1.1 Confidentiality | record keys wrapped by a KEK; record contents never pass through the engine | `THREAT-MODEL.md` | KEK custody (HSM or cloud KMS) |
| PI1 Processing integrity | grants single-use, short-lived and bound to the exact action; every record hash-chained and signed | `integrity.json` | |

ISO 27001:2022 Annex A, the same features: A.5.15–5.18 (access control, identities, authentication,
access rights), A.8.2 (privileged access), A.8.5 (secure authentication), A.8.15 (logging), A.8.16
(monitoring), A.8.24 (cryptography), A.8.32 (change management).

## What this page does not claim

- Authority itself does not have a SOC 2 report. A hosted Mastyf service would need its own (an independent
  auditor and, for Type II, an observation period of several months).
- The criteria above are met by how you run Authority, not by installing it.
