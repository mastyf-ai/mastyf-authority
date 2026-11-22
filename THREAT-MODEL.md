# Threat model

What Mastyf Authority defends, against whom, how, and what it does not cover. Each line names the code or
the test that shows it. Kept with the code; updated when either changes.

## What it protects

A decision before an action happens: may this identity (person, service, AI agent) do this, now, to this
resource? The things worth protecting:

| Asset | Where it lives | Why it matters |
|---|---|---|
| Record keys (data custody) | key service (Rust), KEK-wrapped, journaled | without a released key, encrypted records cannot be read even by a compromised app |
| Grant signing key | engines (one shared key) | anyone holding it can mint grants (bounded by the key service's budgets and fences) |
| Audit log | engines, hash-chained and signed, 0600 | evidence; also the state an engine is rebuilt from |
| Freezes, approvals, denials | audit log + key-service floor | a confirmed freeze must hold through any failover |
| Policy, model, budgets | config + learned state | weakening them weakens every decision |

## Who attacks

1. **Outside attacker with a stolen credential** (API key, cloud key, session token).
2. **Malicious or compromised insider**, including a hijacked admin account.
3. **Hijacked AI agent** (prompt injection in content it reads).
4. **Attacker on the network** between components.
5. **Attacker who has compromised one component** (an engine host, a gateway host).
6. **An attacker who knows the system exactly** (the code is public): adaptive, stays under every limit.

## STRIDE

| Threat | Example | Defence | Shown by |
|---|---|---|---|
| Spoofing | caller claims another identity | caller key or SSO token maps to one identity; the action's identity must be the caller's own (gateway and engine) | `tests/test_server.py`, `tools/sso_e2e.py` |
| Spoofing | forged approval | approvals signed by the approver's own key or passkey; weak/small-order Ed25519 keys refused | `tests/test_wycheproof.py`, `test_passkey_approvals.py` |
| Spoofing | stolen key used from the thief's machine | known networks per identity: new network asks (always for stable identities and root) | `origins.py`; flaws.cloud: 119/120 replayed sessions caught at the first call |
| Tampering | edit the audit log | hash chain + signature on every record; verified at start, on replication, before SIEM export | `test_audit_snapshot.py`, `test_siem.py` |
| Tampering | replay or alter a grant | grants single-use, short-lived, bound to the exact action fingerprint, signed | `test_rust_differential.py` |
| Repudiation | "I never approved that" | every approval, denial, freeze and decision is a signed audit record, exportable as OCSF | `siem.py` |
| Information disclosure | bulk exfiltration | data budgets per identity: per 24 h, per 7 days, per 28 days, enforced by the key service | `tools/adaptive_attack.py`: an attacker that never triggers a question gets at most ~1.4-1.7x the victim's normal month |
| Information disclosure | network sniffing | TLS 1.3 only at the gateway; mTLS to the key service; replication requires TLS off loopback | `tools/security_scan.py` (testssl) |
| Denial of service | flood the gateway | per-caller rate limit, connection cap, slow-down on bad keys, strict HTTP parser (no smuggling) | `tests/test_rust_gateway.py`, fuzzing |
| Denial of service | kill the active engine | hot standby, semi-synchronous replication, gateway failover in 2-10 s | `test_failover.py`, `tools/k8s_e2e.py`, `tools/partition_chaos.py` |
| Elevation of privilege | split brain after a network split | key service hands out strictly increasing epochs; a replaced engine's grants and confirmations are refused | `formal/Failover.tla` (TLC, 4.8 M states), `test_failover.py` |
| Elevation of privilege | agent does more than its task | agent sessions: manifest approved by the person's passkey; out-of-task actions refused; 3 strikes revoke | `agents.py`; 500/500 hijacked SWE-agent runs stopped |
| Elevation of privilege | hijacked admin locks out other admins | crown-jewel rules (acting on admins or protected resources always asks), undo windows and burst freezes | Wikipedia admin log: 60/60 hijacked admins stopped at the first action |

## AI-specific threats (MITRE ATLAS)

| ATLAS technique | How it applies | Defence | Limit |
|---|---|---|---|
| AML.T0051 LLM Prompt Injection | text an agent reads makes it act for the attacker | the agent can only do what its approved manifest allows; untrusted-provenance arguments need the person's confirmation | an injection that uses only approved actions is not stopped here: a typo-named package from an approved index, secrets copied into the agent's own pull request (measured: 0/50 each). Needs package allow-lists and secret scanning of the diff. |
| AML.T0015 Evade ML Model | stay under the risk model's thresholds | the model is one layer: budgets, origins, crown-jewel rules, undo windows and bait records do not depend on it | measured with a white-box adaptive attacker (`tools/adaptive_attack.py`) |
| AML.T0020 Poison Training Data | be active during the learning period so attacks look normal | learning only from a period believed clean; approved actions join a baseline only after a person approves them; budgets learned with a margin, not from the maximum | an attacker already inside during learning is baked in (documented in `learn.py`) |
| AML.T0043 Craft Adversarial Data | craft actions that score low | per-identity calibration, novelty layer, hard limits independent of scores | |
| AML.T0024 Exfiltration via ML Inference API | probe decisions to learn the model | decisions say why, not the score threshold; probing generates escalations a person sees; rate limits | the public code reveals the model's features |

## Trust boundaries

```
 callers ──TLS 1.3──> gateway ──localhost / pod network──> engine (active)  ──mTLS──> key service (+ standby, witness)
                         │                                    │  replication (TLS)
                         └── SSO: checks IdP tokens            └──> engine (standby)
```

- The engine trusts an identity header **only** from the gateway's own key.
- The key service trusts nothing it did not verify: grant signatures, epochs, budgets, fences and floors are
  all checked there, so a compromised engine can mint grants only within the budgets and only while it is
  the current epoch.
- Network policies (Helm) let only the gateway reach engines and only engines reach the key service.

## Not covered (by design or not yet)

- **A compromised key service host**: it holds the record keys; protect it like a KMS (separate nodes,
  HSM-backed KEK where available).
- **The engine signing key stolen**: grants can be minted up to the key service's budgets; rotate the key
  and fence a new epoch. A quorum of signing nodes (`quorum.py`) removes the single key.
- **Approvers who approve anything**: two-person rules and overrun caps bound it; they do not replace judgement.
- **Independent review**: everything above is our own testing (and public datasets). An independent audit
  is planned (OSTIF application drafted in `docs/applications/`).
