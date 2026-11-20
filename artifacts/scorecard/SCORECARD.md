# Security scorecard

Generated 2026-11-19 16:55 in 806 s. Everything here was run against the actual code; nothing is estimated.

## Code and configuration

- **Dependency audit:** Python: 0 known vulnerabilities (50 packages). Rust: 0 vulnerabilities, 0 warnings.
- **Static analysis:** bandit: {'LOW': 10, 'MEDIUM': 1} (MEDIUM = the gated legacy pickle loader). semgrep security packs: {'INFO': 2}. clippy -D warnings: clean. Rust core: #![forbid(unsafe_code)].
- **TLS (testssl.sh on the gateway):** 86 checks; protocol/cipher/vulnerability problems: none; 5 findings about the throwaway test certificate only (self-signed, 1-day).

- **Automated tests:** 129 passed in 792.47s (0:13:12)
- **Fuzzing:** Rust key service 50,000 hostile requests (tests/test_rust_fuzz.py with FUZZ_EXAMPLES=50000); gateway 300 mutated/garbage requests; crash tests (SIGKILL) for journal, failover and undo windows.

## Attack scorecard (MITRE ATT&CK / ATLAS)

Real components, two attackers: **stolen** credentials through the authority, and **bypass** (the authority defeated; the attacker signs its own grants).

Totals: BLOCKED 9, CAPPED 5, DELAYED 5, DETECTED 3, NOT COVERED 6

| Technique | Name | Tactic | Stolen credentials | Authority bypassed | Outcome | Why |
|---|---|---|---|---|---|---|
| T1078 | Valid Accounts (stolen password/session) | Initial Access | 0 records | 0 records | **BLOCKED** | device binding: a login without the person's registered device gets no keys |
| T1550.004 | Use Alternate Authentication Material: Web Session Cookie | Lateral Movement | 0 records | 0 records | **BLOCKED** | same: cookies and tokens are not the device key |
| T1213 | Data from Information Repositories (malware on the laptop) | Collection | 5000 records/24h | 5000 records/24h | **CAPPED** | per-person data budget (5,000/24h) holds even with the authority bypassed |
| T1567 | Exfiltration Over Web Service | Exfiltration | 0 records | 0 records | **BLOCKED** | unregistered destination: authority denies; key service budget for it is 0 |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration | DENY | n/a (no data keys) | **BLOCKED** | denied destinations (paste sites, onion, tunnels) |
| T1555 | Credentials from Password Stores | Credential Access | 0 secrets/24h | 20 secrets/24h | **CAPPED** | secret budget 20/24h |
| T1530 | Data from Cloud Storage (stolen service key) | Collection | 0 records/24h | 20000 records/24h | **CAPPED** | service budget bound to its own destination |
| T1005 | Data from Local System: harvesting (bait record) | Collection | DENY | key service freezes on bait ids too | **DETECTED** | bait record touched: identity frozen at once |
| T1485 | Data Destruction (mass storage deletion) | Impact | same as bypass | 0 executed of 12 | **DELAYED** | 24 h undo window; 6th request in an hour froze the identity and cancelled all |
| T1486 | Data Encrypted for Impact (overwrite files) | Impact | same as bypass | person 0 / backup job 12,000 files in 24h | **CAPPED** | file-write budgets at the storage gate (12,000/24h for the backup job, only into the vault, 0 for people); storage keeps prior versions |
| T1490 | Inhibit System Recovery (delete backups) | Impact | always escalates | refused | **BLOCKED** | needs 2 approvers AND a 72 h time lock anyone can cancel |
| T1657 | Financial Theft (large payment) | Impact | same as bypass | held 4 h | **DELAYED** | payments over the threshold wait 4 h; cancellable; burst freezes |
| T1098 | Account Manipulation (grant admin) | Persistence | same as bypass | held 1 h | **DELAYED** | admin grants wait 1 h, the person and security are alerted |
| T1584.002 | DNS hijack of own domain | Resource Development | same as bypass | held 1 h | **DELAYED** |  |
| T1534 | Internal Spearphishing (mass mail from a hijacked account) | Lateral Movement | same as bypass | held 1 h | **DELAYED** |  |
| T1195.002 | Compromise Software Supply Chain (publish skimmer) | Initial Access | integrity check denies | refused at the CDN gate | **BLOCKED** |  |
| T1059.007 | JavaScript injected via a trusted vendor (OptimJack) | Execution | - | 0 of 3 variants served | **BLOCKED** | pinned first-party copy; changes checked; strict CSP |
| T1199 | Trusted Relationship (vendor platform pushes code to all customers) | Initial Access | - | 2 of 188 customers | **CAPPED** | campaign detector freezes the indicator after 2 customers |
| T1070 | Indicator Removal (rewrite protected history) | Defense Evasion | DENY | refused | **BLOCKED** | protected branches need 2 approvers at the Git gate |
| AML.T0051 | LLM Prompt Injection -> agent exfiltration (MITRE ATLAS) | Exfiltration | DENY/DENY/DENY, then DENY | session cap also in key service | **BLOCKED** | out-of-task actions refused; 3 attempts revoke the session and alert the person |
| T1021 | Remote Services (lateral movement, LANL real red team) | Lateral Movement | 374 of 691 logins stopped | - | **DETECTED** | measured: 54% stopped by the device lock; 23/50 compromised users flagged at 5 alerts/day (supervised) |
| TA0009 | Insider data theft (CERT r2-r6.2, real labels) | Collection | 179 of 187 insiders flagged | - | **DETECTED** | novelty score, 5 reviews a day; graded against CERT's official insider list (answer files also name victims and email recipients); method chosen on r4-r5 only, held-out r2/r6: 9 of 11; budgets cap the rest |
| T1190 | Exploit Public-Facing Application | Initial Access | - | - | **NOT COVERED** | a bug in the customer's app; we limit what the exploited identity can then take |
| T1203 | Exploitation for Client Execution | Execution | - | - | **NOT COVERED** | browser/OS bugs; endpoint protection; we stop the delivering scripts |
| T1566 | Phishing (inbound) | Initial Access | - | - | **NOT COVERED** | mail security; a phished login without the device gets nothing (T1078) |
| T1498 | Network Denial of Service | Impact | - | - | **NOT COVERED** | DDoS protection; our gateway caps connections and rate |
| T1052 | Exfiltration Over Physical Medium (USB) | Exfiltration | - | - | **NOT COVERED** | endpoint DLP; budgets cap what reached the laptop |
| T1113 | Screen Capture / reading what the person may see | Collection | - | - | **NOT COVERED** | a legitimate viewer's own access; watermarking traces leaks |


## AI agents: AgentDojo v1.2, worst case

Assumes the agent is hijacked on **every** task (without controls: 100% attack success). 609 task x attack pairs.

| Approval style | Attack succeeds | Blocked | Held for the person |
|---|---|---|---|
| Exact task approved (recipients named) | 1.6% | 98.4% | 0.0% |
| + runtime marks inputs from untrusted content | 0.0% | 98.4% | 1.6% |
| Loose approval (no recipients) - now refused by policy | 13.6% | 86.4% | - |

Ordinary work: 97 of 97 user tasks complete without any confirmation. Caveat: approvals are taken from AgentDojo's reference solutions (an ideal planner); 9 attacker goals have no reference action sequence and are not scored.

## Damage ceiling

### Damage ceiling: 1 compromised identity, passwords/sessions only

Assumes the authority is bypassed and compromised approvers sign anything. Bait records, the risk model and people noticing are not counted.

| Data class | Worst identities | Records per 24 h | Records per 30 days |
|---|---|---|---|
| ssh.key | human:bob | 100 | 3,000 |
| secret | human:bob | 20 | 600 |
| crm.customer | svc:export-job | 20,000 | 600,000 |
| prod.files | svc:backup | 12,000 | 360,000 |
| system.config | agent:support-bot | 0 | 0 |

Why (worst combination per class):

Irreversible actions (undo windows): nothing below happens before its delay; anyone on the security team or an approver can cancel; at most 5 can be queued per identity per hour (more freezes the identity and cancels them all):

- backup.delete: 72 h
- key.delete: 72 h
- storage.delete (>= 100): 24 h
- account.delete: 24 h
- payment.send (>= 1,000,000): 4 h
- email.bulk_send (>= 500): 1 h
- dns.change: 1 h
- permission.grant: 1 h


### Damage ceiling: 3 compromised identities, passwords/sessions only

Assumes the authority is bypassed and compromised approvers sign anything. Bait records, the risk model and people noticing are not counted.

| Data class | Worst identities | Records per 24 h | Records per 30 days |
|---|---|---|---|
| ssh.key | human:bob, human:dana, human:erin | 150 | 4,500 |
| secret | human:bob, human:dana, human:erin | 30 | 900 |
| crm.customer | human:bob, human:dana, svc:export-job | 30,000 | 900,000 |
| prod.files | human:bob, human:dana, svc:backup | 18,000 | 540,000 |
| system.config | agent:support-bot, human:alice, human:bob | 0 | 0 |

Why (worst combination per class):
- ssh.key / human:bob: 2 compromised approvers can sign overruns: +50/24h
- secret / human:bob: 2 compromised approvers can sign overruns: +10/24h
- crm.customer / svc:export-job: 2 compromised approvers can sign overruns: +10,000/24h
- prod.files / svc:backup: 2 compromised approvers can sign overruns: +6,000/24h

Change gates: with agent:support-bot, human:bob, human:dana compromised, approvals reach quorum: protected-branch rewrites allowed (quorum); backups: none within 72 h; after that only if nobody cancels.

Irreversible actions (undo windows): nothing below happens before its delay; anyone on the security team or an approver can cancel; at most 5 can be queued per identity per hour (more freezes the identity and cancels them all):

- backup.delete: 72 h
- key.delete: 72 h
- storage.delete (>= 100): 24 h
- account.delete: 24 h
- payment.send (>= 1,000,000): 4 h
- email.bulk_send (>= 500): 1 h
- dns.change: 1 h
- permission.grant: 1 h



## Detection on real data (no attack examples used), 5 alerts/day

| CERT release | Isolation forest | Novelty (live engine) |
|---|---|---|
| r2 | 1 of 1 | 1 of 1 |
| r4.1 | 1 of 4 | 4 of 4 |
| r4.2 | 20 of 72 | 69 of 72 |
| r5.1 | 1 of 17 | 5 of 17 |
| r5.2 | 46 of 99 | 83 of 99 |
| r6.1 | 1 of 9 | 3 of 9 |
| r6.2 | 2 of 29 | 3 of 29 |

LANL red team: device lock stops 374 of 691 attacker logins (54%) for ~3% of users confirming a new machine per day; supervised model flags 23 of 50 held-out compromised users.

## Not covered by this layer

Software bugs in the customer's own apps and in browsers/OSes, inbound phishing delivery, network DDoS, USB copying on the endpoint, and people misusing what they may legitimately see. The ceiling and watermarks limit and trace the damage of each; they do not prevent the first step.

## Not yet done

Mathematical proof of the Rust budget logic (needs the Kani toolchain), an outside penetration test, real-model AgentDojo runs (needs an LLM API budget).
