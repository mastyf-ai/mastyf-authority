# Operating Mastyf Authority

How to run Authority in production: what to deploy, how it fails, and what to do when it does.

- [What runs](#what-runs)
- [Deploy on Kubernetes](#deploy-on-kubernetes)
- [Deploy on servers (systemd)](#deploy-on-servers-systemd)
- [Sizing](#sizing)
- [How it fails](#how-it-fails)
- [Monitoring and alerts](#monitoring-and-alerts)
- [Runbooks](#runbooks)
- [Backup and restore](#backup-and-restore)
- [Upgrades](#upgrades)
- [Audit log retention](#audit-log-retention)

## What runs

| Component | What it does | State | Failure behaviour |
|---|---|---|---|
| **Gateway** (Rust) | The only thing callers reach: TLS 1.3, per-caller keys and rate limits, strict HTTP parsing; routes to the active engine and promotes a standby when the active one dies | none | Callers retry another gateway replica |
| **Engine** (Python), active + standby | Decides: policy, budgets, approvals, behavioural model; writes the signed audit log | audit log, snapshots | The standby takes over in about 3 s; until then decisions are refused (fail closed) |
| **Key service** (Rust), primary + synchronous standby + witnesses | Holds the record keys; releases them only for a valid grant and within the data budget | journal + KEK | The standby takes the witness lease and continues with nothing lost; a single node restarts in about a second |

The engines share **one signing key**: to the key service they are one authority. The standby pulls every audit
record from the active engine, checks its hash chain and signature, and applies it, so it holds the same state.
When the gateway promotes it, it **first raises the key service's engine epoch** ("fencing"): from then on any
grant from the old engine is refused, even if the old engine is still running somewhere.

Freezes, unfreezes, approvals and denials reach the standby **before** the caller gets an answer, so a failover
can never lose them. Routine decisions are replicated within milliseconds; a failover can lose the last few,
which costs nothing for safety because data budgets are counted by the key service, not the engine.

## Credentials

To try everything on one computer, `authority local` makes all of these for you (see the README). For a real
deployment, make them yourself:

**API keys and the callers file.** Every caller (a person, a service, an AI agent, the admin, the standby
engine) gets its own random key, bound to exactly one identity. The engine stores only each key's SHA-256:

```bash
key=$(openssl rand -base64 33 | tr '+/' '-_')                                  # give this to the caller only
printf '%s' "$key" | openssl dgst -sha256 | awk '{print $NF}'                 # goes into callers.json
```

```json
{"<sha256 of alice's key>": "human:alice", "<sha256 of the admin key>": "admin", "<sha256 of the standby's key>": "replica"}
```

Point the engine at it with `AUTHORITY_CALLERS=/path/callers.json`. Keep the keys themselves in your secret
store. To revoke a key, delete its line and restart.

**Approvers.** Each approver signs with a passkey (recommended) or an Ed25519 key:

- *Passkeys*: set `AUTHORITY_RP_ID` (the console's domain, e.g. `authority.corp.example`),
  `AUTHORITY_ORIGIN` (`https://authority.corp.example`) and `AUTHORITY_DEVICES` (the devices file, shared with the
  key service). Approvers add their passkeys on the console's *Devices* page. The first passkey of each person
  needs two other approvers to agree.
- *Ed25519 keys*: each approver runs `authority approver keygen` on their own machine. The private key stays
  in `~/.mastyf/approver.pem`; the command prints the public key. Collect them into a file
  `{"human:dana": "-----BEGIN PUBLIC KEY-----..."}` and set `AUTHORITY_APPROVER_KEYS` to it.

Who may approve is set in the policy (`"approver": true` on a human identity). Single sign-on can replace the
API key for the console, but approving still needs the person's passkey: see [Single sign-on](#single-sign-on).

## Deploy on Kubernetes

The Helm chart is in [`deploy/helm/mastyf-authority`](deploy/helm/mastyf-authority) and is attached to every release.
It runs two gateways, two engines (pod `-0` starts active) on different nodes, and the key service (optionally
two nodes with synchronous replication and a witness: `keyservice.ha.enabled=true`), with
network policies that let only the gateway reach the engines and only the engines (and the namespaces you
choose) reach the key service. Every pod runs as a non-root user with a read-only root filesystem, no Linux
capabilities and the default seccomp profile.

1. **Create the secrets** (never in values files):

   ```bash
   kubectl create secret generic mastyf-signing-key --from-file=signing_key.pem --from-file=authority.pub.pem
   kubectl create secret generic mastyf-callers --from-file=callers.json        # sha256(key) -> identity, incl. "replica" and "admin"
   kubectl create secret generic mastyf-approvers --from-file=approvers.json    # approver -> Ed25519 public key PEM
   kubectl create secret generic mastyf-replica-key --from-file=replica.key     # the "replica" caller's bearer key
   kubectl create secret generic mastyf-kek --from-file=kek.b64                 # or keyservice.kekCommand with your KMS
   # TLS: gateway (tls.crt, tls.key, ca.crt; SAN <release>-gateway) and key service
   # (server.crt, server.key, ca.crt, clients-ca.crt, client.crt, client.key; SAN <release>-keyservice).
   # cert-manager's Certificate resources produce exactly these keys.
   ```

2. **Install** with your policy:

   ```bash
   helm install authority deploy/helm/mastyf-authority --set-file policy.json=policies/your-policy.json
   ```

3. **Check** that one engine is `active`, the other `standby`, at the same `seq` (see the chart's NOTES).

Tested end to end on a real Kubernetes cluster (kind, three nodes) on every chart change (`tools/k8s_e2e.py`):
install; decisions through the gateway; killing the active engine pod (standby promoted in about 4-10 s, freezes
kept, the old pod rejoins as standby); taking the key-service primary down (the other node takes over in about 35
s, the old one rejoins as standby); a second engine failover that fences the new key-service primary; and the
network policies (a stray pod reaches the gateway, not the engines or the key service).

Notes from that testing:
- The key service keeps its state in `/state/data` (a directory it owns), because a volume's root belongs to root.
- With `secrets.kek`, an init container copies the KEK owner-only into memory: Kubernetes makes secret files
  group-readable when `fsGroup` is set, and the key service refuses a KEK others can read. With your KMS, use
  `keyservice.kekCommand` instead.
- Key-service HA needs `secrets.keyserviceHaTls` (one certificate whose SANs cover `<release>-ks-a-0.<release>-ks-a`,
  `<release>-ks-b-0.<release>-ks-b` and `<release>-witness-N.<release>-witness`). Use 3 witnesses in production.

Verify release images before you deploy them (keyless Sigstore signatures, build provenance):

```bash
cosign verify ghcr.io/mastyf-ai/mastyf-authority-gateway:v0.2.0 \
  --certificate-identity-regexp '^https://github.com/mastyf-ai/mastyf-authority/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/mastyf-ai/mastyf-authority-gateway:v0.2.0 --owner mastyf-ai
```

## Deploy on servers (systemd)

`deploy/` has hardened systemd units and a Caddy configuration. Run the two engines on different hosts:

```bash
# host A
authority serve --policy policy.json --state /var/lib/mastyf --role auto \
  --follow https://gateway.internal:8443 --peer https://gateway.internal:8443     # AUTHORITY_ORDINAL=0
# host B: same command with AUTHORITY_ORDINAL=1
mastyf-gateway --listen 0.0.0.0:8443 --tls-cert ... --tls-key ... --callers callers.json \
  --upstream hostA:8740 --upstream hostB:8740 --promote-key-file replica.key
```

Engines need `AUTHORITY_KEYSERVICE` (`unix:/path` or `tls:host:port` with `AUTHORITY_KEYSERVICE_CA/_CERT/_KEY`)
to fence on promotion, `AUTHORITY_REPLICA_KEY`, and `AUTHORITY_PEER_CA` (the CA of the gateway's certificate).

## Sizing

Measured on an Apple M-series laptop (10 cores) through the full stack: TLS gateway, engine with the
behavioural model, key service with its journal on disk, with real traffic (Los Alamos sign-ins, public
attack logs and a simulated company's work across 2,475 identities), using our internal replay harness.

| | Measured |
|---|---|
| Decisions per second, one active engine | about 2,400 through the TLS gateway, 4,800 direct over HTTP, 8,000 in-process (one CPU core; the model's tree walks run in Rust, `rust/native`). The rest of a decision is two Ed25519 signatures (already native code), JSON encoding and feature updates, so a full Rust engine would gain about 2–3x per core: shards are the way to scale |
| Decision latency | p50 4.5–10.5 ms, p99 19–26 ms through the gateway (48 concurrent clients) |
| Key release latency | p50 0.1 ms, p99 8 ms |
| Audit log | about 740 bytes per decision (roughly 60 GB/day at 1,000 decisions/s: see retention) |
| Snapshot | about 57 MB for 2,475 identities with full history; written in well under a second |
| Restart | about 6 s from snapshot + tail on an idle machine |
| Engine failover | 2.3–2.8 s on one host, 4–10 s on Kubernetes, from killing the active engine to decisions continuing |
| Key-service failover | about 5 s on Kubernetes (3-node cluster, primary killed); a node that comes back within its lease resumes at once |
| Shards | 2,407 decisions/s with one engine pair, 3,934 with two, 4,705 with four (one 10-core laptop running clients, gateway and engines, so four shards are limited by the machine; `tools/shard_bench.py`); across separate machines (Modal, one 2-CPU container per engine, six load machines each with its own gateway): 1,475 / 2,992 / 5,820 / 11,774 decisions/s with 1 / 2 / 4 / 8 engines, zero errors (7.98x with 8) |

Give each engine two dedicated cores and fast local SSD storage. For more than ~2,000 decisions per second
per engine pair, add shards (see "Scaling out: shards").

## Availability, measured

`tools/partition_chaos.py` runs three engines, a three-node key service and the gateway, sends decisions, freezes
and key releases continuously, and injects faults: killing or pausing an engine, cutting the active engine or a
standby off the network. It checks that no freeze is lost or undone and that no replaced engine's grant is
honoured.

| Fault rate | Availability (decisions answered) | Longest outage | Safety violations |
|---|---|---|---|
| one fault every 5 minutes, 1 hour (`artifacts/partition_chaos_realistic.json`) | 99.65% | 3 s | none |
| one fault every ~30 s, 30 faults (`artifacts/partition_chaos_3eng.json`) | 97.9% | 3 s | none |

A fault costs about 1.1 s of refusals on average (at most 4 s). At one fault an hour that is about 99.97%; at one a
day, 99.999%. These are extrapolations from measured outages, not a measured long-term figure: run two gateway
replicas, three engines and three key-service nodes on separate machines to get them.

## Container images

The gateway and key service are static binaries (rustls, no OpenSSL) on `distroless/static` (no shell, no C
library); the engine image installs Debian security updates at build time. A release fails if Trivy finds a fixable
HIGH or CRITICAL vulnerability in any image. Remaining unfixed Debian findings in the engine image (util-linux,
acl: mount and namespace tools) are not reachable: the container runs as non-root with a read-only root filesystem
and every capability dropped.

## Evidence for auditors

`authority evidence` writes a signed bundle for a period (approvals, freezes, failovers, access review, config
fingerprints, audit-log verification); see `SOC2-CONTROLS.md`.

## How it fails

Every failure fails **closed**: nothing is allowed or released that would not have been allowed with every
component healthy.

| What breaks | What callers see | Recovery |
|---|---|---|
| Active engine dies | Refusals (503) for about 3 s, then normal | Automatic: the gateway promotes the standby |
| Both engines down | Every decision refused | Start either engine; it restores from snapshot + log |
| Key service down | Releases refused; promotion refused (the standby stays standby rather than risk two engines whose grants both work) | Restart; it replays its journal |
| Gateway down | Connection errors | Other gateway replicas; restarts in under a second |
| Engine's disk full | Snapshots fail (alerted); the audit log is still written until the disk is truly full, then decisions fail closed | Free space; archive old segments |
| Power loss | Freezes, approvals and every key release survive; at most 0.2 s of routine decision records can be lost | Automatic: a half-written last line is cut back on start |
| Standby slow or detached when a freeze is confirmed | The freeze is confirmed anyway (availability), after the active engine records it as the **floor** in the key service | A standby that lacks the floor record can never be promoted; it catches up first (`formal/Failover.tla`) |
| Active engine cut off from the gateway but still running | Its grants and confirmations are refused by the key service within a second (it polls the key service, not only its peer) | Automatic; with `--role auto` it exits and rejoins as standby |
| Old engine comes back after a failover | It sees the newer active engine and stops deciding ("fenced"); with `--role auto` it rejoins as standby | Automatic; diverged records are moved aside, never deleted |

## Single sign-on

Callers can present tokens from your identity provider (Okta, Entra ID, Google, Keycloak, Ping, Auth0) instead of
Authority keys. The gateway checks them (RS256/ES256 only; issuer, audience, expiry) and maps a claim to an identity:

```
mastyf-gateway ... --oidc-issuer https://idp.example.com/realms/acme --oidc-audience authority \
  --oidc-jwks /etc/authority/jwks.json --oidc-claim preferred_username --oidc-identity-format human:{} \
  [--oidc-map map.json] --gateway-key-file /etc/authority/gateway.key
```

Refresh `jwks.json` from the provider's JWKS URL (it is re-read when it changes). `human:{}` maps `alice` to
`human:alice`; a format can never produce `admin` or `replica` - only an explicit `--oidc-map` entry can. Add the
gateway key's SHA-256 to the callers file as `"gateway"`: engines accept an identity from the gateway only with it.
Tested end to end against Keycloak (`tools/sso_e2e.py`).

**The approve and enroll pages** sign people in the same way (OIDC authorization code with PKCE; a public client,
no secret in the page). Register a public client with redirect URIs `https://<gateway>/approve` and
`https://<gateway>/enroll`, then set on the engines:

```
AUTHORITY_SSO_ISSUER=https://idp.example.com/realms/acme   AUTHORITY_SSO_CLIENT_ID=authority-web
```

and add that client id as an `--oidc-audience` on the gateway. The pages show "Sign in with your company account";
the token stays in the tab (session storage) and only says who the person is - approving still needs their passkey.

## Sending the audit log to your SIEM

`authority siem --state <dir> --to <target>` follows the audit log and sends every record as an OCSF 1.3 event
(decisions: API Activity; freezes, promotions, agent revocations: Detection Finding; approvals: User Access
Management). Targets: `opensearch+https://host:9200/<index>` (also Elasticsearch), `splunk+https://host:8088` (HEC,
token in `AUTHORITY_SIEM_TOKEN`), `webhook+https://...`, `file:/path`, `stdout`. Every record is verified (hash chain
and signature) before it is sent; it resumes from `<dir>/siem.pos`; event ids are log sequence numbers, so a resend
never duplicates. Measured into OpenSearch: 4,300 events/s. Run it next to the active engine (it reads the log).

## More standbys, and requests held during a failover

Run three engines (`engine.replicas: 3`, needs three nodes for the anti-affinity) for two standbys: a failover then
still leaves a standby, and while one standby rebuilds after a failover another is ready. The gateway tries every
standby in turn; the key service refuses any that lacks the newest confirmed records. The protocol is model-checked
with three engines too (`formal/FailoverFixed3.cfg`, 20 M states).

During a failover the gateway holds requests (default 3 s, `--hold-ms`) and sends them to the new active engine
instead of refusing them - only requests that certainly were not processed (no connection, or "not active").

## Scaling out: shards

One engine pair decides on one core. To go beyond it, run several engine pairs behind the same gateways and key
service and name them:

```
mastyf-gateway ... --shard eu=10.0.1.10:8740,10.0.1.11:8740 --shard us=10.0.2.10:8740,10.0.2.11:8740
# each engine of a pair: AUTHORITY_SHARD=eu (or us)
```

Each identity always lands on the same shard (rendezvous hashing); approvals, denials and freezes go to the shard of
the identity they concern; alerts, pending requests and metrics are merged across shards. Each pair fails over on
its own: the key service keeps an epoch and a floor per shard, so one pair's promotion never refuses another's
grants. Adding a shard moves about 1 in N identities to it, where they start a fresh baseline (warm-up). Team
budgets pool only within a shard.

## Monitoring and alerts

Each engine serves Prometheus metrics at `/metrics`: decisions by verdict and stage, frozen identities,
pending approvals, `authority_role` (1 active, 0 standby, -1 fenced), `authority_epoch`, replication lag and
last contact, unsynced audit records and snapshot age. Alert rules are in
[`deploy/monitoring/alerts.yml`](deploy/monitoring/alerts.yml) (and as a PrometheusRule in the chart).

## Runbooks

### No active engine
`AuthorityNoActiveEngine`. Every decision is being refused.
1. `GET /healthz` on each engine. If a standby is healthy, the gateway should have promoted it within 3 s: check the
   gateway log for `promote answered`. A `409 ... not fenced` means the key service is unreachable: fix that first.
2. If no engine is running, start one. It restores from its snapshot and the log after it.

### Fenced engine
`AuthorityEngineFenced` or `AuthorityTwoActiveEngines`. An engine was replaced during a failover. Grants from the
lower epoch are already refused by the key service. Restart it with `--role auto`: it rejoins as standby; if its
log holds records the new active engine never received, they are moved to `diverged-<time>/` in its state
directory (for investigation) and it resyncs.

### Not promotable
The gateway log says `promote answered ... not promotable: this engine does not hold confirmed record N`. The only
engines holding the newest confirmed freeze/approval are down. Bring one of them back; it starts active (or is
promoted) and the other copies from it. **Only if every copy is lost** (both disks gone), accept the loss explicitly:
`authority failover reset-floor --state <engine state dir> --accept-loss --reason "<what happened>"`. It is signed with
the engine key and journaled by the key service; freezes and approvals confirmed after the last surviving record are
gone, so re-apply them from the SIEM copy of the audit log. `authority failover status` shows the floor.

### Standby missing or lagging
`AuthorityStandbyMissing`, `AuthorityReplicationLag`. A crash now would mean downtime until restart. Check the
standby's log for `replication` errors: a chain or signature error means its copy does not match and it must be
rebuilt (empty state directory, same signing key).

### Audit log verification
`authority audit-verify --state <dir>` checks every record in every segment (hash chain and signatures).
Run it daily on a copy, and after any incident. An engine refuses to start if the log or snapshot was altered.

### KEK rotation
Without downtime: start the key service with the new KEK and `--previous-kek-file` (or `-command`); it re-wraps
every record key in the background (`{"op":"kek_status"}` shows progress). Retire the old KEK when
`unopenable` is 0 and `previous` is 0.

## Backup and restore

| What | How | Restores |
|---|---|---|
| Engine state directory (`audit.jsonl`, `audit-archive/`, `snapshot.json`) | Copy while running (a half-written final line is repaired on start) | Everything: start an engine on the copy |
| Signing key | Your secret store | The authority identity (both engines) |
| Key service state directory (journal) | Copy while running, or stop briefly | Budgets, freezes, record keys (wrapped) |
| **KEK** | Your KMS, or an offline copy | **Every record key. Losing it loses all protected data.** |

Test a restore every quarter: start an engine on yesterday's copy in a scratch environment and run
`authority audit-verify` on it. Our test suite does this on every change (`tests/test_backup_upgrade.py`).

## Upgrades

1. Upgrade the **standby** first, let it catch up (`seq` equal), then upgrade the active engine: the gateway fails
   over to the upgraded standby while the old active restarts, then that one rejoins as standby.
2. State formats are forward compatible: a log written by v0.1.0 loads, verifies and continues its chain under
   v0.2.0 (tested). Snapshots carry a format number; an unrecognised one is ignored and the log is replayed.
3. Gateways and key service: rolling restart; both start in under a second.

## Audit log retention

The active segment rotates at 256 MB into `audit-archive/<first>-<last>.jsonl`. Closed segments may be compressed
with `gzip` in place (verification and replay read `.jsonl.gz`) and moved to cheaper storage once they are older
than your newest snapshot plus your retention period. Keep enough to answer your auditors: most regulations ask
for one year; keep the newest segments and snapshot on the engine's disk.
