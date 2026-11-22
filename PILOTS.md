# Pilot results

> [!IMPORTANT]
> **These are not customer pilots.** No customer has run Authority yet. Until one does, these are the closest honest
> substitutes: our own account, a real organisation's public logs, 32 companies' public engineering activity, a real
> AWS account's CloudTrail, 20,000 real AI coding-agent runs, Wikipedia's admin log, and real public attack logs. Each section says exactly what the data is. We will add customer pilots here, with their
> permission, as they finish.

All results use **shadow mode** with the **default policy** shipped in this repository. Shadow mode scores what would
have happened and blocks nothing. The rules for counting:
- An *interruption* is something that would have needed a person: asking a second person, a refusal, or a freeze.
- A *freeze* counts once; then it's treated as reviewed and lifted.
- A *hold* means an irreversible action waited out its undo window. Nobody has to act, so holds aren't interruptions.
- *Ask once*: after one approval for a new destination, that person isn't asked again for it.

## Summary

| | Data | Interruptions | Attacks |
|---|---|---|---|
| **Pilot 0** · Mastyf itself | Our GitHub security log, 12 Jun – 20 Nov 2026 (5 months) | **0.33 a day** for the whole account | Flagged every OAuth client secret created (none malicious) |
| **Pilot 1** · A real enterprise | LANL sign-in logs: 300 random employees + every red-team-compromised account, 30 days | **0.20 per person per day** | **60 of 94** compromised accounts caught at their **first** malicious login |
| **Pilot 2** · 32 companies | Public GitHub activity of company-owned organisations (GH Archive), 45 days | **0.10 per active person per day** (median company 0.06) | n/a (no labelled attacks) |
| **Pilot 3** · a real AWS account | flaws.cloud CloudTrail, 1.94 M events, 2017–2020; keys deliberately leaked and used by thousands of strangers | **1 in 550** of the owners' actions | **119 of 120** real stolen-key sessions caught at the attacker's **first** call |
| **Pilot 4** · AI coding agents | 20,010 real SWE-agent runs on real GitHub issues (356 k gated commands) | **2.0% of runs** stopped once (almost all reaching websites outside the task) | **500 of 500** hijacked runs stopped before the harmful step |
| **Pilot 5** · privileged admins | English Wikipedia's admin log, 45 days: 1,016 admins, 143 k deletions, blocks, protections, rights changes | **0.12 per admin per day** (admin-console policy) | **60 of 60** hijacked admin accounts stopped at their **first** action |
| **Attack replay** | 71 public real-attack log sets (Splunk attack_data) | n/a | **55 of 62** attacks stopped, escalated or held |

## Pilot 0: Mastyf's own GitHub account

- **Data:** the account's own GitHub security log, 755 events, of which 241 are decisions worth gating (sign-ins, new app and token grants, secrets, webhooks, exports). The other 514 are routine background events such as token refreshes and repository topics.
- **Method:** learn from the first 30 days, then score the next 131 days.
- **Result:**
  - **0.33 interruptions a day**, mostly first-time grants to new third-party apps (asked once each).
  - **0.44 holds a day**, mostly new app permissions waiting out their 1-hour undo window.
  - The behavioural model refused every OAuth app creation and client-secret generation as highly unusual for this account.
- **Caveat:** one account, one person, with no attacker present. It measures how often Authority would bother a real user; it does not measure detection.

## Pilot 1: a real enterprise's sign-ins (Los Alamos National Laboratory)

**Data.** LANL's *Comprehensive, Multi-Source Cyber-Security Events* (cyber1, CC0): 58 days of real authentication logs from LANL's corporate network, about 1.05 billion events, including a real red-team exercise.

**Who was included.** All 98 accounts the red team compromised, plus 300 employees picked at random (284 were active). For each, every sign-in in the first 30 days: 13.9 million sign-ins, 1.49 million decisions after collapsing repeats within an hour.

**What a decision is.** An account signing in to a machine, *from* a machine. A source machine that person has never used is a new destination, which is what Authority's device binding guards.

**Method.**
- **Learning period:** days 0–6, with known red-team events left out of what is learned. This is a pilot that starts just before an incident.
- **Scoring period:** days 7–29, which contain 653 of the red team's malicious logins across 94 accounts.

**What we learned first.** We measured which layers should judge sign-ins:

| How sign-ins are judged | Interruptions per person per day | Compromised accounts caught | …at their first malicious login |
|---|---|---|---|
| A: behavioural model + novelty + device binding | 31.0 | 92 of 94 | 92 |
| B: novelty + device binding | 22.6 | 86 of 94 | 76 |
| **C: rules + device binding (ask once per new machine)** | **0.20** | **60 of 94** | **60** |

On raw sign-ins, the behavioural layers catch nearly everything, but they would interrupt each person about 31 times a day, which no company would accept. Device binding alone is about one interruption per person every five working days. It still stops **64% of compromised accounts at the first malicious login**, because the attacker signs in from a machine that person has never used.

**What changed in Authority because of this pilot.**
- The default policy now leaves sign-ins to device binding and ask-once destinations (`model.skip: ["auth.login"]`).
- The behavioural model is kept for high-impact actions (exports, secrets, publishes, deletions), which is what it was built for.
- With the shipped default, Pilot 1 gives the row C numbers.

**Caveats.**
- **Real sign-ins only.** LANL contains sign-ins, not the high-impact actions Authority mainly gates, so data budgets, approvals and undo windows aren't exercised here.
- **The 34 missed accounts** were used from machines their owners also used. Catching those is the job of limits on what the account then does, which these logs don't contain.
- **No hold-out period.** We compared three settings on the same data, with no separate hold-out period, and chose the one a company could actually run.
- **Per-login counts understate detection.** Ask once means that after an interruption the device is treated as approved, as it would be for a real employee. So malicious logins *after* the first interruption aren't counted again, and the per-login figure (61 of 653) understates detection. The account-level figure (60 of 94) is the meaningful one.

## Pilot 2: 32 companies' engineering activity (GH Archive)

- **Data:** every public GitHub event of 56 company-owned organisations (Microsoft, NVIDIA, Azure, Grafana, HMCTS,
  Canonical, IBM, Elastic, Google, Sentry and others) from 15 September to 29 October 2026, streamed from
  [GH Archive](https://www.gharchive.org). The 32 organisations with at least 20 people doing gated work are scored,
  each as its own deployment: **2,766 people, 5,374 person-days**.
- **What is gated:** exactly what the shipped GitHub connector gates: pushes to `main`, `master` and `release/*`,
  deleting a protected branch, publishing releases, adding members, making a repository public. Pushes to feature
  branches are not decisions anyone gates and are left out, as in the connector.
- **Method:** shadow mode, default policy, 14-day learning period, then 31 days scored.
- **Result:**
  - **0.10 interruptions per active person per day** (median company 0.06): about one ask per person every two
    working weeks. (First run: 0.11; shadow mode now also models what happens after a person approves - the
    approved action becomes part of that account's normal, as it does in production.)
  - 11.5% of gated actions would have needed a person. Most come from two sources: releases published without the
    script-integrity report our policy expects from CI (484), and bots departing from their own usual pattern.
- **What changed in Authority because of this pilot:**
  - **Per-identity calibration** (`model.per_identity_calibration`): each identity is judged against its own normal,
    so accounts that are always busy (CI bots, merge queues) are not flagged for being themselves. Detection on our
    attack simulations is unchanged.
  - **Busy identities no longer slow the engine:** the behavioural features are now computed incrementally (the same
    values, bit for bit), 7× faster per decision for heavily used accounts.
- **Caveats:** public repositories only, so private work and private-repository risks are not covered; there are no
  labelled attacks, so this measures interruptions, not detection; people are counted by GitHub account.

## Pilot 3: a real AWS account with leaked keys (flaws.cloud)

- **Data:** the public CloudTrail of flaws.cloud (Summit Route), 1.94 million events from February 2017 to October
  2020. The account's owner deliberately leaked two users' access keys and an EC2 role as a security exercise, and
  thousands of strangers used them from their own machines. So the log holds two real populations: the owner and
  their audit tools (17 identities, 96 k events), and real attackers using stolen keys (1.84 M events).
- **Method:** the shipped CloudTrail connector, default policy, 60-day learning period. Interruptions are measured on
  the owner's identities. For detection, 120 real attacker sessions (one source address, one day) are replayed as if
  the attacker held one of the owner's keys - same calls, same address, same order - inside that identity's active
  period.
- **Result:** **157 interruptions in 87,670 owner actions** (0.06 per identity per active day); **119 of 120**
  stolen-key sessions caught at the attacker's **first call**, before any call that changed anything. The one miss
  came through an AWS service endpoint, not the attacker's own address.
- **What changed in Authority because of this pilot:**
  - **Known networks per identity** (`origins.enabled`): the first run caught only 15 of 120 sessions, because
    attackers mostly made ordinary read calls. A call from a network the identity never used now asks once - any
    call for identities that use few networks (services, audit roles, CI), sensitive calls for people who roam,
    and any call for root accounts and break-glass admins (`origins.strict`).
  - **Approved actions join the baseline:** an audit scanner whose every run looked unusual asked 815 times; once
    approved actions count as that identity's normal (as a person confirmed), interruptions fell from 966 to 157.
- **Caveats:** one small account; IP addresses in this dataset are anonymised (prefix-preserving); the replay places
  real attacker behaviour on real identities, it is not a recorded breach of them.

## Pilot 4: 20,000 real AI coding-agent runs (SWE-agent)

- **Data:** `nebius/SWE-agent-trajectories` (Hugging Face): 20,010 runs of SWE-agent fixing real issues in real
  GitHub repositories, with every shell command the agent typed (356 k gated actions after mapping).
- **Method:** the agent-shell connector turns each command into what it really does (reading code, running tests,
  installing packages, reaching a website, reading credentials, pushing, publishing). Each run is an agent session a
  person approved with a standard "fix an issue" manifest: read and run anything in the task's repository, install
  from the public package indexes, open a pull request, at most 1,000 actions. 500 held-out runs are hijacked
  mid-run by a prompt-injected instruction from ten playbooks real injections use: stealing cloud or SSH keys,
  tokens from the environment, pushing to a fork, attacker package indexes, `curl | sh`, publishing, copying the
  repository to a bucket or over `scp`, deleting outside the workspace.
- **Result:** **2.0% of normal runs** were stopped once - almost all for reaching websites outside the task (many
  invented by the agent), editing system files, or printing a token; **500 of 500** hijacked runs stopped before the
  harmful step, with no attacker action allowed.
- **What changed in Authority because of this pilot:** an agent's in-task work is bounded by its manifest and session
  totals, not judged by the behavioural model (trained on people, it refused ordinary test loops); package servers
  the person named in the manifest also pass the company-wide destination list. Normal runs stopped: 17% → 2.0%.
- **Known limits (measured, 0 of 50 each):** an injection that uses only what the person approved is not stopped by
  this layer - a typo-named package from the approved index, or secrets copied into the agent's own pull request.
  Those need a package allow-list and secret scanning of the diff.

## Pilot 5: privileged admins (English Wikipedia's admin log)

- **Data:** every deletion, block, page protection and user-rights change on English Wikipedia for 45 days (public
  MediaWiki API): 1,016 human admins, 143 k scored privileged actions, plus bots.
- **Method:** mapped as an enterprise admin console would gate them (deleting content, disabling accounts, changing
  who may edit, changing someone's rights). 60 held-out takeovers: a real admin account, hijacked, does what
  documented takeovers did - blocks other real admins, deletes prominent (protected) pages, makes a new admin.
- **Result by policy:**

  | Policy | Interruptions per admin per day | Hijacked admins stopped within 5 actions |
  |---|---|---|
  | Shipped default (every `storage.delete` asks) | 28.9 | 60 / 60 |
  | `storage.delete` asks only for infrastructure | 0.33 (+ 3 actions a day held in undo windows) | 60 / 60 contained, 12 interrupted |
  | Admin console (rules and undo windows only for infrastructure) | 0.09 | 12 / 60 |
  | **Admin console + crown jewels** (acting on other admins or on protected pages always asks) | **0.12** | **60 / 60, at the first action** |

  The crown jewels come from the learning period of the log itself: the 652 admins, and the 871 pages someone
  protected.
- **What changed in Authority because of this pilot:** always-ask rules can be scoped to resources
  (`"storage.delete@s3://*"`), and thousands of crown-jewel entries cost nothing per decision; shadow mode now models
  undo-window minimums and the burst freeze exactly as the undo gate does.
- **Lesson for deployment:** behaviour alone does not separate a hijacked admin from a busy one - deleting and
  blocking is their job. List the crown jewels.

## The careful attacker (white-box, never triggers a question)

- **Setup:** malware on the victim's own laptop (their network, device and hours) with an exact copy of Authority's
  state; before every move it tries the move on its copy and only makes it if nothing would ask. Goal: as many of
  the victim's customer records, or production secrets, as possible in 28 days. Simulated companies, 5 worlds.
- **Result:** with daily data budgets only, it took **3.4×** (records) and **6.6×** (secrets) the victim's own normal
  month without ever being asked. With weekly and 4-weekly budgets learned the same way (now shipped, enforced by
  the key service): **1.4×** and **1.7×**. No extra interruptions for normal staff.
- **What this means:** an undetectable attacker on the victim's own device is bounded by the victim's own normal use,
  not by detection. Bait records and need-to-know case binding (both available) cut it further.

## Attack replay: 71 real attack log sets

- **Data:** Splunk's public `attack_data` collection: real attack logs from AWS CloudTrail, Okta and GitHub, each tagged with its MITRE ATT&CK technique. 62 of the 71 log sets contained actions the connectors understand.
- **Connector coverage:**
  - **CloudTrail:** 35,790 of 35,791 events.
  - **Okta:** 112 of 112.
  - **GitHub:** 11 of 24. The other 13 are webhook notifications, not actions anyone takes.
- **Result:** **55 of 62** attacks had at least one step stopped, escalated or held.
- **The 7 missed:**
  - 4 were attempts **Okta itself had already blocked** (threat detected, suspicious activity reported, unauthorised app access, account lockouts).
  - 3 need a baseline of that company's normal activity, which attack-only logs don't have: a burst of downloads, concurrent sessions, and repeated model-listing failures.
- **Caveat:** the logs contain only the attack, with no normal activity around it. This tests whether Authority understands and gates attack actions; it does not measure false alarms.

## Reproduce

- **Pilot 0:** export your own GitHub security log (Settings → Archives → Security log → Export) and run shadow mode on it. The GitHub security-log connector is in the Enterprise package.
- **Pilots 1, 3, 4, 5 and the replay:** the scripts are in the Enterprise package. Researchers can request access under NDA at https://www.mastyf.ai/pilot. Both datasets are public: LANL cyber1 at https://csr.lanl.gov/data/cyber1/, and https://github.com/splunk/attack_data.

**Run a pilot on your own logs:** the Damage Ceiling Report is a pilot like these on 30 days of your read-only logs. It's free for our first 10 companies: https://www.mastyf.ai/authority#report
