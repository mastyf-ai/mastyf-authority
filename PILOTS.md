# Pilot results

> [!IMPORTANT]
> **These are not customer pilots.** No customer has run Authority yet. Until one does, these are the closest honest
> substitutes: our own account, a real organisation's public logs, and real public attack logs. Each section says
> exactly what the data is. We will add customer pilots here, with their permission, as they finish.

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
- **Pilot 1 and the replay:** the scripts are in the Enterprise package. Researchers can request access under NDA at https://www.mastyf.ai/pilot. Both datasets are public: LANL cyber1 at https://csr.lanl.gov/data/cyber1/, and https://github.com/splunk/attack_data.

**Run a pilot on your own logs:** the Damage Ceiling Report is a pilot like these on 30 days of your read-only logs. It's free for our first 10 companies: https://www.mastyf.ai/authority#report
