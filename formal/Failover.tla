------------------------------- MODULE Failover -------------------------------
(* Engine failover in Mastyf Authority: two engines, one key service (itself replicated, modelled here as
   one durable store), gateways that may promote a standby at any moment (including by mistake, when a
   network split only makes the active engine look dead).

   What the code does (src/authority/failover.py, engine.py, rust/keyservice):
     - only the active engine decides; every critical record (freeze, approval, denial) is appended to its
       signed log and replicated to the standby, which copies a prefix of the active engine's log;
     - semi-synchronous: a critical record is confirmed to the caller once the standby has it, OR, after a
       timeout or with no standby attached, anyway (availability); with Fixed, that fallback first records
       a "floor" in the key service, which accepts it only from an engine of the current epoch: a standby
       below the floor can no longer be promoted;
     - promotion: the standby fences the key service with epoch = known epoch + 1 (the key service then
       refuses grants of lower epochs) and becomes active with that epoch; with Fixed the key service
       hands out the next epoch itself, strictly above every earlier one;
     - the key service honours a grant only if its epoch >= the fenced minimum;
     - an active engine that sees a peer active with a higher epoch stops (watch_peer);
     - a restarted engine follows an active peer; engine 0 with no active peer visible starts active
       (with Fixed: by fencing a new epoch, like a promotion).

   Properties:
     OneEffectiveEngine  at most one engine can get grants honoured (epoch >= fenced minimum) at a time
     NoLostCritical      every critical record confirmed to a caller is in the log of the engine whose
                         grants the key service honours *)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Engines, Zero, MaxEpoch, MaxLog, MaxCrashes, Fixed

VARIABLES role,      \* engine -> "active" | "standby" | "fenced" | "down"
          epoch,     \* engine -> epoch it holds
          log,       \* engine -> sequence of records [ep, n]
          ksMin,     \* key service: lowest epoch whose grants are honoured
          ksFloor,   \* key service (Fixed): records [ep, n] a promotable standby must hold
          acked,     \* critical records confirmed to callers
          crashes

vars == <<role, epoch, log, ksMin, ksFloor, acked, crashes>>

Rec(ep, n) == [ep |-> ep, n |-> n]
Range(s) == {s[i] : i \in 1..Len(s)}
IsPrefix(a, b) == Len(a) <= Len(b) /\ SubSeq(b, 1, Len(a)) = a
Effective(e) == role[e] = "active" /\ epoch[e] >= ksMin

Init == /\ role = [e \in Engines |-> IF e = Zero THEN "active" ELSE "standby"]
        /\ epoch = [e \in Engines |-> 0]
        /\ log = [e \in Engines |-> <<>>]
        /\ ksMin = 0
        /\ ksFloor = {}
        /\ acked = {}
        /\ crashes = 0

\* the active engine records a critical decision (it is not yet confirmed to the caller)
Record(e) == /\ role[e] = "active"
             /\ Len(log[e]) < MaxLog
             /\ log' = [log EXCEPT ![e] = Append(@, Rec(epoch[e], Len(@) + 1))]
             /\ UNCHANGED <<role, epoch, ksMin, ksFloor, acked, crashes>>

\* confirm a record to the caller: the standby has it (semi-sync) ...
AckReplicated(e, r) == /\ role[e] = "active" /\ r \in Range(log[e]) /\ r \notin acked
                       \* the standby reports its position (Current: a sequence number; Fixed: position and hash,
                       \* so a diverged standby cannot confirm)
                       /\ \E s \in Engines \ {e} : role[s] = "standby" /\ r \in Range(log[s])
                                                  /\ (Fixed => IsPrefix(log[s], log[e]) \/ IsPrefix(log[e], log[s]))
                       /\ (Fixed => epoch[e] >= ksMin)   \* Fixed: every confirmation writes the floor first
                       /\ acked' = acked \cup {r}
                       /\ ksFloor' = IF Fixed THEN ksFloor \cup {r} ELSE ksFloor
                       /\ UNCHANGED <<role, epoch, log, ksMin, crashes>>

\* ... or the standby is slow or detached: go on anyway (with Fixed: after writing the floor)
AckTimeout(e, r) == /\ role[e] = "active" /\ r \in Range(log[e]) /\ r \notin acked
                    /\ (Fixed => epoch[e] >= ksMin)   \* the key service refuses a floor from a replaced engine
                    /\ acked' = acked \cup {r}
                    /\ ksFloor' = IF Fixed THEN ksFloor \cup {r} ELSE ksFloor
                    /\ UNCHANGED <<role, epoch, log, ksMin, crashes>>

\* the standby copies the next record of an active engine's log; a diverged log is set aside first
Replicate(s, a) == /\ role[s] = "standby" /\ role[a] = "active" /\ a # s
                   /\ IF IsPrefix(log[s], log[a])
                      THEN /\ Len(log[s]) < Len(log[a])
                           /\ log' = [log EXCEPT ![s] = Append(@, log[a][Len(@) + 1])]
                      ELSE log' = [log EXCEPT ![s] = <<>>]
                   /\ epoch' = [epoch EXCEPT ![s] = IF epoch[a] > @ THEN epoch[a] ELSE @]
                   /\ UNCHANGED <<role, ksMin, ksFloor, acked, crashes>>

\* a gateway promotes a standby (whenever it believes the active engine is gone, rightly or not)
\* Current: the engine proposes its known epoch + 1; the key service raises its minimum to at least that and
\* the promotion goes ahead if the minimum is now >= n (an equal epoch is accepted).
\* Fixed: the key service hands out the next epoch itself (strictly above every earlier fence), and only to
\* a standby holding every record of the floor.
Promote(s) == /\ role[s] = "standby"
              /\ IF Fixed
                 THEN LET n == ksMin + 1 IN
                      /\ n <= MaxEpoch /\ ksFloor \subseteq Range(log[s])
                      /\ ksMin' = n
                      /\ role' = [role EXCEPT ![s] = "active"]
                      /\ epoch' = [epoch EXCEPT ![s] = n]
                 ELSE LET n == epoch[s] + 1 IN
                      /\ n <= MaxEpoch
                      /\ ksMin' = IF n > ksMin THEN n ELSE ksMin
                      /\ IF (IF n > ksMin THEN n ELSE ksMin) >= n
                         THEN /\ role' = [role EXCEPT ![s] = "active"]
                              /\ epoch' = [epoch EXCEPT ![s] = n]
                         ELSE UNCHANGED <<role, epoch>>
              /\ UNCHANGED <<log, ksFloor, acked, crashes>>

\* an active engine sees a peer active with a higher epoch and stops deciding
Superseded(e, p) == /\ role[e] = "active" /\ role[p] = "active" /\ epoch[p] > epoch[e]
                    /\ role' = [role EXCEPT ![e] = "fenced"]
                    /\ UNCHANGED <<epoch, log, ksMin, ksFloor, acked, crashes>>

Crash(e) == /\ role[e] # "down" /\ crashes < MaxCrashes
            /\ role' = [role EXCEPT ![e] = "down"]
            /\ crashes' = crashes + 1
            /\ UNCHANGED <<epoch, log, ksMin, ksFloor, acked>>

\* restart (log kept on disk): follow an active peer if one is visible (or by chance not), else engine 0
\* starts active; with Fixed it starts active only by fencing a new epoch, like a promotion
Restart(e) == /\ role[e] \in {"down", "fenced"}
              /\ \/ /\ role' = [role EXCEPT ![e] = "standby"]
                    /\ UNCHANGED <<epoch, ksMin>>
                 \/ /\ e = Zero /\ ~Fixed
                    /\ role' = [role EXCEPT ![e] = "active"]
                    /\ UNCHANGED <<epoch, ksMin>>
                 \/ /\ e = Zero /\ Fixed
                    /\ LET n == ksMin + 1 IN
                       /\ n <= MaxEpoch /\ ksFloor \subseteq Range(log[e])
                       /\ ksMin' = n
                       /\ epoch' = [epoch EXCEPT ![e] = n]
                       /\ role' = [role EXCEPT ![e] = "active"]
              /\ UNCHANGED <<log, ksFloor, acked, crashes>>

Next == \E e \in Engines :
          \/ Record(e) \/ Crash(e) \/ Restart(e) \/ Promote(e)
          \/ \E r \in Range(log[e]) : AckReplicated(e, r) \/ AckTimeout(e, r)
          \/ \E p \in Engines : Replicate(e, p) \/ Superseded(e, p)

Spec == Init /\ [][Next]_vars

OneEffectiveEngine == \A e, f \in Engines : (Effective(e) /\ Effective(f)) => e = f
NoLostCritical == \A e \in Engines : Effective(e) => acked \subseteq Range(log[e])
TypeOK == /\ role \in [Engines -> {"active", "standby", "fenced", "down"}]
          /\ ksMin \in 0..MaxEpoch
=============================================================================
