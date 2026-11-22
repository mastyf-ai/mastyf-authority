# Formal model of engine failover

`Failover.tla` models two engines, the key service and gateways that may promote a standby at any time
(also by mistake, when a network split only makes the active engine look dead). It checks:

- **OneEffectiveEngine**: at most one engine can get grants honoured at a time;
- **NoLostCritical**: every freeze, approval or denial confirmed to a caller is held by the engine whose
  grants the key service honours.

`Fixed = FALSE` is the protocol as it was before 2026-11-22; TLC finds three counterexamples
(a freeze confirmed after the replication timeout and lost on failover; two engines with the same
epoch; a diverged standby confirming records it then discards). `Fixed = TRUE` is the shipped protocol:
the key service hands out strictly increasing epochs, every confirmed critical record is reported to it
first (the "floor", refused from a replaced engine), and only an engine holding the floor record can be
promoted or start active.

    java -cp tla2tools.jar tlc2.TLC -config FailoverFixed.cfg -workers 8 -deadlock Failover.tla      # passes
    java -cp tla2tools.jar tlc2.TLC -config FailoverCurrent.cfg -workers 8 -deadlock Failover.tla    # fails
    java -cp tla2tools.jar tlc2.TLC -config FailoverFixedLarge.cfg -workers 8 -deadlock Failover.tla # larger bounds

Bounds are small (2 engines, a few epochs, records and crashes): model checking explores every interleaving
within them, which is where protocol bugs show up; it is not a proof for unbounded runs. The code that
implements each step is named in the module's header; tests/test_failover.py replays the counterexample
against the real binaries.
