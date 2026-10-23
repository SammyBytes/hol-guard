"""How long a harness gives one ``hol-guard-runtime resident-stop`` process."""

from __future__ import annotations

# The runtime bounds its own stop work by MANAGED_STOP_TIMEOUT (2 s,
# rust/crates/guard-runtime/src/managed_resident.rs), and a successful stop
# can spend that whole bound waiting for the supervisor to finish its last
# writes. Process start and the runtime self-digest come before that bound,
# so a caller timeout equal to it kills healthy stops on slow runners. This
# outer bound still fails a stop that hangs.
RESIDENT_STOP_TIMEOUT_SECONDS = 5.0

__all__ = ["RESIDENT_STOP_TIMEOUT_SECONDS"]
