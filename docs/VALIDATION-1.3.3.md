# 1.3.3 candidate validation

The tested code commit is `3f8595e5507fa504681ed89f40e873807b9a67b5`.
The later documentation update does not change build inputs.

- [Windows CI run 38591175808](https://github.com/ltmroberthk915/AppProxySwitch/actions/runs/38591175808) succeeded: 17 unit, 12 integration and 1 real WinDivert test. The driver test passed in 1.00 second; it was not skipped.
- Local Release passed all 29 ordinary checks. Its driver check was skipped without elevation.
- Local Debug passed 28/29 in the full run. The remaining discovery fixture could not acquire its process-named pipe while the Release suite was running concurrently; its isolated rerun passed all 24 discovery cases. The two configurations share that fixture pipe name.
- Recompiling the previous relay against the new backpressure tests fails both directional cases. The revised relay passes them, send deadlines/failure-side checks, stop under pressure, and the existing TLS prefix, half-close, idle/truncated streaming checks.
- The engine harness preserves its critical marker and reinjects all 15001 synthetic packets without filling the debug log. Concurrent log threshold updates preserve all 2000 warning records.
- A separate production-relay probe confirms TLS certificate verification and HTTP responses through a local proxy when its hostname policy permits the target; unlisted stale-address attempts retain the original IP behavior. No credentials or response contents were captured.

The candidate package uses the locally tested Release program. All 165 source,
resource, script and build inputs match the public checkout byte for byte;
the workflow matches after newline normalization. The diagnostic probe and
private operational records are excluded from the package. The default TLS
hostname policy remains empty.

This establishes the local defects and transport behavior. Live authenticated
application recovery and external proxy connection closures require separate
verification. The stable release remains 1.3.2 while this PR is a candidate.
