# 1.3.6 candidate validation

Background layout no longer toggles top-level `WS_VISIBLE`. Five isolated
refreshes produced 20 visibility transitions before the fix and zero afterward.
The minimized-window test did not reproduce the complete unsolicited-restore
incident. Explicit show-source metadata supports later live investigation.

Stalled control-channel readers previously held writes until the fixture's
2.5-second watchdog released them: four assertions failed in seven cases.
Writes now have a 500 ms deadline, cancellation is drained before resource
release, and failed byte-mode writes reconnect before later JSON messages.
A persistent reset event covers cancellation racing a new client read.

The relay stop regression retained its original one-second threshold. Phase
metadata reproduced a 1004 ms stop, with 1003 ms in session shutdown and zero in
listener shutdown. The socket-readiness wait now rechecks cancellation within
250 ms. Idle stream lifetime and queued-byte send deadlines are unchanged.

Local validation:

- Debug and Release applications build with `APS_TEST_HOOKS=OFF`.
- Full Debug unit/integration run: 29/29 passed in 296.73 seconds, including the
  engine harness in 220.26 seconds. This included the relay cancellation fix.
- After the final IPC reset-event addition, rebuilt Debug IPC and main-window
  targets passed again (2/2, 18.56 seconds).
- Final Release affected targets: 7/7 passed in 33.26 seconds (relay, IPC,
  main window, rules view, connections view, tray and logging).
- Final IPC: 9 cases, 70 assertions in each configuration; main window: 16 cases,
  198 assertions; relay: 25 cases, 1588 assertions.
- Three slow-download stop measurements were 269/233/264 ms in Debug and
  223/233/267 ms in Release. The earlier failures remain recorded.

Tests use local loopback mocks, fake packet devices and isolated GUI boundaries.
No real-driver test or installed-candidate acceptance was performed locally for
this revision. The candidate does not establish the cause of upstream TLS EOFs
or claim to repair them. CI validation is reported separately in the pull request.
