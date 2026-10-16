# 1.3.6 candidate: window refresh, control recovery and relay cancellation

Background outlet updates previously suspended redraw on the top-level window.
Windows implements that operation by clearing and restoring `WS_VISIBLE`, so
routine status updates also changed the window state observed by the shell.
Layout now leaves the top-level visibility flag alone. Minimized windows skip
layout and connection-list rendering; the next restored snapshot repopulates
the list, including when the skipped payload is unchanged.

A second launch now requests one restore through the existing instance, rather
than restoring both from the caller and from the event listener. Event requests
are dispatched on the UI thread. GUI logs record the source of explicit show
requests and system minimize/restore commands. Clearing GUI logs keeps their
separate file name instead of reopening the engine's log file.

Control-channel writes now have a 500 ms deadline and observe shutdown. A GUI
or engine that stops reading can no longer hold its peer in an unbounded write.
A failed or partial write resets the control connection before another command
is sent. Read/connect cancellation is completed before its buffers and events
are released, and pipe handles remain valid until pending operations finish.
The engine and its existing network relays keep running when GUI IPC reconnects.
A persistent reset event also covers a write failure that races the next read.

Local regressions stall each peer, fill its pipe buffer, and verify bounded
failure, automatic reconnection, intact later messages, and stop cancellation.
The pre-fix implementation failed both stalled-reader write checks. These are
offline control-channel findings, not proof of the cause of model TLS failures.

Relay workers now check explicit cancellation at most 250 ms apart while waiting
for socket readiness. Local shutdown does not always wake a backpressured Windows
`select`; the previous one-second wait could consume the entire stop budget.
The regression reproduced a 1004 ms stop before the change and now repeats the
same backpressure case three times under the original one-second assertion.
This changes cancellation responsiveness, while preserving idle stream lifetime
and the configured deadline for queued bytes. Stop logs record listener and
session wait times separately.

Regression tests cover visibility changes during background refresh, minimized
and hidden updates, explicit restoration, restored connection rows, and existing
DPI and scrolling behavior. These tests replace the engine, configuration and
tray boundaries with doubles and do not contact the installed engine.

This candidate addresses confirmed GUI and control/relay behavior. An isolated minimized-window
test did not reproduce an unsolicited full restore, so that incident remains
subject to live acceptance using the added show-source logs. It does not claim
to resolve upstream TLS disconnections. Building and packaging this candidate
do not install it or change running proxy settings.
