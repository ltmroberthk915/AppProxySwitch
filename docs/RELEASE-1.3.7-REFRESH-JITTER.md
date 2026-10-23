# 1.3.7 candidate: fix the 1.3.6 GUI refresh regression

Version 1.3.6 exposed intermediate layout steps after removing the top-level
redraw toggle. Each status refresh first restored template rectangles, then
applied layout sizes and scrolling, repainting controls between these steps.
This could make the whole visible interface flicker and jump repeatedly.

Layout now calculates final rectangles, including scroll offsets, before
submitting a batch of position changes for each parent. Unchanged rectangles
and scrollbar ranges are skipped. Measuring wrapped node text does not move
controls. Background updates no longer invalidate and erase every child.
The top-level visibility flag remains untouched.

Node text is resolved before display, so a missing controller result does not
briefly show a placeholder before the final liveness label. Unchanged text and
radio state are not written again. Live counters and changed status text still
update; resizing, DPI rebuilding and both scroll areas remain functional.

The new regressions inspect native position, text and background-erase events
during updates, rather than only checking final geometry. Before the fix,
ten scrolled updates caused 1180 geometry changes and 440 parent background
erase events; ten unchanged node updates made 140 text writes. The corrected
steady updates cause zero unnecessary moves, parent erases and text writes.
Additional wrapped-node cases preserve inner scroll position while live text
changes, at three viewport widths and after DPI rebuilding.

Local Debug and Release GUI targets pass, including 19 main-window cases and
224 assertions. Tests replace IPC/config/tray boundaries and do not access the
installed engine. This hotfix changes GUI rendering only; it does not change
proxy routing, node selection or network relay behavior. Installed acceptance
remains separate. Use this candidate in place of the 1.3.6 GUI candidate.
