# 1.3.7 GUI hotfix validation

The 1.3.6 visibility tests checked the final state and missed intermediate
position and painting events. Two new native-HWND regressions failed five
assertions against 1.3.6: ten scrolled updates caused 1180 geometry changes and
440 parent background-erase messages; ten unchanged node updates produced
140 text writes and 400 geometry changes. These counts are parent erase events,
not a claim that each event erased the complete client area.

After the hotfix:

- Ten changing connection-counter updates at a scrolled viewport produce zero
  layout moves and zero parent background erases. Displayed duration/download
  values still advance to the last received snapshot.
- Ten unchanged node snapshots produce zero text writes and zero moves, while
  preserving the final controller-unavailable label.
- Wrapped node warnings at logical widths 740, 1100 and 760, including DPI
  rebuilding and inner scrolling, retain the scroll offset and display updated
  latency without geometry changes or full-client erases.
- Debug GUI targets: 4/4 passed in 8.38 seconds. Release: 4/4 in 8.60 seconds.
  Main window: 19 cases / 224 assertions in each configuration. Existing minimized,
  hidden, restore, DPI, long-text, selector and socket-probe cases still pass.
- Production test hooks remain disabled. All product/build inputs match the
  validation checkout. Routing and relay code are unchanged from 1.3.6.

The isolated preview was also visually inspected at full and narrow sizes and
after scrolling. Its link-time doubles cannot connect to the installed engine
or save user configuration. This is not acceptance of a replaced installation.
CI for the new revision is reported separately in the pull request.
