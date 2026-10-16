# 1.3.4 candidate validation

- The old candidate-selection code fails both timed and manual nested-choice
  cases: the regression records four failures. The revised code passes both,
  selects only the legal outer member, and leaves child selections unchanged.
- The focused engine cases pass 24 assertions, including invalid, unselected
  and duplicate/current-leaf exclusions. Controller tests pass 21 cases and
  153 assertions, including deep selected leaves, cycles and empty branches.
- Local Release and Debug each pass all 29 ordinary checks, run separately
  to avoid process-named discovery-fixture contention.
- Code commit `9120c2741a23f6cc303b3b3cf0e1082bd278cbbd` passes
  [Windows CI run 38602241484](https://github.com/ltmroberthk915/AppProxySwitch/actions/runs/38602241484):
  17 unit, 12 integration and 1 real WinDivert check. The driver check passes
  in 0.99 second and is not skipped. Later documentation does not change
  build inputs.
- All 165 source, resource, script and build inputs match the public checkout
  byte for byte; the workflow matches after newline normalization. The local
  candidate package contains the tested Release program, 15 expected files,
  an empty default TLS allowlist, and no private incident/configuration data.

Live recovery remains a separate acceptance step. No test result above proves
that an upstream proxy or remote service will keep a model stream open.
