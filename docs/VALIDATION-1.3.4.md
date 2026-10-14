# 1.3.4 candidate validation

- The old candidate-selection code fails both timed and manual nested-choice
  cases: the regression records four failures. The revised code passes both,
  selects only the legal outer member, and leaves child selections unchanged.
- The focused engine cases pass 24 assertions, including invalid, unselected
  and duplicate/current-leaf exclusions. Controller tests pass 21 cases and
  153 assertions, including deep selected leaves, cycles and empty branches.
- Local Release passes all 29 ordinary checks. Debug and cloud checks are
  being completed; real WinDivert execution must be confirmed separately.

Live recovery remains a separate acceptance step. No test result above proves
that an upstream proxy or remote service will keep a model stream open.
