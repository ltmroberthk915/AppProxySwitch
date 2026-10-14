# 1.3.4 candidate: nested service-policy choices

A rule-mode service Selector can contain a child group whose selected node
already satisfies the configured region and class. Previously the monitor
discarded every group-valued member, reported that no matching node existed,
and kept an out-of-region service route.

For an explicitly configured `GROUP:<service>` preference that is referenced
by runtime rules, the monitor now evaluates each legal immediate choice at its
existing selected leaf. It probes and ranks that leaf, then switches the outer
service Selector to the legal member. It does not change the child selection.
It checks the resulting route again before reporting the expected node.

Cycles, empty branches and built-in direct/reject leaves remain ineligible.
Unused nodes inside a child group are not flattened into selectable choices.
Duplicate leaves and the current leaf do not cause redundant switches.
General/global/legacy selection behavior retains its previous group exclusion.

This candidate also includes the 1.3.3 duplex-relay and diagnostic changes.
Changing a Selector does not guarantee that existing connections move to its
new route. Verify new business connections and response completion separately;
node latency and a successful controller update do not establish stream health.

The stable release remains [1.3.2](https://github.com/ltmroberthk915/AppProxySwitch/releases/tag/v1.3.2).
Stop interception and exit APS normally before installing a candidate.
