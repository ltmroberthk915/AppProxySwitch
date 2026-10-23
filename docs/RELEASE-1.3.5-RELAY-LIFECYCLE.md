# 1.3.5 candidate: relay configuration and shutdown races

When proxy settings change while a new connection is accepted, the relay
previously copied endpoint, credentials and timeouts without holding the
configuration lock. A connection could receive fields from different updates,
causing an authentication failure or a reset. New sessions now take one locked
snapshot. Engine target resolution and verification also use one outlet snapshot.

The relay now publishes each worker thread under its session lock. Natural
completion detaches under that lock; shutdown first claims remaining workers,
then aborts all and joins them. These paths no longer race over a thread object.
Socket publication and close are serialized with abort so cancellation cannot
shut down a closed handle that another connection has since reused. The accept
thread is joined before its listener member is invalidated.

Regression coverage includes concurrent endpoint/authentication changes, shutdown
while completion callbacks are in flight, and rapid EOFs across repeated starts.
The configuration regression failed against the previous code and passed after
the fix. The existing duplex, half-close, DNS and TLS-domain cases remain covered.

This candidate includes the earlier duplex-relay and nested-selector changes.
It does not establish the cause of an upstream HTTP rejection or prove that a
particular model stream will remain connected. Runtime configuration and other
proxy clients are not modified by these source changes. Live installation and
acceptance are separate from local regression checks.
