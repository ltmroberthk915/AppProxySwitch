# 1.3.8: detect TLS connections closed without a response

For an authorized TLS hostname, sending a ClientHello followed by proxy-side
EOF with no response now reports `tls-no-response`, instead of increasing the
successful-flow count. Repeated failures use the existing failure threshold,
ratio and switch cadence, including cached addresses absent from the clean
DNS cache. Application-first FIN and engine cancellation keep their original
semantics; received HTTP error responses are not classified by this change.

The effective hostname accompanies the result. After a switch, a SOCKS CONNECT
acknowledgement or the application's original IP no longer clears a hostname
failure signal. Real traffic supplies subsequent evidence. This version does
not claim authenticated application completion from a transport handshake.

A failed controller delay is displayed as unavailable with an explicit warning,
instead of recycling a previous latency as a fresh healthy result. An isolated
controller failure still preserves established connections; repeated real
traffic failures drive recovery.

Local regressions cover zero-response EOF, application-first FIN, recovery with
an untrusted cached IP, and unavailable delay display. Installing the candidate
requires normally stopping and exiting the existing APS instance first.
