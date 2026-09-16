# Stage 3 native configuration scanner

Stage 3 adds a deliberately small, non-destructive scanner for explicitly authorised development targets.

The worker performs at most two HTTP `HEAD` requests per scan (one HTTP and one HTTPS) plus one TLS handshake. It does not submit forms, enumerate paths, brute force, execute payloads, follow cross-host redirects, or read response bodies.

Before connecting, DNS is resolved and every returned address must be public. Loopback, private, link-local, carrier-grade NAT, documentation, multicast, reserved IPv4 ranges, IPv6 unique-local/link-local/documentation ranges, and localhost/IP targets are rejected. HTTP requests are pinned to the already-vetted address while preserving the authorised hostname for Host/SNI.

Raw Stage 3 output is stored in `scan_observations`. These rows are descriptive observations (`pass`, `warn`, `info`, `error`) rather than vulnerability findings. Stage 4 is responsible for mapping supported observations into findings/evidence without inflating severity.

The worker uses a Supabase service-role key and service-role-only RPCs. That key must never be put in the web app, committed to Git, or exposed through a `NEXT_PUBLIC_*` variable.
