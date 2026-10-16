# acreetionos-db

The little data brain behind AcreetionOS: a SQLite file wrapped in a
Python-stdlib HTTP shim (`db-api.py`), running on the US VPS inside a
128 MiB cgroup.

Runs as the `acreetionos-db` Docker container on `us.iso.acreetionos.org`
(loopback-only: `127.0.0.1:8284` → in-container `:8081`). The token lives at
`/opt/acreetionos-db/secrets/api_token`; Vault. Nothing here shows a secret.

## Why the shim exists
SQLite has no network protocol and nothing here wants a Postgres for ~100
subscribers + rate counters. The shim speaks HTTPS-to-the-tunnel only
(`https://db.acreetionos.org`, via cloudflared ingress → `http://127.0.0.1:8284`),
and every route requires the bearer token except `GET /health`.

## What it stores
- `providers` — mirror/hosting registry (part of acreetionos.org hosting signup)
- `subscribers` — newsletter/hosting lists, with double-opt-in (`confirmed_at`)
- `rate_buckets` — shared rate-limit/budget counters (`POST /limits/check|add`)
  *replaces* the per-isolate `rateLimitMap` in the site Worker (bead `ray`)
- `replay_keys` — first-wins dedupe for one-shot tokens (`POST /replay`)
- `mail_queue` — enqueue-and-drain mail queue (bead `7k8`); the Worker writes
  pending confirmations; a drain job on the VPS sends via Mailcow and marks rows
  sent. VPS down ⇒ confirmations defer, writes do NOT open.

## Deploy an update
    scp db-api.py us_ssh:/opt/acreetionos-db/db-api.py.new
    ssh us_ssh 'cp -a /opt/acreetionos-db/db-api.py /opt/acreetionos-db/db-api.py.bak.$(date +%Y%m%d_%H%M%S)
                && mv /opt/acreetionos-db/db-api.py.new /opt/acreetionos-db/db-api.py
                && docker restart acreetionos-db'

## Ops notes
- atomicity: every counter/dedupe mutation runs in `BEGIN IMMEDIATE`;
  correct across concurrent handlers and restarts
- sweep: a daemon thread purges dead windows, stale replay keys and expired
  mail jobs every 60 s
- privacy: the Worker hashes visitor IPs (HMAC with a Worker-side salt) before
  any key gets here; raw IPs are never stored
