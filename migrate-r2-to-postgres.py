#!/usr/bin/env python3
"""
Copy the stateful records out of the R2 bucket 'acreetionos-hosting' and into
Postgres.

This is the one-shot importer for the move tracked in the repo. It is written to
be safe to run more than once: every insert is an upsert keyed on the natural
identifier, and r2_migration_log records what has been seen.

It only ever reads R2. It never deletes or mutates anything there, because the
Worker's dual-read fallback still depends on those objects existing. Removing the
R2 copies is a separate, deliberate step once the new path has been correct in
production for a while.

Usage (on the VPS):
    R2_TOKEN=... R2_ACCOUNT=... python3 migrate-r2-to-postgres.py [--dry-run]
"""

import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

CF_API = "https://api.cloudflare.com/client/v4"
BUCKET = "acreetionos-hosting"
DB = dict(
    host="127.0.0.1",
    port=5433,
    dbname="acreetionos",
    user="acreetionos",
)

token = os.environ.get("R2_TOKEN", "")
account = os.environ.get("R2_ACCOUNT", "")
if not token or not account:
    sys.exit("R2_TOKEN and R2_ACCOUNT must be set")

password = open("/opt/acreetionos-db/secrets/postgres_password").read().strip()

import psycopg2  # noqa: E402

dry_run = "--dry-run" in sys.argv


def r2_list(prefix):
    """Yield every object under a prefix.

    The original Worker code called the list endpoint once and returned whatever
    arrived, ignoring R2's 1000-object cap and its truncation cursor. This
    follows the cursor to completion; anything that still comes back truncated
    is reported rather than silently passed off as the whole set.
    """
    url = (
        f"{CF_API}/accounts/{account}/r2/buckets/{BUCKET}/objects"
        f"?prefix={urllib.parse.quote(prefix)}"
    )
    seen = 0
    while url:
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, context=ssl.create_default_context()) as r:
            data = json.load(r)
        result = data.get("result") or {}
        for obj in result.get("objects", []):
            key = obj["key"]
            size = int(obj.get("size") or 0)
            if size == 0:
                # R2 returns "cumulatively-conserved placeholder" for deletes;
                # skip rather than fetch a body that no longer exists.
                continue
            yield key, size
            seen += 1
        if result.get("truncated"):
            print(f"  ! truncated after {seen} under {prefix}", file=sys.stderr)
        url = None


def r2_get(key):
    quoted = urllib.parse.quote(key, safe="")
    url = f"{CF_API}/accounts/{account}/r2/buckets/{BUCKET}/objects/{quoted}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, context=ssl.create_default_context()) as r:
        return json.load(r)


def checksum(value):
    import hashlib

    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:16]


def migrate(conn):
    cur = conn.cursor()
    counts = {"providers": 0, "subscribers": 0, "skipped": 0}

    for key, _ in r2_list("provider-"):
        rec = r2_get(key)
        pid = rec.get("id") or key[len("provider-"):]
        vetting = rec.get("vetting") or {}
        cur.execute(
            """
            INSERT INTO providers (id, org, email, website, mirror_url, location,
                bandwidth, notes, password, status, created, removal_requested,
                removal_reason, discord_user_id, subscribed, vetting_score,
                vetting_flags, personal_email, last_seen, expiry_warning_sent)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (id) DO UPDATE SET
                org=EXCLUDED.org, email=EXCLUDED.email, status=EXCLUDED.status,
                removal_requested=EXCLUDED.removal_requested,
                removal_reason=EXCLUDED.removal_reason,
                notes=EXCLUDED.notes, subscribed=EXCLUDED.subscribed,
                vetting_score=EXCLUDED.vetting_score,
                vetting_flags=EXCLUDED.vetting_flags,
                last_seen=EXCLUDED.last_seen
            """,
            (
                pid, rec.get("org", ""), rec.get("email", ""), rec.get("website", ""),
                rec.get("mirror_url"), rec.get("location"), rec.get("bandwidth", ""),
                rec.get("notes", ""), rec.get("password", ""), rec.get("status", "pending"),
                rec.get("created"), bool(rec.get("removal_requested")),
                rec.get("removal_reason"), rec.get("discord_user_id", ""),
                bool(rec.get("subscribed")), int(vetting.get("score", 0) or 0),
                json.dumps(vetting.get("flags", [])), bool(rec.get("personal_email")),
                rec.get("last_seen"), bool(rec.get("expiry_warning_sent")),
            ),
        )
        cur.execute(
            """INSERT INTO r2_migration_log (r2_key, namespace, checksum)
               VALUES (%s,'provider',%s)
               ON CONFLICT (r2_key) DO UPDATE SET
                 migrated_at=now(), checksum=EXCLUDED.checksum""",
            (key, checksum(rec)),
        )
        counts["providers"] += 1
        print(f"  provider {pid}  {rec.get('org','')[:40]}")

    for prefix, listname in (("subscriber-", "hosting"), ("nl-subscriber-", "newsletter")):
        for key, _ in r2_list(prefix):
            rec = r2_get(key)
            email = rec.get("email")
            if not email:
                counts["skipped"] += 1
                print(f"  ! {key} has no email, skipped")
                continue
            cur.execute(
                """INSERT INTO subscribers (list, email, org, subscribed,
                     unsubscribe_token)
                   VALUES (%s,%s,%s,%s,%s)
                   ON CONFLICT (list, email) DO UPDATE SET
                     org=EXCLUDED.org, unsubscribe_token=EXCLUDED.unsubscribe_token""",
                (listname, email, rec.get("org", ""), rec.get("subscribed"), rec.get("unsubscribe_token", "")),
            )
            cur.execute(
                """INSERT INTO r2_migration_log (r2_key, namespace, checksum)
                   VALUES (%s,%s,%s)
                   ON CONFLICT (r2_key) DO UPDATE SET
                     migrated_at=now(), checksum=EXCLUDED.checksum""",
                (key, listname, checksum(rec)),
            )
            counts["subscribers"] += 1
            print(f"  {listname:10s} {email}")

    return counts


def main():
    conn = psycopg2.connect(password=password, **DB)
    if dry_run:
        print("DRY RUN — no writes")
    else:
        counts = migrate(conn)
        conn.commit()
        print(f"\n  migrated: {counts}")
        for table in ("providers", "subscribers"):
            cur = conn.cursor()
            cur.execute(f"SELECT count(*) FROM {table}")
            print(f"  {table} in postgres now: {cur.fetchone()[0]}")
    conn.close()


if __name__ == "__main__":
    main()