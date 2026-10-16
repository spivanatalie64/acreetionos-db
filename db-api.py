#!/usr/bin/env python3
"""
acreetionos-db — a tiny HTTP front for a SQLite file.

Why this exists instead of a database server:

  SQLite has no network protocol, so nothing on this host or the internet can
  connect to the database. It is a file. The only thing that can read it is the
  process running in the same container. That removes the entire category of
  "database credential leaked / database port exposed" for a project holding
  provider passwords and subscriber email addresses.

  The trade is that a Worker on Cloudflare cannot open the file, so this process
  exists to serve it over loopback. That is the whole design.

Python standard library only — no Flask, no driver, no ORM. SQLite ships with
CPython. Runs comfortably inside a 128 MiB cgroup limit.

Endpoints (all require the bearer token except /health):
    GET    /health
    GET    /providers?status=&pending_removal=&limit=&cursor=
    GET    /providers/<id>
    PUT    /providers            upsert by id
    DELETE /providers/<id>
    GET    /subscribers?list=&confirmed_only=
    GET    /subscribers/by-token/<token>
    PUT    /subscribers          upsert by (list, email)
    DELETE /subscribers?list=&email=
    POST   /subscribers/confirm  mark confirmed_at, the double opt-in step

Shared store endpoints (bead ray: rate limiting, bead 38u: AI budget, bead 7k8: mail queue):
    POST /limits/check     atomic windowed counter: {bucket, limit, window_ms,
                           weight=1}. Counts weight against limit inside a
                           wall-clock aligned window; allows when count <= limit.
                           SQLite BEGIN IMMEDIATE makes this atomic across every
                           caller on this machine AND across Worker isolates via
                           this shim. This is the replacement for the per-isolate
                           rateLimitMap in index.js, which resets on every cold
                           start and is nearly free to evade under load.
    POST /limits/add       charge to a bucket without an allow check (budget
                           top-ups after a response is already generated).
    POST /replay           {key, ttl}: INSERT-first-wins dedupe. The Worker
                           relies on this for one-shot confirmation tokens.
    GET  /mail-queue       pending rows (limit param, default 50)
    POST /mail-queue       enqueue {id, kind, to_email, payload, ttl}
    POST /mail-queue/<id>/claim      atomic claim for the drain job
    POST /mail-queue/<id>/sent       mark sent / last_error
    DELETE /mail-queue/<id>          remove a row

PRIVACY: keys arriving here are already hashed by the Worker (HMAC of the
visitor IP using a Worker-side secret salt). This file never sees a raw IP.
"""

import hashlib
import hmac
import json
import os
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

DB_PATH = os.environ.get("DB_PATH", "/data/acreetionos.db")
TOKEN_PATH = os.environ.get("TOKEN_PATH", "/run/secrets/api_token")
LISTEN_HOST = os.environ.get("LISTEN_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8081"))
MAX_BODY = 256 * 1024
DEFAULT_LIMIT = 100
MAX_LIMIT = 500
MAIL_KINDS = ("confirm",)
MIN_WINDOW_MS = 1_000                 # 1 s — windows below this are noise
MAX_WINDOW_MS = 86_400_000 * 30       # 30 d — a budget month
MAX_BUCKET_LEN = 256                  # hashed keys stay small; refuse creeps
MAX_WEIGHT = 10_000                   # no single call may leap 10k tokens
SWEEP_INTERVAL_S = 60                 # background cleanup cadence

_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS providers (
    id                  TEXT PRIMARY KEY,
    org                 TEXT NOT NULL,
    email               TEXT NOT NULL,
    website             TEXT NOT NULL DEFAULT '',
    mirror_url          TEXT,
    location            TEXT,
    bandwidth           TEXT NOT NULL DEFAULT '',
    notes               TEXT NOT NULL DEFAULT '',
    password            TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'pending',
    created             TEXT NOT NULL,
    removal_requested   INTEGER NOT NULL DEFAULT 0,
    removal_reason      TEXT,
    discord_user_id     TEXT NOT NULL DEFAULT '',
    subscribed          INTEGER NOT NULL DEFAULT 0,
    vetting_score       INTEGER NOT NULL DEFAULT 0,
    vetting_flags       TEXT NOT NULL DEFAULT '[]',
    personal_email      INTEGER NOT NULL DEFAULT 0,
    last_seen           TEXT,
    expiry_warning_sent INTEGER NOT NULL DEFAULT 0,
    confirm_token       TEXT,
    email_confirmed_at  TEXT
);
CREATE INDEX IF NOT EXISTS providers_status_idx  ON providers (status);
CREATE INDEX IF NOT EXISTS providers_created_idx ON providers (created DESC);
CREATE INDEX IF NOT EXISTS providers_removal_idx ON providers (removal_requested)
    WHERE removal_requested = 1;
-- NOTE: providers_token_idx (unique on confirm_token) is created in
-- ensure_columns(), AFTER the column exists. Putting it here killed the old
-- database on startup — CREATE TABLE IF NOT EXISTS does not reconcile an
-- existing table's columns, so the index referenced a column that does not
-- exist yet in a pre-7k8 database.

CREATE TABLE IF NOT EXISTS subscribers (
    list              TEXT NOT NULL CHECK (list IN ('hosting','newsletter')),
    email             TEXT NOT NULL,
    org               TEXT NOT NULL DEFAULT '',
    subscribed        TEXT NOT NULL,
    unsubscribe_token TEXT NOT NULL,
    confirmed_at      TEXT,
    PRIMARY KEY (list, email)
);
CREATE UNIQUE INDEX IF NOT EXISTS subscribers_token_idx ON subscribers (unsubscribe_token);
CREATE INDEX IF NOT EXISTS subscribers_confirmed_idx ON subscribers (list, confirmed_at);

CREATE TABLE IF NOT EXISTS rate_buckets (
    key       TEXT NOT NULL,
    window_id INTEGER NOT NULL,          -- wall-clock floor(now / window_ms)
    window_ms INTEGER NOT NULL,
    count     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (key, window_id)
);
CREATE INDEX IF NOT EXISTS rate_buckets_sweep_idx ON rate_buckets (window_id);

CREATE TABLE IF NOT EXISTS replay_keys (
    key        TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    expires_at INTEGER
);
CREATE INDEX IF NOT EXISTS replay_sweep_idx ON replay_keys (expires_at);

-- Email queue served by the drain job on this host. The Worker enqueues and
-- returns immediately (bead 7k8: enqueue-and-drain, never a synchronous send):
-- if this host is down, signups succeed and the mail is merely late. The
-- service fails DEFERRED, not OPEN.
CREATE TABLE IF NOT EXISTS mail_queue (
    id           TEXT PRIMARY KEY,
    kind         TEXT NOT NULL,
    to_email     TEXT NOT NULL,
    payload      TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    claim_id     TEXT,
    claimed_at   INTEGER,
    sent_at      INTEGER,
    attempts     INTEGER NOT NULL DEFAULT 0,
    last_error   TEXT,
    expires_at   INTEGER               -- SELF-CLEAN: stale confirmations die here
);
CREATE INDEX IF NOT EXISTS mail_queue_pending_idx ON mail_queue (sent_at, created_at);
CREATE INDEX IF NOT EXISTS mail_queue_sweep_idx ON mail_queue (expires_at);

CREATE TABLE IF NOT EXISTS r2_migration_log (
    r2_key      TEXT PRIMARY KEY,
    namespace   TEXT NOT NULL,
    migrated_at TEXT NOT NULL DEFAULT (datetime('now')),
    checksum    TEXT
);

CREATE TABLE IF NOT EXISTS kv (
    k          TEXT PRIMARY KEY,
    v          TEXT NOT NULL,
    expires_at INTEGER
);
CREATE INDEX IF NOT EXISTS kv_expiry_idx ON kv (expires_at);
"""


def ensure_columns():
    """Carry old tables to the current shape without a migration framework.

    The ALTERs here mirror the CREATE TABLE above; keep them in sync when new
    columns land. Each runs only when the column is absent, so restarts are
    idempotent.
    """
    cols = {r["name"] for r in db().execute("PRAGMA table_info(providers)").fetchall()}
    if "confirm_token" not in cols:
        db().execute("ALTER TABLE providers ADD COLUMN confirm_token TEXT")
    if "email_confirmed_at" not in cols:
        db().execute("ALTER TABLE providers ADD COLUMN email_confirmed_at TEXT")
    # Unique index follows the columns (see SCHEMA note): partial-unique so a
    # NULL confirm_token never collides, which is most of the table forever.
    db().execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS providers_token_idx "
        "ON providers (confirm_token) WHERE confirm_token IS NOT NULL"
    )


def now_ms():
    return int(time.time() * 1000)


def sweep():
    """Expire rate buckets, replay keys and abandoned mail jobs.

    A rate-bucket row is dead once its window closed and enough margin has
    passed that no caller in that window can still arrive. Replay keys and mail
    jobs have explicit TTLs from their callers.
    """
    now = now_ms()
    # A bucket is gone when (window_id + 1) * window_ms is a minute behind now.
    db().execute(
        "DELETE FROM rate_buckets WHERE (window_id + 1) * window_ms < ?",
        (now - 60_000,),
    )
    db().execute("DELETE FROM replay_keys WHERE expires_at IS NOT NULL AND expires_at < ?", (now,))
    db().execute("DELETE FROM mail_queue WHERE expires_at IS NOT NULL AND expires_at < ?", (now,))


def sweep_forever():
    while True:
        time.sleep(SWEEP_INTERVAL_S)
        try:
            sweep()
        except sqlite3.Error as exc:
            sys.stderr.write("sweeper: database error: %s\n" % exc)


def db():
    """One connection per thread. SQLite connections are not thread safe."""
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        conn.execute("PRAGMA cache_size=-8000")  # 8 MiB page cache
        _local.conn = conn
    return conn


def load_token():
    with open(TOKEN_PATH) as fh:
        return fh.read().strip()


class Handler(BaseHTTPRequestHandler):
    server_version = "acreetionos-db"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    # ── helpers ──────────────────────────────────────────────────────────
    def send(self, code, payload=None):
        body = b"" if payload is None else json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def fail(self, code, msg):
        self.send(code, {"error": msg})

    def guarded(self, fn, *args, **kwargs):
        """Run a handler and turn any escaping exception into a clean response.

        Without this a single SQL error raised inside do_PUT propagated out of
        the handler, http.server tore down the connection, and the client saw a
        reset with no status code at all. The first version of put_provider did
        exactly that because of a typo in its ON CONFLICT clause, which is
        exactly the kind of failure that is invisible in testing and obvious in
        production. A broken handler must still answer.
        """
        try:
            return fn(*args, **kwargs)
        except sqlite3.Error as exc:
            sys.stderr.write("database error: %s\n" % exc)
            return self.fail(500, "database error")
        except Exception as exc:  # noqa: BLE001
            sys.stderr.write("handler error: %r\n" % (exc,))
            return self.fail(500, "internal error")

    def authorised(self):
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return False
        # Constant-time compare: a timing oracle here would leak the token.
        return hmac.compare_digest(header[7:], self.server.api_token)

    def body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            return None
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw or b"{}")

    # ── routing ──────────────────────────────────────────────────────────
    def do_GET(self):
        if self.path.startswith("/health"):
            self.send(200, {"ok": True, "db": os.path.basename(DB_PATH)})
            return
        if not self.authorised():
            self.fail(401, "unauthorised")
            return
        url = urlparse(self.path)
        q = parse_qs(url.query)
        parts = [p for p in url.path.split("/") if p]

        if parts[:1] == ["providers"]:
            if len(parts) == 3 and parts[1] == "by-token":
                return self.guarded(self.provider_by_token, unquote(parts[2]))
            if len(parts) == 1:
                return self.guarded(self.list_providers, q)
            return self.guarded(self.get_provider, unquote(parts[1]))
        if parts[:1] == ["subscribers"] and len(parts) == 3 and parts[1] == "by-token":
            return self.guarded(self.subscriber_by_token, unquote(parts[2]))
        if parts[:1] == ["subscribers"]:
            return self.guarded(self.list_subscribers, q)
        if parts[:1] == ["mail-queue"]:
            return self.guarded(self.mail_queue_list, q)
        self.fail(404, "not found")

    def do_PUT(self):
        if not self.authorised():
            self.fail(401, "unauthorised")
            return
        parts = [p for p in urlparse(self.path).path.split("/") if p]
        try:
            payload = self.body()
        except (ValueError, json.JSONDecodeError):
            return self.fail(400, "invalid json")
        if payload is None:
            return self.fail(413, "body too large")
        if parts[:1] == ["providers"]:
            return self.guarded(self.put_provider, payload)
        if parts[:1] == ["subscribers"]:
            return self.guarded(self.put_subscriber, payload)
        self.fail(404, "not found")

    def do_DELETE(self):
        if not self.authorised():
            self.fail(401, "unauthorised")
            return
        url = urlparse(self.path)
        parts = [p for p in url.path.split("/") if p]
        q = parse_qs(url.query)
        if parts[:1] == ["providers"] and len(parts) == 2:
            return self.guarded(self.delete_provider, unquote(parts[1]))
        if parts[:1] == ["subscribers"]:
            lst = (q.get("list") or [""])[0]
            email = (q.get("email") or [""])[0]
            if lst not in ("hosting", "newsletter") or not email:
                return self.fail(400, "list and email required")
            return self.guarded(self.delete_subscriber, lst, email)
        if parts[:1] == ["mail-queue"] and len(parts) == 2:
            return self.guarded(self.mail_queue_delete, unquote(parts[1]))
        self.fail(404, "not found")

    def do_POST(self):
        if not self.authorised():
            self.fail(401, "unauthorised")
            return
        parts = [p for p in urlparse(self.path).path.split("/") if p]
        try:
            payload = self.body()
        except (ValueError, json.JSONDecodeError):
            return self.fail(400, "invalid json")
        if payload is None:
            return self.fail(413, "body too large")
        if parts[:2] == ["subscribers", "confirm"]:
            return self.guarded(self.confirm_subscriber, payload)
        if parts[:2] == ["providers", "confirm"]:
            return self.guarded(self.confirm_provider, payload)
        if parts[:2] == ["limits", "check"]:
            return self.guarded(self.limits_check, payload, allow_over=False)
        if parts[:2] == ["limits", "add"]:
            return self.guarded(self.limits_check, payload, allow_over=True)
        if parts[:1] == ["replay"]:
            return self.guarded(self.replay_claim, payload)
        # mail-queue/<id>/claim     parts = [mail-queue, <id>, claim]
        # mail-queue/<id>/sent      parts = [mail-queue, <id>, sent]
        if len(parts) == 3 and parts[0] == "mail-queue" and parts[2] in ("claim", "sent"):
            return self.guarded(self.mail_queue_result, unquote(parts[1]), parts[2], payload)
        if parts[:1] == ["mail-queue"]:
            return self.guarded(self.mail_queue_enqueue, payload)
        self.fail(404, "not found")

    # ── handlers ─────────────────────────────────────────────────────────
    def delete_provider(self, pid):
        cur = db().execute("DELETE FROM providers WHERE id = ?", (pid,))
        return self.send(200, {"deleted": cur.rowcount})

    def delete_subscriber(self, lst, email):
        cur = db().execute(
            "DELETE FROM subscribers WHERE list = ? AND email = ?", (lst, email)
        )
        return self.send(200, {"deleted": cur.rowcount})

    def list_providers(self, q):
        where, args = [], []
        status = (q.get("status") or [None])[0]
        if status:
            where.append("status = ?")
            args.append(status)
        pending = (q.get("pending_removal") or [None])[0]
        if pending in ("1", "true"):
            where.append("removal_requested = 1")
        elif pending in ("0", "false"):
            where.append("removal_requested = 0")
        sql = "SELECT * FROM providers"
        if where:
            sql += " WHERE " + " AND ".join(where)
        # Keyset pagination. The old R2 code ignored its 1000-object cap and
        # silently returned a partial list; this cannot do that.
        try:
            limit = min(max(int((q.get("limit") or [DEFAULT_LIMIT])[0]), 1), MAX_LIMIT)
        except ValueError:
            limit = DEFAULT_LIMIT
        cursor = (q.get("cursor") or [None])[0]
        if cursor:
            sql += " AND (created, id) < (SELECT created, id FROM providers WHERE id = ?)"
            args.append(cursor)
        sql += " ORDER BY created DESC, id DESC LIMIT ?"
        args.append(limit + 1)
        rows = db().execute(sql, args).fetchall()
        more = len(rows) > limit
        rows = rows[:limit]
        next_cursor = rows[-1]["id"] if (more and rows) else None
        return self.send(200, {"providers": [dict(r) for r in rows],
                               "next_cursor": next_cursor, "has_more": more})

    def get_provider(self, pid):
        row = db().execute("SELECT * FROM providers WHERE id = ?", (pid,)).fetchone()
        if not row:
            return self.fail(404, "not found")
        return self.send(200, dict(row))

    def put_provider(self, p):
        if not p.get("id") or not p.get("org") or not p.get("email"):
            return self.fail(400, "id, org and email required")
        db().execute(
            """INSERT INTO providers (id, org, email, website, mirror_url, location,
                 bandwidth, notes, password, status, created, removal_requested,
                 removal_reason, discord_user_id, subscribed, vetting_score,
                 vetting_flags, personal_email, last_seen, expiry_warning_sent,
                 confirm_token, email_confirmed_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(id) DO UPDATE SET
                 org=excluded.org, email=excluded.email, website=excluded.website,
                 mirror_url=excluded.mirror_url, location=excluded.location,
                 bandwidth=excluded.bandwidth, notes=excluded.notes,
                 status=excluded.status, removal_requested=excluded.removal_requested,
                 removal_reason=excluded.removal_reason,
                 discord_user_id=excluded.discord_user_id,
                 subscribed=excluded.subscribed, vetting_score=excluded.vetting_score,
                 vetting_flags=excluded.vetting_flags,
                 personal_email=excluded.personal_email, last_seen=excluded.last_seen,
                 expiry_warning_sent=excluded.expiry_warning_sent,
                 confirm_token=excluded.confirm_token,
                 email_confirmed_at=excluded.email_confirmed_at""",
            (
                p["id"], p["org"], p["email"], p.get("website", ""),
                p.get("mirror_url"), p.get("location"), p.get("bandwidth", ""),
                p.get("notes", ""), p.get("password", ""), p.get("status", "pending"),
                p.get("created") or "", int(bool(p.get("removal_requested"))),
                p.get("removal_reason"), p.get("discord_user_id", ""),
                int(bool(p.get("subscribed"))), int(p.get("vetting_score") or 0),
                json.dumps(p.get("vetting_flags") or []),
                int(bool(p.get("personal_email"))), p.get("last_seen"),
                int(bool(p.get("expiry_warning_sent"))),
                p.get("confirm_token"), p.get("email_confirmed_at"),
            ),
        )
        return self.send(200, {"ok": True, "id": p["id"]})

    def provider_by_token(self, token):
        row = db().execute(
            "SELECT * FROM providers WHERE confirm_token = ?", (token,)
        ).fetchone()
        if not row:
            return self.fail(404, "not found")
        return self.send(200, dict(row))

    def confirm_provider(self, s):
        """One-shot email confirmation for a mirror registration (bead 7k8).

        Single use: after this runs the token is consumed, so replaying the
        link cannot flip an admin-approved provider's state again."""
        token = s.get("confirm_token")
        if not token:
            return self.fail(400, "confirm_token required")
        cur = db().execute(
            """UPDATE providers SET email_confirmed_at = datetime('now'),
                  confirm_token = NULL
               WHERE confirm_token = ? AND email_confirmed_at IS NULL""",
            (token,),
        )
        if cur.rowcount == 0:
            return self.fail(404, "unknown token or already confirmed")
        row = db().execute(
            "SELECT * FROM providers WHERE email_confirmed_at = datetime('now')"
        ).fetchone()
        return self.send(200, {"ok": True, "provider": dict(row) if row else None})

    def list_subscribers(self, q):
        lst = (q.get("list") or [None])[0]
        confirmed_only = (q.get("confirmed_only") or ["0"])[0] in ("1", "true")
        sql = "SELECT * FROM subscribers WHERE 1=1"
        args = []
        if lst:
            sql += " AND list = ?"
            args.append(lst)
        if confirmed_only:
            sql += " AND confirmed_at IS NOT NULL"
        sql += " ORDER BY subscribed DESC"
        rows = db().execute(sql, args).fetchall()
        return self.send(200, {"subscribers": [dict(r) for r in rows]})

    def subscriber_by_token(self, token):
        row = db().execute(
            "SELECT * FROM subscribers WHERE unsubscribe_token = ?", (token,)
        ).fetchone()
        if not row:
            return self.fail(404, "not found")
        return self.send(200, dict(row))

    def put_subscriber(self, s):
        lst = s.get("list")
        if lst not in ("hosting", "newsletter"):
            return self.fail(400, "list must be hosting or newsletter")
        if not s.get("email") or not s.get("unsubscribe_token"):
            return self.fail(400, "email and unsubscribe_token required")
        db().execute(
            """INSERT INTO subscribers (list, email, org, subscribed,
                 unsubscribe_token, confirmed_at)
               VALUES (?,?,?,?,?,?)
               ON CONFLICT(list, email) DO UPDATE SET
                 org=excluded.org, unsubscribe_token=excluded.unsubscribe_token""",
            (lst, s["email"], s.get("org", ""),
             s.get("subscribed") or "", s["unsubscribe_token"], s.get("confirmed_at")),
        )
        return self.send(200, {"ok": True, "list": lst, "email": s["email"]})

    def confirm_subscriber(self, s):
        """Double opt-in. Until this runs, a row is unproven and unmailable."""
        token = s.get("unsubscribe_token")
        if not token:
            return self.fail(400, "unsubscribe_token required")
        cur = db().execute(
            """UPDATE subscribers SET confirmed_at = datetime('now')
               WHERE unsubscribe_token = ? AND confirmed_at IS NULL""",
            (token,),
        )
        if cur.rowcount == 0:
            return self.fail(404, "unknown token or already confirmed")
        return self.send(200, {"ok": True, "confirmed": True})

    # ── shared store: rate limits / budget (beads ray + 38u) ─────────────
    def limits_check(self, p, allow_over=False):
        """Atomic windowed counter, valid across Worker isolates and restarts.

        BEGIN IMMEDIATE takes the write lock before reading the previous
        count, so a count can never race even with many concurrent callers.
        Wall-clock windows are aligned on epoch; not a true rolling average,
        which is a documented, honest approximation (see 38u)."""
        try:
            bucket = p["bucket"]
            limit = int(p["limit"])
            window_ms = int(p["window_ms"])
            weight = int(p.get("weight", 1))
        except (KeyError, TypeError, ValueError):
            return self.fail(400, "bucket, limit and window_ms required")
        if (not isinstance(bucket, str) or not bucket
                or len(bucket) > MAX_BUCKET_LEN):
            return self.fail(400, "bucket missing or too long")
        if limit < 1 or weight < 0 or weight > MAX_WEIGHT:
            return self.fail(400, "limit must be >=1, weight in [0, %d]" % MAX_WEIGHT)
        if not (MIN_WINDOW_MS <= window_ms <= MAX_WINDOW_MS):
            return self.fail(400, "window_ms out of range")
        now = now_ms()
        window_id = now // window_ms
        conn = db()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT count FROM rate_buckets WHERE key = ? AND window_id = ?",
                (bucket, window_id),
            ).fetchone()
            prev = row["count"] if row else 0
            allowed = allow_over or (prev + weight <= limit)
            new_count = prev + weight
            if weight > 0:
                conn.execute(
                    """INSERT INTO rate_buckets (key, window_id, window_ms, count)
                       VALUES (?, ?, ?, ?)
                       ON CONFLICT(key, window_id)
                       DO UPDATE SET count = excluded.count""",
                    (bucket, window_id, window_ms, new_count),
                )
            conn.execute("COMMIT")
        except sqlite3.Error:
            conn.execute("ROLLBACK")
            raise
        return self.send(200, {"count": new_count, "limit": limit, "allowed": allowed,
                               "used": prev})

    def replay_claim(self, p):
        """First-wins dedupe. An expired key frees up at claim time.

        This backs one-shot confirm tokens (7k8): the first reader of a link
        claims it; replays inside the TTL window get 'claimed': false."""
        key = p.get("key")
        ttl = int(p.get("ttl", 86_400))   # default one day
        if not isinstance(key, str) or not key or len(key) > MAX_BUCKET_LEN:
            return self.fail(400, "key missing or too long")
        if not (1 <= ttl <= 86_400 * 30):
            return self.fail(400, "ttl out of range")
        now = now_ms()
        expires_at = now + ttl * 1000
        conn = db()
        try:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                """INSERT INTO replay_keys (key, created_at, expires_at)
                   VALUES (?, ?, ?)
                   ON CONFLICT(key) DO UPDATE SET
                     created_at = excluded.created_at,
                     expires_at = excluded.expires_at
                   WHERE replay_keys.expires_at IS NOT NULL
                     AND replay_keys.expires_at < ?""",
                (key, now, expires_at, now),
            )
            if cur.rowcount > 0:
                conn.execute("COMMIT")
                return self.send(200, {"claimed": True})
            conn.execute("COMMIT")
        except sqlite3.Error:
            conn.execute("ROLLBACK")
            raise
        return self.send(200, {"claimed": False})

    # ── mail queue (bead 7k8) ─────────────────────────────────────────────
    def mail_queue_enqueue(self, p):
        row_id = p.get("id")
        kind = p.get("kind")
        to_email = p.get("to_email")
        payload = p.get("payload")
        try:
            ttl = int(p.get("ttl", 172_800))  # 48 h: stale confirmations die here
        except (TypeError, ValueError):
            return self.fail(400, "invalid ttl")
        if not isinstance(row_id, str) or len(row_id) > 64:
            return self.fail(400, "id required")
        if kind not in MAIL_KINDS:
            return self.fail(400, "kind must be one of %s" % (MAIL_KINDS,))
        if not isinstance(to_email, str) or not to_email or "@" not in to_email:
            return self.fail(400, "to_email required")
        if not isinstance(payload, dict):
            return self.fail(400, "payload must be an object")
        cur = db().execute(
            """INSERT INTO mail_queue
                 (id, kind, to_email, payload, created_at, expires_at)
               VALUES (?, ?, ?, ?, ?, ?)
               ON CONFLICT(id) DO NOTHING""",
            (row_id, kind, to_email,
             json.dumps(payload), now_ms(), now_ms() + ttl * 1000),
        )
        if cur.rowcount == 0:
            return self.send(200, {"ok": True, "duplicate": True})
        return self.send(200, {"ok": True, "queued": True})

    def mail_queue_list(self, q):
        """Pending jobs in send order. Used by the drain job on this host."""
        try:
            limit = min(max(int((q.get("limit") or ["50"])[0]), 1), MAX_LIMIT)
        except ValueError:
            limit = 50
        now = now_ms()
        rows = db().execute(
            """SELECT * FROM mail_queue
               WHERE sent_at IS NULL
                 AND (claim_id IS NULL OR claim_id = '' OR
                      (claim_id IS NOT NULL AND
                       (claimed_at IS NULL OR claimed_at < ?)))
                 AND (expires_at IS NULL OR expires_at > ?)
               ORDER BY created_at
               LIMIT ?""",
            (now - 10 * 60 * 1000, now, limit),
        ).fetchall()
        return self.send(200, {"jobs": [dict(r) for r in rows]})

    def mail_queue_result(self, job_id, action, p):
        conn = db()
        if action == "claim":
            try:
                claim_ttl = int(p.get("claim_ttl", 300))
            except (TypeError, ValueError):
                return self.fail(400, "invalid claim_ttl")
            claim_id = p.get("claim_id")
            if not isinstance(claim_id, str) or len(claim_id) > 64:
                return self.fail(400, "claim_id required")
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute(
                    "SELECT * FROM mail_queue WHERE id = ?", (job_id,)
                ).fetchone()
                if not row or row["sent_at"] or row["expires_at"] and row["expires_at"] < now_ms():
                    conn.execute("COMMIT")
                    return self.fail(404, "no claimable job")
                st = row["claim_id"]
                still_held = (st and row["claimed_at"] and
                              row["claimed_at"] > now_ms() - claim_ttl * 1000)
                if still_held:
                    conn.execute("COMMIT")
                    return self.fail(409, "already claimed")
                conn.execute(
                    "UPDATE mail_queue SET claim_id = ?, claimed_at = ? WHERE id = ?",
                    (claim_id, now_ms(), job_id),
                )
                conn.execute("COMMIT")
            except sqlite3.Error:
                conn.execute("ROLLBACK")
                raise
            return self.send(200, {"ok": True, "claimed": True, "job": dict(row)})
        # action == "sent"
        ok = bool(p.get("ok"))
        error = p.get("error")
        if ok:
            conn.execute(
                "UPDATE mail_queue SET sent_at = ?, claim_id = NULL WHERE id = ?",
                (now_ms(), job_id),
            )
            return self.send(200, {"ok": True, "sent": True})
        attempts = conn.execute(
            "SELECT attempts FROM mail_queue WHERE id = ?", (job_id,)
        ).fetchone()
        if not attempts:
            return self.fail(404, "unknown job")
        conn.execute(
            """UPDATE mail_queue
               SET attempts = attempts + 1, last_error = ?, claim_id = NULL
               WHERE id = ?""",
            (str(error or "")[:500], job_id),
        )
        return self.send(200, {"ok": True, "retry": True,
                               "attempts": attempts["attempts"] + 1})

    def mail_queue_delete(self, job_id):
        cur = db().execute("DELETE FROM mail_queue WHERE id = ?", (job_id,))
        return self.send(200, {"deleted": cur.rowcount})


def main():
    with open(DB_PATH, "a"):
        pass
    conn = db()
    conn.executescript(SCHEMA)
    ensure_columns()
    token = load_token()
    # The sweeper does the deletes that nobody else in the request path would
    # think to do: dead rate windows, stale replay keys, abandoned mail jobs.
    threading.Thread(target=sweep_forever, daemon=True).start()
    server = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    server.daemon_threads = True
    server.api_token = token
    sys.stderr.write(
        "acreetionos-db listening on %s:%d, db=%s\n" % (LISTEN_HOST, LISTEN_PORT, DB_PATH)
    )
    server.serve_forever()


if __name__ == "__main__":
    main()