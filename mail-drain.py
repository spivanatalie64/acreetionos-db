#!/usr/bin/env python3
"""
acreetionos-db mail drain (bead 7k8): enqueue-and-drain, the sending half.

The Worker enqueues confirmation emails into the sqlite queue and returns
immediately. This job runs on the VPS next to the container, polls
GET /mail-queue over loopback, sends each job through the local Mailcow relay
and marks it sent. A VPS outage therefore DELAYS confirmations; it never opens
a write. Malformed jobs are skipped and logged, never silently dropped.

Config:
  DB_API base/token — shim token from /opt/acreetionos-db/secrets/api_token
  SMTP              — 127.0.0.1:587 (Mailcow trusts localhost per mynetworks)
"""
import json, smtplib, sys, urllib.request, urllib.error
from email.message import EmailMessage

DB = "http://127.0.0.1:8284"
SMTP = ("127.0.0.1", 587)


def shim(method, path, token, payload=None):
    req = urllib.request.Request(DB + path, method=method,
        data=json.dumps(payload).encode() if payload is not None else None,
        headers={"Authorization": "Bearer " + token,
                 "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode() or "{}")


def main():
    token = open("/opt/acreetionos-db/secrets/api_token").read().strip()
    code, r = shim("GET", "/mail-queue?limit=25", token)
    if code != 200 or not r.get("jobs"):
        return  # nothing to drain; silence is success
    for job in r["jobs"]:
        if job.get("claim_id"):
            continue  # claimed in-flight by another drain run
        rid = job["id"]
        payload = json.loads(job.get("payload") or "{}")
        to = job["to_email"]
        subject = payload.get("subject")
        body = payload.get("body")
        if not subject or not body or "@" not in to:
            log("malformed job %s — skipping (no send, review manually)" % rid)
            continue
        msg = EmailMessage()
        msg["From"] = "AcreetionOS <no-reply@acreetionos.org>"
        msg["To"] = to
        msg["Subject"] = subject
        msg.set_content(body)
        try:
            with smtplib.SMTP(SMTP[0], SMTP[1], timeout=20) as s:
                s.starttls()
                s.sendmail("no-reply@acreetionos.org", [to], msg.as_string())
        except Exception as e:
            shim("POST", "/mail-queue/%s/sent" % rid, token, {"ok": False, "error": repr(e)[:300]})
            log("job %s attempt %s failed: %r" % (rid, job.get("attempts"), e))
            continue
        shim("POST", "/mail-queue/%s/sent" % rid, token, {"ok": True})
        log("job %s sent to %s" % (rid, to))


def log(line):
    sys.stderr.write(line + "\n")


if __name__ == "__main__":
    try:
        sys.exit(main() or 0)
    except Exception as e:
        log("drain aborted: %r" % e)
        sys.exit(1)  # systemd retries next tick; jobs stay queued
