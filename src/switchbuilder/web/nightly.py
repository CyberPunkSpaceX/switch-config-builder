"""Nightly config backups per client, with change alerts.

A client admin lists the client's switches (address, vendor, SSH port), picks a
time and time zone, and who hears about changes (email addresses and Teams,
Slack, Discord or other webhooks). Every night the jobs service
(``switchbuilder jobs``, see ``jobs.py``) signs in to each switch with the client's
SSH key, reads its config with the vendor's read-only command
(``sshfetch.VENDOR_CMDS``) and keeps it as a config backup of the Production
space (source "nightly"). An unchanged config is not stored again. When a
config changed, the alert lists what changed; when a switch could not be read,
the alert says why.

Nightly backups only use the client's SSH key (or the server key): a password
is never stored. Webhook addresses hold a token, so they are kept encrypted
with the master key, like the SSH key.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from flask import Blueprint, flash, redirect, render_template, request, url_for

from .. import compare as cmp
from .. import notify, redact, sshfetch
from . import auth, backups, clients

bp = Blueprint("nightly", __name__, template_folder="templates")
log = logging.getLogger("switchbuilder.nightly")

SCHEMA = """
CREATE TABLE IF NOT EXISTS nightly_settings (
    client_id INTEGER PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 0,
    at_time TEXT NOT NULL DEFAULT '02:00',
    tz TEXT NOT NULL DEFAULT 'UTC',
    switches TEXT NOT NULL DEFAULT '',     -- one per line: address [vendor] [port]
    emails TEXT NOT NULL DEFAULT '',
    hooks TEXT NOT NULL DEFAULT '',        -- JSON list, encrypted with the master key
    notify_on TEXT NOT NULL DEFAULT 'changes',
    last_day TEXT NOT NULL DEFAULT '',     -- the local day of the last scheduled run
    updated_at TEXT NOT NULL DEFAULT '',
    updated_by TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS nightly_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    trigger TEXT NOT NULL,
    changed INTEGER NOT NULL DEFAULT 0,
    unchanged INTEGER NOT NULL DEFAULT 0,
    failed INTEGER NOT NULL DEFAULT 0,
    details TEXT NOT NULL DEFAULT '[]',
    alert TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS nightly_runs_client ON nightly_runs (client_id, id);
"""
NOTIFY_ON = {"changes": "When a config changed or a switch could not be read",
             "always": "After every run, also when nothing changed",
             "never": "Never (only keep the backups)"}
MAX_SWITCHES = 200
KEEP_RUNS = 100
DEFAULT_VENDOR = "juniper"
_running: set[int] = set()
_running_lock = threading.Lock()


def migrate(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


# --------------------------------------------------------------- settings
def parse_switches(text: str) -> tuple[list[dict], list[str]]:
    """'address [vendor] [port]' lines -> ([{host, vendor, port}], problems)."""
    out, problems, seen = [], [], set()
    for n, line in enumerate((text or "").splitlines(), 1):
        words = line.split("#", 1)[0].replace(",", " ").split()
        if not words:
            continue
        host, vendor, port = words[0], DEFAULT_VENDOR, 22
        for w in words[1:]:
            if w.isdigit():
                port = int(w)
            else:
                vendor = w.lower()
        if vendor not in sshfetch.VENDOR_CMDS:
            problems.append(f"Line {n}: {vendor} is not a vendor with SSH backups "
                            f"(use one of {', '.join(sorted(sshfetch.VENDOR_CMDS))}).")
        elif not 1 <= port <= 65535:
            problems.append(f"Line {n}: port {port} is not 1-65535.")
        elif len(host) > 253 or host.startswith("-"):
            problems.append(f"Line {n}: {host} is not an address.")
        elif host.lower() not in seen:
            seen.add(host.lower())
            out.append({"host": host, "vendor": vendor, "port": port})
    if len(out) > MAX_SWITCHES:
        problems.append(f"At most {MAX_SWITCHES} switches per client.")
    return out[:MAX_SWITCHES], problems


def settings_of(conn: sqlite3.Connection, cid: int) -> dict:
    r = conn.execute("SELECT * FROM nightly_settings WHERE client_id = ?", (cid,)).fetchone()
    if r is None:
        return {"client_id": cid, "enabled": 0, "at_time": "02:00", "tz": os.environ.get("TZ") or "UTC", "switches": "",
                "emails": "", "hooks": "", "notify_on": "changes", "last_day": "", "updated_at": "", "updated_by": ""}
    return dict(r)


def hooks_of(s: dict) -> list[str]:
    if not s.get("hooks"):
        return []
    try:
        return json.loads(clients._fernet().decrypt(s["hooks"].encode()).decode())
    except Exception:  # noqa: BLE001 - made with another master key
        log.warning("nightly: the webhooks of client %s cannot be decrypted (another master key?)", s["client_id"])
        return []


def _zone(name: str):
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        return timezone.utc


def local_now(s: dict, now: datetime | None = None) -> datetime:
    return (now or datetime.now(timezone.utc)).astimezone(_zone(s["tz"]))


def is_due(s: dict, now: datetime | None = None) -> bool:
    if not s["enabled"]:
        return False
    local = local_now(s, now)
    return local.strftime("%H:%M") >= s["at_time"] and s["last_day"] != local.date().isoformat()


# ------------------------------------------------------------------ a run
def _diff_lines(result: dict, limit: int = 25) -> list[str]:
    out = []
    for sec in result.get("sections", []):
        for x in sec["lines"]:
            if x["op"] in "+-":
                out.append(f"{x['op']} {x['text'].strip()}")
    return out[:limit] + ([f"… and {len(out) - limit} more lines"] if len(out) > limit else [])


def run(conn: sqlite3.Connection, cid: int, trigger: str, now: datetime | None = None) -> dict:
    """Back up every switch of client ``cid`` now, store the configs, send the alert. Returns the run row."""
    with _running_lock:
        if cid in _running:
            return {"error": "A backup of this client is already running."}
        _running.add(cid)
    try:
        return _run(conn, cid, trigger)
    finally:
        with _running_lock:
            _running.discard(cid)


def _run(conn: sqlite3.Connection, cid: int, trigger: str) -> dict:
    conn.row_factory = sqlite3.Row
    client = conn.execute("SELECT * FROM clients WHERE id = ?", (cid,)).fetchone()
    if client is None:
        return {"error": "No such client."}
    s = settings_of(conn, cid)
    switches, _ = parse_switches(s["switches"])
    rid = conn.execute("INSERT INTO nightly_runs (client_id, started_at, trigger) VALUES (?, ?, ?)",
                       (cid, _now(), trigger)).lastrowid
    conn.commit()
    details, problem = [], ""
    nets, _ = sshfetch.check_networks(client["ssh_networks"])
    pkey = None
    try:
        pkey = clients.ssh_key_for(client, "ro")
    except Exception as exc:  # noqa: BLE001 - a broken key must not stop the jobs service
        problem = f"the SSH key cannot be used ({exc.__class__.__name__})"
    user = clients.key_user_for(client, "ro")
    if not switches:
        problem = "no switches are listed"
    elif sshfetch.disabled() or not nets:
        problem = "SSH is off for this client (no switch networks on the client page)"
    elif pkey is None and not problem:
        problem = "the client has no SSH key (make one on the client page)"
    elif not user:
        problem = "no SSH username is set for the key (client page)"
    if problem:
        details = [{"host": sw["host"], "status": "failed", "error": problem} for sw in switches] or [
            {"host": "-", "status": "failed", "error": problem}]
    else:
        results = sshfetch.fetch([sw["host"] for sw in switches], user, "", clients.client_folder(cid), "nightly",
                                 nets=nets, pkey=pkey, client=client["name"], max_hosts=MAX_SWITCHES,
                                 vendors={sw["host"]: sw["vendor"] for sw in switches},
                                 ports={sw["host"]: sw["port"] for sw in switches})
        for r in results:
            if not r["ok"]:
                details.append({"host": r["host"], "status": "failed", "error": r.get("error", "failed")})
                continue
            saved = backups.store(conn, cid, [{"name": r["host"], "address": r["host"], "text": r["text"]}],
                                  "nightly", "nightly", "Nightly backup", space="production")[0]
            if saved.get("error"):
                details.append({"host": r["host"], "status": "failed", "error": "the switch's answer is not a config"})
            elif saved["unchanged"]:
                details.append({"host": r["host"], "name": saved["host"], "status": "unchanged", "id": saved["id"]})
            else:
                row = conn.execute("SELECT * FROM config_backups WHERE id = ?", (saved["id"],)).fetchone()
                before = backups.previous(conn, row)
                d = {"host": r["host"], "name": saved["host"], "id": saved["id"], "status": "changed" if before else "new"}
                if before is not None:
                    # Alerts leave the server (email, chat): never put a secret in them.
                    res = cmp.compare(redact.config(before["text"]), redact.config(row["text"]), ignore_secrets=True)
                    d["previous"] = before["id"]
                    d["summary"] = (f"{res.get('only_a', 0)} lines removed, {res.get('only_b', 0)} added"
                                    if not res.get("identical") else "only passwords or keys changed")
                    d["diff"] = _diff_lines(res)
                details.append(d)
    count = {k: sum(d["status"] in v for d in details) for k, v in
             (("changed", ("changed", "new")), ("unchanged", ("unchanged",)), ("failed", ("failed",)))}
    alert = _alert(conn, client, s, count, details)
    conn.execute("UPDATE nightly_runs SET finished_at = ?, changed = ?, unchanged = ?, failed = ?, details = ?, "
                 "alert = ? WHERE id = ?", (_now(), count["changed"], count["unchanged"], count["failed"],
                                            json.dumps(details), alert, rid))
    conn.execute("DELETE FROM nightly_runs WHERE client_id = ? AND id NOT IN (SELECT id FROM nightly_runs WHERE "
                 "client_id = ? ORDER BY id DESC LIMIT ?)", (cid, cid, KEEP_RUNS))
    conn.commit()
    log.warning("audit: nightly backup (%s) of client %r: %d changed, %d unchanged, %d failed", trigger,
                client["name"], count["changed"], count["unchanged"], count["failed"])
    return dict(conn.execute("SELECT * FROM nightly_runs WHERE id = ?", (rid,)).fetchone())


def _alert(conn, client, s: dict, count: dict, details: list[dict]) -> str:
    """Send the alert if the settings ask for one. Returns what happened, for the run history."""
    worth = s["notify_on"] == "always" or (s["notify_on"] == "changes" and (count["changed"] or count["failed"]))
    emails, _ = notify.parse_emails(s["emails"])
    hooks = hooks_of(s)
    if not worth or not (emails or hooks):
        return ""
    title = (f"{client['name']}: {count['changed']} switch config{'s' if count['changed'] != 1 else ''} changed"
             + (f", {count['failed']} switch{'es' if count['failed'] != 1 else ''} not backed up" if count["failed"] else ""))
    if not count["changed"] and not count["failed"]:
        title = f"{client['name']}: nightly backup, nothing changed ({count['unchanged']} switches)"
    lines = []
    for d in details:
        if d["status"] in ("changed", "new"):
            lines.append(f"{d.get('name') or d['host']} ({d['host']}): "
                         + (d.get("summary", "") if d["status"] == "changed" else "first backup"))
            lines += ["    " + x for x in d.get("diff", [])]
    for d in details:
        if d["status"] == "failed":
            lines.append(f"NOT BACKED UP {d['host']}: {d['error']}")
    lines.append(f"{count['unchanged']} switch{'es' if count['unchanged'] != 1 else ''} unchanged.")
    base = os.environ.get("EXB_PUBLIC_URL", "").rstrip("/")
    if base:
        lines.append(f"Backups and compare: {base}/build/juniper#Backups%20%26%20compare")
    problems = notify.send_all(emails, hooks, title, "\n".join(lines),
                               {"client": client["name"], "changed": count["changed"], "failed": count["failed"]})
    return "sent" if not problems else "not all sent: " + "; ".join(problems)[:500]


def run_due(conn: sqlite3.Connection, now: datetime | None = None) -> list[int]:
    """Run every client whose time has come today. Each run is claimed first, so it happens once."""
    conn.row_factory = sqlite3.Row
    ran = []
    for r in conn.execute("SELECT * FROM nightly_settings WHERE enabled = 1").fetchall():
        s = dict(r)
        if not is_due(s, now):
            continue
        day = local_now(s, now).date().isoformat()
        cur = conn.execute("UPDATE nightly_settings SET last_day = ? WHERE client_id = ? AND last_day != ?",
                           (day, s["client_id"], day))
        conn.commit()
        if cur.rowcount != 1:
            continue
        try:
            run(conn, s["client_id"], "schedule", now)
        except Exception:  # noqa: BLE001 - one client must not stop the others
            log.exception("nightly backup of client %s failed", s["client_id"])
        ran.append(s["client_id"])
    return ran


# ------------------------------------------------------------------- pages
@bp.get("/clients/<int:cid>/nightly")
def nightly_page(cid: int):
    c = clients._client_admin(cid)
    db = auth.db()
    s = settings_of(db, cid)
    switches, problems = parse_switches(s["switches"])
    runs = [dict(r, details=json.loads(r["details"])) for r in db.execute(
        "SELECT * FROM nightly_runs WHERE client_id = ? ORDER BY id DESC LIMIT 20", (cid,))]
    from zoneinfo import available_timezones
    return render_template("auth/nightly.html", c=c, s=s, switches=switches, problems=problems, runs=runs,
                           hooks=[notify.short(h) for h in hooks_of(s)], notify_on=NOTIFY_ON,
                           vendors=sorted(sshfetch.VENDOR_CMDS), zones=sorted(available_timezones()),
                           smtp=notify.smtp_ready(), key=bool(c["ssh_key"]) or bool(sshfetch.key_file()),
                           nets=bool(sshfetch.check_networks(c["ssh_networks"])[0]), ssh_off=sshfetch.disabled(),
                           next_run=_next_run(s))


def _next_run(s: dict) -> str:
    if not s["enabled"]:
        return ""
    local = local_now(s)
    if s["last_day"] != local.date().isoformat():
        return ("within a minute" if local.strftime("%H:%M") >= s["at_time"]
                else f"today at {s['at_time']} ({s['tz']})")
    return f"tomorrow at {s['at_time']} ({s['tz']})"


@bp.post("/clients/<int:cid>/nightly")
def nightly_save(cid: int):
    c = clients._client_admin(cid)
    db, who = auth.db(), auth.current_user()["username"]
    action = request.form.get("action", "save")
    back = redirect(url_for("nightly.nightly_page", cid=cid))
    s = settings_of(db, cid)
    if action == "run":
        if cid in _running:
            flash("A backup of this client is already running.", "error")
            return back
        app = auth.data_dir()

        def go():
            conn = sqlite3.connect(app / "users.db", timeout=30)
            try:
                run(conn, cid, f"run now by {who}")
            except Exception:  # noqa: BLE001
                log.exception("nightly backup (run now) of client %s failed", cid)
            finally:
                conn.close()
        threading.Thread(target=go, daemon=True).start()
        flash("Backing up now. Reload this page in a minute to see the result.", "ok")
        return back
    if action == "test":
        emails, _ = notify.parse_emails(s["emails"])
        hooks = hooks_of(s)
        if not emails and not hooks:
            flash("Add an email address or a webhook first.", "error")
            return back
        problems = notify.send_all(emails, hooks, f"{c['name']}: test alert from Switch Config Builder",
                                   f"Nightly backup alerts for {c['name']} arrive here. Sent by {who}.")
        flash("Test alert sent." if not problems else "Not all sent: " + "; ".join(problems), "error" if problems else "ok")
        return back

    switches, problems = parse_switches(request.form.get("switches", ""))
    emails, bad_mail = notify.parse_emails(request.form.get("emails", ""))
    problems += [f"{b} is not an email address." for b in bad_mail]
    hooks = hooks_of(s)
    if request.form.get("clear_hooks"):
        hooks = []
    new_hooks, hook_problems = notify.parse_hooks(request.form.get("hooks", ""))
    problems += hook_problems
    hooks = list(dict.fromkeys(hooks + new_hooks))[:10]
    at = request.form.get("at_time", "02:00").strip()
    if len(at) != 5 or at[2] != ":" or not (at[:2].isdigit() and at[3:].isdigit()) or int(at[:2]) > 23 or int(at[3:]) > 59:
        problems.append("Pick a time like 02:00.")
    tz = request.form.get("tz", "UTC").strip()
    if _zone(tz) is timezone.utc and tz != "UTC":
        problems.append(f"{tz} is not a time zone.")
    notify_on = request.form.get("notify_on", "changes")
    if notify_on not in NOTIFY_ON:
        problems.append("Pick when to send alerts.")
    if emails and not notify.smtp_ready():
        problems.append("Email is not set up on this server (EXB_SMTP_HOST), so only webhooks can be used.")
    if problems:
        for p in problems:
            flash(p, "error")
        return back
    enabled = 1 if request.form.get("enabled") else 0
    new = {**s, "enabled": enabled, "at_time": at, "tz": tz, "notify_on": notify_on}
    # Turned on after today's time: the first run is the next night, not right now.
    today = local_now(new).date().isoformat()
    last_day = s["last_day"]
    if enabled and local_now(new).strftime("%H:%M") >= at:
        last_day = today
    text = "\n".join(f"{sw['host']} {sw['vendor']}" + (f" {sw['port']}" if sw["port"] != 22 else "") for sw in switches)
    enc = clients._fernet().encrypt(json.dumps(hooks).encode()).decode() if hooks else ""
    db.execute("INSERT INTO nightly_settings (client_id, enabled, at_time, tz, switches, emails, hooks, notify_on, last_day, "
               "updated_at, updated_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (client_id) DO UPDATE SET "
               "enabled = excluded.enabled, at_time = excluded.at_time, tz = excluded.tz, switches = excluded.switches, "
               "emails = excluded.emails, hooks = excluded.hooks, notify_on = excluded.notify_on, "
               "last_day = excluded.last_day, updated_at = excluded.updated_at, updated_by = excluded.updated_by",
               (cid, enabled, at, tz, text, ", ".join(emails), enc, notify_on, last_day, _now(), who))
    db.commit()
    log.warning("audit: %r changed the nightly backup settings of client %r (%s, %d switches, %d emails, %d webhooks)",
                who, c["name"], "on" if enabled else "off", len(switches), len(emails), len(hooks))
    flash("Saved.", "ok")
    return back


def init_app(app) -> None:
    app.register_blueprint(bp)
