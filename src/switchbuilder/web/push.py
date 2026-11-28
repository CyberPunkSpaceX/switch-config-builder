"""Push approved Production projects to switches, with a backup first and an automatic rollback.

Rules:

* Only from the Production space, and only a project whose saved data is
  exactly what was approved and promoted from the Lab (see promote.py).
* Only client admins (Admin / Super Admin) talk to switches. Everyone in the
  client sees the list of pushes; the diff is shown to Configurators and up.
* The config sent is built on the server from the project. Nothing typed on
  the page reaches the switch, and the switch must be in the client's SSH
  networks with an already known host key.
* Every push starts with a preview: the running config is read and kept as a
  backup, and the switch says what would change. The push itself must follow
  within ``PREVIEW_TTL`` seconds and the running config must still be the
  same, or it is refused.
* The switch commits with its own safe-revert timer. The page then checks the
  switch is still reachable and asks for confirmation. Without one, the
  switch puts the old config back by itself.
* ``EXB_PUSH_DISABLE=true`` turns pushing off for everyone. Every step is in
  the audit log and in the client's list of pushes.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone

from flask import Blueprint, request
from werkzeug.exceptions import HTTPException

from .. import push as engine
from .. import sshfetch
from . import auth, backups, clients

bp = Blueprint("push", __name__)
log = logging.getLogger("switchbuilder.push")

PREVIEW_TTL = 15 * 60
SCHEMA = """
CREATE TABLE IF NOT EXISTS config_pushes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    project_id INTEGER NOT NULL,
    project_name TEXT NOT NULL,
    project_sha TEXT NOT NULL,
    review_id INTEGER,
    vendor TEXT NOT NULL,
    host TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 22,
    mode TEXT NOT NULL DEFAULT 'merge',          -- merge (add and change) or replace (whole config)
    status TEXT NOT NULL,                        -- previewed, waiting, confirmed, rolled_back, expired, failed
    diff TEXT NOT NULL DEFAULT '',
    check_ok INTEGER NOT NULL DEFAULT 0,
    running_sha TEXT NOT NULL DEFAULT '',
    backup_id INTEGER,
    after_backup_id INTEGER,
    minutes INTEGER,
    deadline REAL,                               -- epoch seconds when the switch reverts by itself
    message TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_ts REAL NOT NULL,
    pushed_by TEXT NOT NULL DEFAULT '',
    pushed_at TEXT NOT NULL DEFAULT '',
    checked_at TEXT NOT NULL DEFAULT '',
    decided_by TEXT NOT NULL DEFAULT '',
    decided_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS config_pushes_client ON config_pushes (client_id, id);
"""
LABEL = {"previewed": "Previewed", "waiting": "Waiting for confirmation", "confirmed": "Confirmed",
         "rolled_back": "Rolled back", "expired": "Timer ran out (switch rolled back)", "failed": "Failed",
         "cancelled": "Preview not used"}
_busy: set = set()
_busy_lock = threading.Lock()


def migrate(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)


def disabled() -> bool:
    return os.environ.get("EXB_PUSH_DISABLE", "").lower() in ("1", "true", "yes")


def _need_push() -> dict:
    """Talking to switches: client admins (Admin and Super Admin), in Production only."""
    c = clients.need("admin")
    if c["space"] != "production":
        clients._json_abort(409, "Pushing to switches is done from the Production space.")
    if disabled() or sshfetch.disabled():
        clients._json_abort(403, "Pushing to switches is turned off on this server.")
    return c


def _audit(c: dict, what: str) -> None:
    log.warning("audit: push: %r %s (client %r)", auth.current_user()["username"], what, c["name"])


def _when(ts: float | None) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC") if ts else ""


def _approved(c: dict, project: sqlite3.Row) -> sqlite3.Row | None:
    """The promoted review whose snapshot is exactly this Production project, or None."""
    sha = engine.sha(project["data"])
    for r in auth.db().execute("SELECT id, data, decided_by FROM project_reviews WHERE client_id = ? AND name = ? "
                               "AND status = 'promoted' ORDER BY id DESC", (c["id"], project["name"])):
        if engine.sha(r["data"]) == sha:
            return r
    return None


def _project(c: dict, pid) -> tuple[sqlite3.Row, dict]:
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        clients._json_abort(400, "Pick a saved Production project.")
    p = auth.db().execute("SELECT * FROM projects WHERE id = ? AND client_id = ? AND space = 'production'",
                          (pid, c["id"])).fetchone()
    if p is None:
        clients._json_abort(404, "That Production project doesn't exist.")
    return p, json.loads(p["data"])


def _build(data: dict):
    from ..generator import build
    res = build(data)
    if res.errors:
        e = res.errors[0]
        clients._json_abort(400, f"The project has {len(res.errors)} error(s), first: {e.get('section')}: "
                                 f"{e.get('message')}. Nothing was sent.")
    if len(res.set_text) > engine.MAX_CONFIG:
        clients._json_abort(400, "The config is too large to push.")
    return res


def _creds(row: sqlite3.Row, body: dict) -> tuple[str, str, object, int]:
    """(username, password, key, port) from the request, the same way SSH fetch does it."""
    username = str(body.get("username") or "").strip()
    password = str(body.get("password") or "")
    pkey = None
    if body.get("use_key"):
        pkey = clients.ssh_key_for(row, "cfg")   # pushes only ever use the config key
        if pkey is None:
            clients._json_abort(400, "This client has no config SSH key yet (the read-only key can't push). A client "
                                     "admin makes one on the client page, or push with a password.")
        username = username or clients.key_user_for(row, "cfg")
        password = ""
        if not username:
            clients._json_abort(400, "Enter the switch username for the config key (or set it on the client page).")
    elif not (username and password):
        clients._json_abort(400, "Enter the switch username and password, or sign in with the SSH key.")
    try:
        port = int(body.get("port") or 22)
        if not 1 <= port <= 65535:
            raise ValueError
    except (TypeError, ValueError):
        clients._json_abort(400, "SSH port must be 1-65535.")
    return username, password, pkey, port


class _Session:
    """Sign in to one switch of the client, one action at a time per switch."""

    def __init__(self, c: dict, vendor: str, host: str, body: dict, port: int | None = None):
        self.c, self.vendor, self.host = c, vendor, host
        self.row = clients.row(c["id"])
        self.nets, _ = sshfetch.check_networks(self.row["ssh_networks"])
        if not self.nets:
            clients._json_abort(403, f"SSH is off for {c['name']}: no switch networks are set on the client page.")
        self.username, self.password, self.pkey, p = _creds(self.row, body)
        self.port = port or p
        self.key = (c["id"], host.lower())
        self.keep = False   # True: the session is handed to a holder thread and stays open

    def __enter__(self):
        try:
            sshfetch.check_rate(auth.current_user()["username"])
        except sshfetch.FetchError as exc:
            clients._json_abort(429, str(exc))
        with _busy_lock:
            if self.key in _busy:
                clients._json_abort(409, f"Someone is already working on {self.host}; try again in a moment.")
            _busy.add(self.key)
        try:
            self.shell, self.driver = engine.connect(self.vendor, self.host, self.username, self.password,
                                                     clients.client_folder(self.c["id"]), self.port, self.nets,
                                                     self.pkey)
        except BaseException as exc:
            with _busy_lock:
                _busy.discard(self.key)
            raise _friendly(self.host, exc) from None
        return self.driver

    def __exit__(self, *exc):
        try:
            if not self.keep:
                self.shell.close()
        finally:
            self.password = ""
            with _busy_lock:
                _busy.discard(self.key)
        return False


def _friendly(host: str, exc: BaseException) -> BaseException:
    import paramiko
    if isinstance(exc, (engine.PushError, sshfetch.FetchError)):
        return engine.PushError(str(exc))
    if isinstance(exc, paramiko.AuthenticationException):
        return engine.PushError(f"{host}: sign-in failed (wrong username, password or key).")
    if isinstance(exc, (OSError, paramiko.SSHException, EOFError)):
        return engine.PushError(f"{host}: could not connect ({exc.__class__.__name__}: {exc})."[:300])
    return exc


def _row(c: dict, push_id: int) -> sqlite3.Row:
    r = auth.db().execute("SELECT * FROM config_pushes WHERE id = ? AND client_id = ?", (push_id, c["id"])).fetchone()
    if r is None:
        clients._json_abort(404, "No such push.")
    return r


def _expire(cid: int) -> None:
    """Waiting pushes whose timer has run out: the switch has rolled back by itself."""
    db = auth.db()
    db.execute("UPDATE config_pushes SET status = 'expired', message = 'The timer ran out without a confirmation, "
               "so the switch put the old config back by itself.' WHERE client_id = ? AND status = 'waiting' AND "
               "deadline < ?", (cid, time.time()))
    held = [k for k, d in engine.DRIVERS.items() if d.held]
    for (pid,) in db.execute(f"SELECT id FROM config_pushes WHERE client_id = ? AND status = 'waiting' AND vendor IN "
                             f"({','.join('?' * len(held))})", (cid, *held)).fetchall():
        age = _alive(pid)
        if age is None or age > 30:
            db.execute("UPDATE config_pushes SET status = 'rolled_back', message = 'The server lost the session it "
                       "held, so the switch undid the change by itself (Safe Mode).' WHERE id = ?", (pid,))
    db.execute("UPDATE config_pushes SET status = 'cancelled' WHERE client_id = ? AND status = 'previewed' AND "
               "created_ts < ?", (cid, time.time() - PREVIEW_TTL))
    db.commit()


def _out(r: sqlite3.Row, show_diff: bool) -> dict:
    d = {k: r[k] for k in r.keys() if k not in ("diff", "created_ts", "deadline", "running_sha", "project_sha")}
    d["label"] = LABEL.get(r["status"], r["status"])
    d["deadline_at"] = _when(r["deadline"])
    d["seconds_left"] = max(0, int(r["deadline"] - time.time())) if r["status"] == "waiting" and r["deadline"] else 0
    d["preview_left"] = max(0, int(r["created_ts"] + PREVIEW_TTL - time.time())) if r["status"] == "previewed" else 0
    if show_diff:
        d["diff"] = r["diff"]
    return d


def _fail(c: dict, push_id: int | None, what: str, exc: Exception):
    msg = str(exc)
    if push_id:
        auth.db().execute("UPDATE config_pushes SET message = ? WHERE id = ?", (msg[:1000], push_id))
        auth.db().commit()
    _audit(c, f"{what} failed: {msg}")
    return {"error": msg}, 502


def _keep_backup(cid: int, host: str, text: str, source: str, who: str, note: str) -> dict:
    """Keep a config as a client backup. backups.store() reads Junos only for now; other vendors are kept as they are."""
    saved = backups.store(auth.db(), cid, [{"name": host, "address": host, "text": text}], source, who, note=note,
                          space="production")
    if saved and saved[0].get("id"):
        return saved[0]
    db = auth.db()
    digest = engine.sha(text)
    last = db.execute("SELECT id, sha, created_at FROM config_backups WHERE client_id = ? AND space = 'production' AND "
                      "host = ? AND source = ? ORDER BY id DESC LIMIT 1", (cid, host, source)).fetchone()
    if last and last[1] == digest:
        return {"id": last[0], "host": host, "unchanged": True, "since": last[2]}
    bid = db.execute("INSERT INTO config_backups (client_id, space, host, address, source, note, text, sha, lines, "
                     "created_at, created_by) VALUES (?, 'production', ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                     (cid, host, host, source, note[:200], text, digest, text.count("\n") + 1, auth._now(), who)).lastrowid
    db.commit()
    return {"id": bid, "host": host, "unchanged": False}


# ---------------------------------------------------- held sessions (MikroTik Safe Mode)
# The thread that holds the session lives in one web worker; any worker can ask it to confirm or roll back.
# They talk through small files in <data>/push-held (not the database, so the holder never takes a write lock).
def _held_dir():
    d = auth.data_dir() / "push-held"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _alive(push_id: int, folder=None) -> float | None:
    """Seconds since the holder of this push last showed a sign of life, or None if it never did."""
    try:
        return time.time() - ((folder or _held_dir()) / f"{int(push_id)}.alive").stat().st_mtime
    except OSError:
        return None


def _start_holder(push_id: int, shell, drv, deadline: float) -> None:
    folder = _held_dir()
    (folder / f"{push_id}.alive").touch()
    try:
        shell.transport.set_keepalive(15)
    except Exception:  # noqa: BLE001
        pass
    threading.Thread(target=_hold, args=(folder, push_id, shell, drv, deadline), daemon=True,
                     name=f"push-hold-{push_id}").start()


def _hold(folder, push_id: int, shell, drv, deadline: float) -> None:
    """Keep the Safe Mode session open; act on confirm / rollback asked through a file (any worker can ask)."""
    alive, ask, answer = (folder / f"{push_id}.{x}" for x in ("alive", "request", "answer"))
    try:
        while True:
            if time.time() >= deadline:
                drv.drop()
                log.warning("audit: push: timer of push %s ran out; Safe Mode session closed, the switch undid it",
                            push_id)
                return
            req = ask.read_text().strip() if ask.exists() else ""
            if req in ("confirm", "rollback"):
                try:
                    drv.confirm() if req == "confirm" else drv.rollback()
                    result = f"{req}:done"
                except Exception as exc:  # noqa: BLE001
                    drv.drop()  # when keeping fails, undo: never leave it half-done
                    result = f"{req}:failed: {exc or exc.__class__.__name__}"[:500]
                tmp = answer.with_suffix(".tmp")
                tmp.write_text(result)
                tmp.replace(answer)  # appears whole, never half-written
                return
            if shell.transport is None or not shell.transport.is_active():
                return
            alive.touch()
            time.sleep(1)
    finally:
        shell.close()
        alive.unlink(missing_ok=True)


def _ask_holder(push_id: int, action: str, wait: float = 45) -> None:
    """Ask the thread holding the session to confirm or roll back, and wait for its answer."""
    folder = _held_dir()
    age = _alive(push_id, folder)
    if age is None or age > 15 or (folder / f"{push_id}.request").exists():
        raise engine.PushError("The server no longer holds the Safe Mode session, so the switch has undone the change "
                               "by itself.")
    tmp = folder / f"{push_id}.request.tmp"
    tmp.write_text(action)
    tmp.replace(folder / f"{push_id}.request")
    answer = folder / f"{push_id}.answer"
    end = time.time() + wait
    while time.time() < end:
        time.sleep(0.3)
        if answer.exists():
            text = answer.read_text()
            for f in (answer, folder / f"{push_id}.request"):
                f.unlink(missing_ok=True)
            if text == f"{action}:done":
                return
            raise engine.PushError(text.split(":", 2)[-1].strip() + " The session was closed, so Safe Mode undid "
                                   "the change.")
    raise engine.PushError("The session holder did not answer; if it is gone, the switch undoes the change by itself.")


# ----------------------------------------------------------------- routes
@bp.get("/push")
def pushes():
    c = clients.need("viewer")
    _expire(c["id"])
    db = auth.db()
    show = clients.RANK[c["role"]] >= clients.RANK["editor"]
    rows = db.execute("SELECT * FROM config_pushes WHERE client_id = ? ORDER BY id DESC LIMIT 100", (c["id"],))
    projects = []
    if c["space"] == "production":
        for p in db.execute("SELECT * FROM projects WHERE client_id = ? AND space = 'production' "
                            "ORDER BY name COLLATE NOCASE", (c["id"],)):
            data = json.loads(p["data"])
            vendor = str(data.get("vendor") or "juniper")
            sup = engine.support(vendor)
            projects.append({"id": p["id"], "name": p["name"], "vendor": vendor, "approved": _approved(c, p) is not None,
                             "ready": sup.ready, "method": sup.method,
                             "modes": list(engine.DRIVERS[vendor].modes) if vendor in engine.DRIVERS else [],
                             "hostname": str((data.get("system") or {}).get("hostname") or "")})
    return {"pushes": [_out(r, show) for r in rows], "projects": projects, "role": c["role"], "space": c["space"],
            "off": disabled() or sshfetch.disabled(),
            "support": {k: vars(v) for k, v in engine.SUPPORT.items()},
            "minutes": {"min": engine.MIN_MINUTES, "max": engine.MAX_MINUTES, "default": engine.DEFAULT_MINUTES}}


@bp.post("/push/preview")
def preview():
    c = _need_push()
    body = request.get_json(silent=True) or {}
    p, data = _project(c, body.get("project_id"))
    review = _approved(c, p)
    if review is None:
        return {"error": f"{p['name']} is not an approved config: its Production copy differs from what was approved "
                         "and promoted from the Lab. Ask for approval in the Lab space, then promote it."}, 403
    vendor = str(data.get("vendor") or "juniper")
    if not engine.support(vendor).ready:
        return {"error": f"Pushing to {vendor} switches is not available yet."}, 400
    mode = "replace" if body.get("mode") == "replace" else "merge"
    if mode not in engine.DRIVERS[vendor].modes:
        return {"error": f"Replacing the whole config is not offered for {vendor}; use the builder's commands."}, 400
    host = str(body.get("host") or "").strip()
    if not host:
        return {"error": "Enter the switch address."}, 400
    res = _build(data)
    me = auth.current_user()["username"]
    sess = _Session(c, vendor, host, body)
    try:
        with sess as drv:
            running = drv.running()
            result = drv.preview(res, mode)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001 - every failure goes back to the page and the audit log
        return _fail(c, None, f"preview of {p['name']!r} on {host}", _friendly(host, exc))
    saved = [_keep_backup(c["id"], host, running, "prepush", me, f"before pushing {p['name']}")]
    want = str((data.get("system") or {}).get("hostname") or "").strip()
    found = engine.DRIVERS[vendor].hostname(running)
    warnings = []
    if want and found and want.lower() != found.lower():
        warnings.append(f"The switch is called {found}, but the project is for {want}. Check you have the right "
                        "switch; you have to tick 'push anyway' to continue.")
    if not result["diff"].strip():
        warnings.append("The switch already has this config: nothing would change.")
    now = auth._now()
    pid = auth.db().execute(
        "INSERT INTO config_pushes (client_id, project_id, project_name, project_sha, review_id, vendor, host, port, "
        "mode, status, diff, check_ok, running_sha, backup_id, message, created_by, created_at, created_ts) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'previewed', ?, ?, ?, ?, ?, ?, ?, ?)",
        (c["id"], p["id"], p["name"], engine.sha(p["data"]), review["id"], vendor, host, sess.port, mode,
         result["diff"][:500_000], int(result["check_ok"]), engine.config_sha(running), (saved[0] or {}).get("id"),
         " ".join(warnings) if result["check_ok"] else "commit check failed: " + result["check"][-500:],
         me, now, time.time())).lastrowid
    auth.db().commit()
    _audit(c, f"previewed {p['name']!r} on {host} ({mode}, push {pid}, check {'ok' if result['check_ok'] else 'FAILED'})")
    return {"id": pid, "diff": result["diff"], "check_ok": result["check_ok"], "check": result["check"],
            "note": result.get("note", "From the switch itself (show | compare and commit check)."),
            "warnings": warnings, "hostname_mismatch": bool(want and found and want.lower() != found.lower()),
            "backup": saved[0] if saved else None, "preview_seconds": PREVIEW_TTL}


@bp.post("/push/<int:push_id>/apply")
def apply(push_id: int):
    c = _need_push()
    body = request.get_json(silent=True) or {}
    _expire(c["id"])
    r = _row(c, push_id)
    if r["status"] != "previewed":
        return {"error": "Only a fresh preview can be pushed. Preview again."}, 409
    if not r["check_ok"]:
        return {"error": "The switch's commit check failed in the preview, so this can't be pushed."}, 409
    if not r["diff"].strip():
        return {"error": "Nothing would change on the switch."}, 409
    try:
        mins = engine.minutes(body.get("minutes", engine.DEFAULT_MINUTES))
    except engine.PushError as exc:
        return {"error": str(exc)}, 400
    p, data = _project(c, r["project_id"])
    if engine.sha(p["data"]) != r["project_sha"] or _approved(c, p) is None:
        return {"error": "The project changed since the preview (or is no longer approved). Preview again."}, 409
    want = str((data.get("system") or {}).get("hostname") or "").strip()
    db = auth.db()
    waiting = db.execute("SELECT id FROM config_pushes WHERE client_id = ? AND lower(host) = lower(?) AND "
                         "status = 'waiting'", (c["id"], r["host"])).fetchone()
    if waiting:
        return {"error": f"Push {waiting[0]} to {r['host']} is still waiting for confirmation. Confirm or roll it "
                         "back first."}, 409
    res = _build(data)
    me = auth.current_user()["username"]
    note = engine.comment(f"switchbuilder push {push_id} by {me}")
    sess = _Session(c, r["vendor"], r["host"], body, port=r["port"])
    try:
        with sess as drv:
            running = drv.running()
            if engine.config_sha(running) != r["running_sha"]:
                db.execute("UPDATE config_pushes SET status = 'cancelled', message = 'The switch config changed after "
                           "the preview.' WHERE id = ?", (push_id,))
                db.commit()
                return {"error": "The switch's running config changed after the preview. Preview again."}, 409
            found = drv.hostname(running)
            if want and found and want.lower() != found.lower() and not body.get("hostname_ok"):
                return {"error": f"The switch is called {found}, not {want}. Tick 'push anyway' if this is right."}, 409
            started = time.time()
            out = drv.apply(res, r["mode"], mins, str(push_id), note)
            if drv.held:  # MikroTik: the session stays open in Safe Mode until confirm, rollback or the timer
                sess.keep = True
                _start_holder(push_id, sess.shell, drv, started + mins * 60)
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        exc = _friendly(r["host"], exc)
        db.execute("UPDATE config_pushes SET status = 'failed' WHERE id = ?", (push_id,))
        db.commit()
        return _fail(c, push_id, f"push {push_id} of {r['project_name']!r} to {r['host']}", exc)
    deadline = started + mins * 60
    db.execute("UPDATE config_pushes SET status = 'waiting', minutes = ?, deadline = ?, pushed_by = ?, pushed_at = ?, "
               "message = ? WHERE id = ?", (mins, deadline, me, auth._now(), out[-500:], push_id))
    db.commit()
    _audit(c, f"pushed {r['project_name']!r} to {r['host']} with a {mins} minute rollback timer (push {push_id}, "
              f"backup {r['backup_id']})")
    return {"status": "waiting", "deadline_at": _when(deadline), "seconds_left": int(deadline - time.time())}


@bp.post("/push/<int:push_id>/check")
def check(push_id: int):
    """A new SSH session: is the switch still reachable, and is the timer still running?"""
    c = _need_push()
    body = request.get_json(silent=True) or {}
    _expire(c["id"])
    r = _row(c, push_id)
    if r["status"] != "waiting":
        return {"error": f"This push is {LABEL.get(r['status'], r['status']).lower()}, nothing to check."}, 409
    try:
        with _Session(c, r["vendor"], r["host"], body, port=r["port"]) as drv:
            if drv.held:  # a second session shows the switch is reachable; the held one carries the change
                drv.running()
                age = _alive(push_id)
                pending = "Safe Mode is on in the session the server holds" if age is not None and age < 15 else ""
            else:
                pending = drv.pending_confirm(str(push_id))
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        return _fail(c, push_id, f"reachability check of push {push_id}", _friendly(r["host"], exc))
    auth.db().execute("UPDATE config_pushes SET checked_at = ? WHERE id = ?", (auth._now(), push_id))
    auth.db().commit()
    _audit(c, f"checked {r['host']} after push {push_id}: reachable, timer {'running' if pending else 'NOT running'}")
    return {"reachable": True, "pending": pending, "seconds_left": max(0, int(r["deadline"] - time.time()))}


@bp.post("/push/<int:push_id>/<action>")
def decide(push_id: int, action: str):
    if action not in ("confirm", "rollback", "discard"):
        clients._json_abort(404, "Unknown action.")
    c = _need_push()
    body = request.get_json(silent=True) or {}
    _expire(c["id"])
    r = _row(c, push_id)
    db = auth.db()
    me = auth.current_user()["username"]
    if action == "discard":
        if r["status"] != "previewed":
            return {"error": "Only an unused preview can be discarded."}, 409
        db.execute("UPDATE config_pushes SET status = 'cancelled', decided_by = ?, decided_at = ? WHERE id = ?",
                   (me, auth._now(), push_id))
        db.commit()
        return {"status": "cancelled"}
    if r["status"] != "waiting":
        return {"error": f"This push is {LABEL.get(r['status'], r['status']).lower()}; nothing to {action}."}, 409
    if action == "confirm" and r["deadline"] - time.time() < 5:
        return {"error": "Too late: the timer is about to run out and the switch will roll back."}, 409
    note = engine.comment(f"switchbuilder push {push_id} {'confirmed' if action == 'confirm' else 'rolled back'} by {me}")
    try:
        if engine.DRIVERS[r["vendor"]].held:
            _ask_holder(push_id, action)
        with _Session(c, r["vendor"], r["host"], body, port=r["port"]) as drv:
            if not drv.held:
                drv.confirm(str(push_id), note) if action == "confirm" else drv.rollback(str(push_id), note)
            after = drv.running()
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        return _fail(c, push_id, f"{action} of push {push_id}", _friendly(r["host"], exc))
    saved = _keep_backup(c["id"], r["host"], after, "postpush", me, f"after push {push_id} ({action})")
    status = "confirmed" if action == "confirm" else "rolled_back"
    db.execute("UPDATE config_pushes SET status = ?, decided_by = ?, decided_at = ?, after_backup_id = ?, message = ? "
               "WHERE id = ?", (status, me, auth._now(), saved.get("id"),
                                "Kept on the switch." if status == "confirmed" else "Rolled back on request.",
                                push_id))
    db.commit()
    _audit(c, f"{'confirmed' if status == 'confirmed' else 'rolled back'} push {push_id} of {r['project_name']!r} on "
              f"{r['host']}")
    return {"status": status}


def init_app(app) -> None:
    app.register_blueprint(bp)
