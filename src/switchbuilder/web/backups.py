"""Config backups, config compare, and backup/restore of a whole client.

Config backups: every switch config the builder reads (SSH fetch, EVE-NG lab
pull, or a file someone uploads) can be kept per client, with its date, where
it came from and who got it. An unchanged config is not stored twice.

Compare: two configs (a backup, a fresh SSH fetch, the builder's output, a
switch on the map, a lab pull or pasted text) side by side; see compare.py.

Client backup: one JSON file with a client's projects, maps, config backups
and settings, to keep somewhere safe or to load into another client or server.
Secrets (the SSH key, the EVE-NG password) are only included when asked for,
and are encrypted with this server's master key, so they only work here.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import re
import sqlite3
import zipfile
from datetime import datetime, timezone

from flask import Blueprint, Response, abort, flash, redirect, request, url_for

from .. import compare as cmp
from .. import importer, redact, sshfetch
from . import auth, clients

bp = Blueprint("backups", __name__)
log = logging.getLogger("switchbuilder.backups")

SCHEMA = """
CREATE TABLE IF NOT EXISTS config_backups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    host TEXT NOT NULL,                 -- the switch's host name (or the file name)
    address TEXT NOT NULL DEFAULT '',   -- where it was fetched from
    source TEXT NOT NULL,               -- ssh, eve, upload, map, builder
    note TEXT NOT NULL DEFAULT '',
    text TEXT NOT NULL,
    sha TEXT NOT NULL,
    lines INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    space TEXT NOT NULL DEFAULT 'production'
);
CREATE INDEX IF NOT EXISTS config_backups_host ON config_backups (client_id, host, source);
"""
SOURCES = {"ssh": "SSH fetch", "nightly": "nightly backup", "eve": "EVE-NG lab", "upload": "uploaded",
           "map": "network map", "builder": "builder output", "restore": "restored",
           "prepush": "before a push", "postpush": "after a push"}
# Sources read from the switch itself: their versions form one history per switch.
LIVE_SOURCES = ("ssh", "nightly", "prepush", "postpush")
MAX_TEXT = 2_000_000
KEEP = 50            # versions kept per switch and source
FORMAT = "switchbuilder-client-backup"
FORMATS = (FORMAT, "exbuilder-client-backup")   # files exported before the rename still import
HOST_RE = re.compile(r"host-name\s+\"?([\w.-]+)")
# Other vendors: hostname X (IOS, EOS, NX-OS, OS10, Aruba, ProCurve, FastIron), set hostname X
# (FortiSwitch), /system identity set name=X (MikroTik), configure snmp sysName X (EXOS).
HOST_OTHER_RE = re.compile(r'^\s*(?:hostname|set hostname|configure snmp sysName)\s+"?([\w.-]+)|'
                           r'^/system identity\s+set name="?([\w.-]+)', re.M)   # one line, or two as /export writes it


def migrate(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    if "space" not in {r[1] for r in conn.execute("PRAGMA table_info(config_backups)")}:
        conn.execute("ALTER TABLE config_backups ADD COLUMN space TEXT NOT NULL DEFAULT 'production'")
        conn.commit()


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def host_of(text: str, fallback: str = "") -> str:
    found = HOST_RE.findall(text or "")
    if not found:
        other = HOST_OTHER_RE.search(text or "")
        found = [other.group(1) or other.group(2)] if other else []
    name = found[-1] if found else fallback   # in set lines the last one wins
    return re.sub(r"[^\w.-]+", "-", name or "switch").strip("-")[:80] or "switch"


def is_config(text: str) -> bool:
    """A switch config of any vendor the builder knows."""
    from ..convert import detect
    return bool(importer.to_set_lines(text)) or bool(detect(text)) or sshfetch.looks_like_config(text, "other")


def sha_of(text: str) -> str:
    """Fingerprint of a config, without the lines that change on every fetch (timestamps)."""
    return hashlib.sha256(cmp.stable_text(text).encode()).hexdigest()


def previous(conn: sqlite3.Connection, row) -> sqlite3.Row | None:
    """The version of the same switch before this one (switch sources together, others by source)."""
    if row["source"] in LIVE_SOURCES:
        q = ",".join("?" * len(LIVE_SOURCES))
        return conn.execute(f"SELECT * FROM config_backups WHERE client_id = ? AND space = ? AND host = ? AND "
                            f"source IN ({q}) AND id < ? ORDER BY id DESC LIMIT 1",
                            (row["client_id"], row["space"], row["host"], *LIVE_SOURCES, row["id"])).fetchone()
    return conn.execute("SELECT * FROM config_backups WHERE client_id = ? AND space = ? AND host = ? AND source = ? "
                        "AND id < ? ORDER BY id DESC LIMIT 1",
                        (row["client_id"], row["space"], row["host"], row["source"], row["id"])).fetchone()


def store(conn: sqlite3.Connection, cid: int, items: list[dict], source: str, who: str, note: str = "",
          space: str = "production") -> list[dict]:
    """Keep each {name, text, address} as a backup. Returns [{id, host, unchanged}]."""
    out = []
    for it in items:
        text = str(it.get("text") or "")
        if not text.strip() or len(text) > MAX_TEXT or not is_config(text):
            out.append({"host": str(it.get("name") or ""), "error": "not a switch config"})
            continue
        host = host_of(text, str(it.get("name") or ""))
        sha = sha_of(text)
        group = LIVE_SOURCES if source in LIVE_SOURCES else (source,)
        q = ",".join("?" * len(group))
        last = conn.execute(f"SELECT id, sha, created_at FROM config_backups WHERE client_id = ? AND space = ? AND "
                            f"host = ? AND source IN ({q}) ORDER BY id DESC LIMIT 1", (cid, space, host, *group)).fetchone()
        if last and last[1] == sha:
            out.append({"id": last[0], "host": host, "unchanged": True, "since": last[2]})
            continue
        bid = conn.execute("INSERT INTO config_backups (client_id, space, host, address, source, note, text, sha, "
                           "lines, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                           (cid, space, host, str(it.get("address") or "")[:200], source, (note or "")[:200], text, sha,
                            text.count("\n") + 1, str(it.get("created_at") or _now()), who)).lastrowid
        old = conn.execute("SELECT id FROM config_backups WHERE client_id = ? AND space = ? AND host = ? AND source = ? "
                           "ORDER BY id DESC LIMIT -1 OFFSET ?", (cid, space, host, source, KEEP)).fetchall()
        if old:
            conn.executemany("DELETE FROM config_backups WHERE id = ?", old)
        out.append({"id": bid, "host": host, "unchanged": False})
    conn.commit()
    return out


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", name).strip("-") or "config"


def _filename(r) -> str:
    stamp = r["created_at"].replace(" UTC", "").replace(":", "").replace(" ", "-")
    return _safe(f"{r['host']}-{stamp}-{r['source']}") + ".conf"


def _get(cid: int, bid: int):
    r = auth.db().execute("SELECT * FROM config_backups WHERE id = ? AND client_id = ? AND space = ?",
                          (bid, cid, clients.space())).fetchone()
    if r is None:
        abort(404)
    return r


def _files_from_upload() -> list[dict]:
    """Uploaded .conf/.txt files and .zip files -> [{name, text}]."""
    out, total = [], 0
    for f in request.files.getlist("file"):
        raw = f.read()
        if (f.filename or "").lower().endswith(".zip"):
            try:
                zf = zipfile.ZipFile(io.BytesIO(raw))
            except zipfile.BadZipFile:
                continue
            for info in zf.infolist():
                name = info.filename.rsplit("/", 1)[-1]
                if info.is_dir() or not name or name.startswith(".") or info.file_size > MAX_TEXT:
                    continue
                total += info.file_size
                if total > 20_000_000 or len(out) >= 200:
                    break
                out.append({"name": name.rsplit(".", 1)[0], "text": zf.read(info).decode("utf-8", "replace")})
        else:
            total += len(raw)
            if total > 20_000_000 or len(out) >= 200:
                break
            out.append({"name": (f.filename or "config").rsplit(".", 1)[0], "text": raw.decode("utf-8", "replace")})
    return out


# ---------------------------------------------------------- config backups
@bp.get("/backups")
def backups_list():
    c = clients.need("viewer")
    rows = auth.db().execute("SELECT id, host, address, source, note, lines, created_at, created_by FROM config_backups "
                             "WHERE client_id = ? AND space = ? ORDER BY host COLLATE NOCASE, id DESC", (c["id"], c["space"]))
    return {"backups": [dict(r, source_name=SOURCES.get(r["source"], r["source"])) for r in rows],
            "client": c["name"], "can_edit": clients.RANK[c["role"]] >= clients.RANK["editor"],
            "can_delete": c["role"] == "admin"}


@bp.get("/backups/<int:bid>")
def backups_get(bid: int):
    c = clients.need("viewer")
    r = _get(c["id"], bid)
    text = r["text"] if clients.can_see_secrets(c) else redact.config(r["text"])
    if request.args.get("download"):
        return Response(text, mimetype="text/plain",
                        headers={"Content-Disposition": f"attachment; filename={_filename(r)}"})
    out = {k: r[k] for k in ("id", "host", "address", "source", "note", "lines", "created_at", "created_by")}
    return {**out, "text": text, "redacted": not clients.can_see_secrets(c)}


@bp.get("/backups/<int:bid>/changes")
def backups_changes(bid: int):
    """What changed in this version since the version of the same switch before it."""
    c = clients.need("viewer")
    r = _get(c["id"], bid)
    before = previous(auth.db(), r)
    head = {k: r[k] for k in ("id", "host", "source", "created_at", "created_by")}
    if before is None:
        return {"backup": head, "previous": None}
    strict = request.args.get("secrets") == "1" and clients.can_see_secrets(c)
    a, b = before["text"], r["text"]
    if not clients.can_see_secrets(c):
        a, b = redact.config(a), redact.config(b)
    result = cmp.compare(a, b, ignore_secrets=not strict)
    return {"backup": head, "previous": {k: before[k] for k in ("id", "source", "created_at", "created_by")},
            "result": result}


@bp.post("/backups")
def backups_save():
    c = clients.need("editor")
    body = request.get_json(silent=True) or {}
    items = [x for x in body.get("items") or [] if isinstance(x, dict)][:200]
    source = str(body.get("source") or "upload")
    if source not in ("upload", "map", "builder", "eve"):
        return {"error": "Unknown source."}, 400
    if not items:
        return {"error": "Nothing to keep."}, 400
    saved = store(auth.db(), c["id"], items, source, auth.current_user()["username"], str(body.get("note") or ""),
                  space=c["space"])
    return {"saved": saved}


@bp.post("/backups/upload")
def backups_upload():
    c = clients.need("editor")
    files = _files_from_upload()
    if not files:
        return {"error": "Choose config files (.conf, .txt) or a .zip of them."}, 400
    saved = store(auth.db(), c["id"], files, "upload", auth.current_user()["username"],
                  str(request.form.get("note") or ""), space=c["space"])
    return {"saved": saved}


@bp.get("/backups/export")
def backups_export():
    """A zip of the chosen backups, or of the newest backup of each switch."""
    c = clients.need("viewer")
    ids = [int(x) for x in re.findall(r"\d+", request.args.get("ids", ""))][:500]
    db = auth.db()
    if ids:
        q = ",".join("?" * len(ids))
        rows = db.execute(f"SELECT * FROM config_backups WHERE client_id = ? AND space = ? AND id IN ({q})",
                          (c["id"], c["space"], *ids)).fetchall()
    else:
        rows = db.execute("SELECT * FROM config_backups WHERE id IN (SELECT MAX(id) FROM config_backups "
                          "WHERE client_id = ? AND space = ? GROUP BY host)", (c["id"], c["space"])).fetchall()
    if not rows:
        return {"error": "No config backups yet."}, 404
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        used = set()
        for r in rows:
            name = _filename(r) if ids else _safe(r["host"]) + ".conf"
            while name in used:
                name = "x-" + name
            used.add(name)
            zf.writestr(name, r["text"] if clients.can_see_secrets(c) else redact.config(r["text"]))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    return Response(buf.getvalue(), mimetype="application/zip", headers={
        "Content-Disposition": f"attachment; filename={_safe(c['name'])}-configs-{stamp}.zip"})


@bp.post("/backups/<int:bid>/delete")
def backups_delete(bid: int):
    c = clients.need("admin")
    r = _get(c["id"], bid)
    auth.db().execute("DELETE FROM config_backups WHERE id = ?", (bid,))
    auth.db().commit()
    log.warning("audit: %r deleted the config backup of %s from %s (client %r)", auth.current_user()["username"],
                r["host"], r["created_at"], c["name"])
    return {"deleted": bid}


# ------------------------------------------------------------- compare
@bp.post("/compare")
def compare_configs():
    clients.need("viewer")
    body = request.get_json(silent=True) or {}
    sides = []
    for key in ("a", "b"):
        side = body.get(key)
        if not isinstance(side, dict):
            return {"error": "Pick both configs."}, 400
        text = str(side.get("text") or "")
        if len(text) > MAX_TEXT:
            return {"error": "A config is too large (2 MB at most)."}, 400
        sides.append(text)
    result = cmp.compare(sides[0], sides[1], ignore_secrets=body.get("ignore_secrets", True) is not False)
    return (result, 400) if "error" in result else result


# ------------------------------------------------------ client backup
CLIENT_SETTINGS = ("ssh_networks", "ssh_user", "ssh_key_pub", "ssh_user_cfg", "ssh_key_cfg_pub", "eve_url", "eve_user", "eve_folder", "eve_verify",
                   "eve_template", "eve_image")


def export_client(cid: int, with_secrets: bool = False, with_configs: bool = True) -> dict:
    db = auth.db()
    r = clients.row(cid)
    out = {"format": FORMAT, "version": 1, "exported_at": _now(), "exported_by": auth.current_user()["username"],
           "client": {"name": r["name"], **{k: r[k] for k in CLIENT_SETTINGS}},
           "members": [dict(m) for m in db.execute(
               "SELECT u.username, m.role FROM client_members m JOIN users u ON u.id = m.user_id WHERE m.client_id = ? "
               "ORDER BY u.username", (cid,))],
           "projects": [dict(p, data=json.loads(p["data"])) for p in db.execute(
               "SELECT space, name, data, updated_at, updated_by FROM projects WHERE client_id = ? ORDER BY space, name",
               (cid,))],
           "maps": [dict(m, data=json.loads(m["data"])) for m in db.execute(
               "SELECT space, name, data, updated_at, updated_by FROM maps WHERE client_id = ? ORDER BY space, name",
               (cid,))]}
    if with_configs:
        out["config_backups"] = [dict(b) for b in db.execute(
            "SELECT space, host, address, source, note, text, created_at, created_by FROM config_backups WHERE client_id = ? "
            "ORDER BY id", (cid,))]
    if with_secrets:
        out["secrets"] = {"encrypted_with": "this server's master key", "ssh_key": r["ssh_key"],
                          "ssh_key_cfg": r["ssh_key_cfg"],
                          "eve_password": r["eve_password"]}
    return out


def import_client(cid: int, data: dict, replace: bool = True, settings: bool = False, people: bool = False) -> list:
    """Load a client backup into client ``cid``. Returns [(level, message)]."""
    from .. import eveng
    from . import eve
    if not isinstance(data, dict) or data.get("format") not in FORMATS:
        return [("error", "That is not a client backup from Multi-Vendor Switch Config Builder.")]
    db, who, notes, now = auth.db(), auth.current_user()["username"], [], _now()
    counts = {"projects": [0, 0], "maps": [0, 0]}
    try:
        for table in ("projects", "maps"):
            for p in data.get(table) or []:
                if not isinstance(p, dict) or not isinstance(p.get("data"), dict):
                    continue
                name = str(p.get("name") or "").strip()[:100]
                text = json.dumps(p["data"])
                if not name or len(text) > (512 * 1024 if table == "projects" else clients.MAX_MAP_BYTES):
                    continue
                space = p.get("space") if p.get("space") in clients.SPACES else "production"
                exists = db.execute(f"SELECT 1 FROM {table} WHERE client_id = ? AND space = ? AND name = ?",
                                    (cid, space, name)).fetchone()
                if exists and not replace:
                    counts[table][1] += 1
                    continue
                db.execute(f"INSERT INTO {table} (client_id, space, name, data, updated_at, updated_by) "
                           "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (client_id, space, name) DO UPDATE SET data = "
                           "excluded.data, updated_at = excluded.updated_at, updated_by = excluded.updated_by",
                           (cid, space, name, text, str(p.get("updated_at") or now)[:40], str(p.get("updated_by") or who)[:80]))
                counts[table][0] += 1
        n_cfg = 0
        have = {r[0] for r in db.execute("SELECT sha FROM config_backups WHERE client_id = ?", (cid,))}
        for b in data.get("config_backups") or []:
            if not isinstance(b, dict) or not isinstance(b.get("text"), str) or len(b["text"]) > MAX_TEXT:
                continue
            sha = sha_of(b["text"])
            if sha in have or not is_config(b["text"]):
                continue
            have.add(sha)
            source = b.get("source") if b.get("source") in SOURCES else "restore"
            db.execute("INSERT INTO config_backups (client_id, space, host, address, source, note, text, sha, lines, "
                       "created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                       (cid, b.get("space") if b.get("space") in clients.SPACES else "production", host_of(b["text"], str(b.get("host") or "")), str(b.get("address") or "")[:200], source,
                        str(b.get("note") or "")[:200], b["text"], sha, b["text"].count("\n") + 1,
                        str(b.get("created_at") or now)[:40], str(b.get("created_by") or who)[:80]))
            n_cfg += 1
        for table, label in (("projects", "project"), ("maps", "map")):
            done, skipped = counts[table]
            notes.append(("ok", f"{done} {label}{'s' if done != 1 else ''} loaded"
                          + (f", {skipped} skipped because one with the same name exists" if skipped else "") + "."))
        notes.append(("ok", f"{n_cfg} config backup{'s' if n_cfg != 1 else ''} added (copies already here are skipped)."))

        src = data.get("client") if isinstance(data.get("client"), dict) else {}
        if settings and src:
            nets, problems = sshfetch.check_networks(str(src.get("ssh_networks") or ""))
            if problems:
                notes += [("error", f"SSH networks not restored: {p}") for p in problems]
            else:
                db.execute("UPDATE clients SET ssh_networks = ? WHERE id = ?", (", ".join(map(str, nets)), cid))
            for ucol in ("ssh_user", "ssh_user_cfg"):
                user = str(src.get(ucol) or "")
                if not user or auth.USERNAME_RE.match(user):
                    db.execute(f"UPDATE clients SET {ucol} = ? WHERE id = ?", (user, cid))
            url = str(src.get("eve_url") or "")
            try:
                if url:
                    eveng.check_url(url)
                folder = str(src.get("eve_folder") or "/exbuilder")
                eve_user = str(src.get("eve_user") or "")
                if not eve.FOLDER_RE.match(folder) or (eve_user and not auth.USERNAME_RE.match(eve_user)):
                    raise eveng.EveError("the EVE-NG folder or username is not valid")
                db.execute("UPDATE clients SET eve_url = ?, eve_user = ?, eve_folder = ?, eve_verify = ?, eve_template = ?, "
                           "eve_image = ? WHERE id = ?",
                           (url, eve_user, folder, 0 if src.get("eve_verify") in (0, False) else 1,
                            str(src.get("eve_template") or "vjunosswitch") if src.get("eve_template") in eveng.TEMPLATES
                            else "vjunosswitch", str(src.get("eve_image") or "")[:200], cid))
            except eveng.EveError as exc:
                notes.append(("error", f"EVE-NG settings not restored: {exc}"))
            secrets_in = data.get("secrets") if isinstance(data.get("secrets"), dict) else {}
            restored = []
            for col, label in (("ssh_key", "read-only SSH key"), ("ssh_key_cfg", "config SSH key"),
                               ("eve_password", "EVE-NG password")):
                value = secrets_in.get(col)
                if not value:
                    continue
                try:
                    clients._fernet().decrypt(str(value).encode())
                except Exception:  # noqa: BLE001 - another server's master key
                    msg = (f"The {label} in the backup was made on another server (different master key), "
                           "so it was not restored. Set it again.")
                    notes.append(("error", msg))
                    continue
                db.execute(f"UPDATE clients SET {col} = ? WHERE id = ?", (value, cid))
                if col in ("ssh_key", "ssh_key_cfg"):
                    db.execute(f"UPDATE clients SET {col}_pub = ? WHERE id = ?", (str(src.get(f"{col}_pub") or ""), cid))
                restored.append(label)
            notes.append(("ok", "Settings restored" + (f", with the {' and '.join(restored)}" if restored else "") + "."))
        if people:
            missing = []
            for m in data.get("members") or []:
                if not isinstance(m, dict) or m.get("role") not in clients.ROLES:
                    continue
                u = db.execute("SELECT id FROM users WHERE username = ?", (str(m.get("username") or ""),)).fetchone()
                if u is None:
                    missing.append(str(m.get("username")))
                    continue
                db.execute("INSERT INTO client_members (client_id, user_id, role) VALUES (?, ?, ?) ON CONFLICT "
                           "(client_id, user_id) DO UPDATE SET role = excluded.role", (cid, u["id"], m["role"]))
            notes.append(("ok", "People restored." + (f" Not on this server (add them on the Users page first): "
                                                      f"{', '.join(missing[:20])}." if missing else "")))
        db.commit()
    except Exception:
        db.rollback()
        raise
    log.warning("audit: %r loaded a client backup (from %r, %s) into client %r", who,
                (data.get("client") or {}).get("name"), data.get("exported_at"), clients.row(cid)["name"])
    return notes


def _read_backup_file():
    f = request.files.get("file")
    if f is None or not f.filename:
        return None, "Choose a client backup file (.json)."
    try:
        return json.loads(f.read().decode("utf-8")), None
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, "That file is not a client backup (not JSON)."


@bp.get("/clients/<int:cid>/export")
def client_export(cid: int):
    r = clients._client_admin(cid)
    with_secrets = request.args.get("secrets") == "1"
    data = export_client(cid, with_secrets, request.args.get("configs") != "0")
    log.warning("audit: %r downloaded a backup of client %r%s", auth.current_user()["username"], r["name"],
                " with its encrypted secrets" if with_secrets else "")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    return Response(json.dumps(data, indent=1), mimetype="application/json", headers={
        "Content-Disposition": f"attachment; filename={_safe(r['name'])}-backup-{stamp}.json"})


@bp.post("/clients/<int:cid>/import")
def client_import(cid: int):
    clients._client_admin(cid)
    data, problem = _read_backup_file()
    if problem:
        flash(problem, "error")
    else:
        for level, text in import_client(cid, data, replace=request.form.get("existing") != "skip",
                                         settings=bool(request.form.get("settings")),
                                         people=bool(request.form.get("people"))):
            flash(text, level)
    return redirect(url_for("clients.client_page", cid=cid) + "#backup")


@bp.post("/clients/restore")
@auth.admin_required
def client_restore_new():
    """Server admins: make a new client from a backup file."""
    data, problem = _read_backup_file()
    if problem is None and (not isinstance(data, dict) or data.get("format") not in FORMATS):
        problem = "That is not a client backup from Multi-Vendor Switch Config Builder."
    name = (request.form.get("name") or "").strip() or str(((data or {}).get("client") or {}).get("name") or "").strip()
    if problem is None and not clients.NAME_RE.match(name):
        problem = "Give the new client a name (1 to 80 characters, without < > quotes or backslashes)."
    if problem is None and auth.db().execute("SELECT 1 FROM clients WHERE name = ?", (name,)).fetchone():
        problem = f"A client called {name} already exists. Pick another name, or load the backup on that client's page."
    if problem:
        flash(problem, "error")
        return redirect(url_for("clients.clients_page"))
    db = auth.db()
    cid = db.execute("INSERT INTO clients (name, created_at) VALUES (?, ?)", (name, auth._now())).lastrowid
    db.commit()
    log.warning("audit: %r created client %r from a backup", auth.current_user()["username"], name)
    for level, text in import_client(cid, data, settings=True, people=bool(request.form.get("people"))):
        flash(text, level)
    return redirect(url_for("clients.client_page", cid=cid) + "#backup")


def init_app(app) -> None:
    app.register_blueprint(bp)
