"""Clients (tenants): separate spaces for projects, network maps and SSH settings.

Every saved project and network map belongs to one client. People see only the
clients they are members of, and switch between them at the top of the page.

Roles:

* Super Admins (users with the ``admin`` role) see and manage every client,
  and create, rename and delete clients.
* In a client, a member is Read-only (``viewer``: opens projects, maps and
  config backups with passwords and keys hidden), Configurator (``editor``:
  also builds, saves and deletes, and sees secrets) or Admin (``admin``: also
  manages the client's members, SSH and EVE-NG settings, approves Lab work and
  fetches configs over SSH).
* A user with ``users.all_clients`` set has that role in every client, also
  in clients made later. A membership with a higher role wins.

SSH settings per client: the networks its switches are in, up to two SSH keys
the server makes for it, each with its own switch username, and the known
switch host keys (in ``<data>/clients/<id>/ssh_known_hosts``):

* the read-only key (``ssh_key``, ``ssh_user``) for SSH fetch, compare, nightly
  backups and discovery. Every member may fetch with it; only admins may sign in
  with a typed password instead.
* the config key (``ssh_key_cfg``, ``ssh_user_cfg``) for pushes. Only client
  admins make it, and pushes with a key always use this one.

Private keys are stored encrypted with a master key from ``EXB_MASTER_KEY_FILE``
(a Docker secret is best), or else ``<data>/master_key``, created on first use.
"""

from __future__ import annotations

import base64
import functools
import json
import logging
import os
import re
import secrets
import shutil
import sqlite3
from pathlib import Path

from flask import Blueprint, abort, flash, g, jsonify, redirect, render_template, request, session, url_for

from .. import redact, sshfetch
from . import auth

bp = Blueprint("clients", __name__, template_folder="templates")
log = logging.getLogger("switchbuilder.clients")

ROLES = ("viewer", "editor", "admin")
# Every client has two spaces with their own projects, maps and config backups.
# Lab also has the EVE-NG lab tools; Production never talks to EVE-NG.
SPACES = {"production": "Production", "lab": "Lab"}
RANK = {r: i for i, r in enumerate(ROLES)}
LABELS = {"viewer": "Read-only", "editor": "Configurator", "admin": "Admin"}
NAME_RE = re.compile(r"^[^<>\"'`\\]{1,80}$")
FIRST_CLIENT = "Default"
MAX_MAP_BYTES = 20 * 1024 * 1024

SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    created_at TEXT NOT NULL,
    ssh_networks TEXT NOT NULL DEFAULT '',
    ssh_user TEXT NOT NULL DEFAULT '',
    ssh_key TEXT,          -- private key, encrypted with the master key
    ssh_key_pub TEXT,      -- public key line, shown to admins
    ssh_user_cfg TEXT NOT NULL DEFAULT '',
    ssh_key_cfg TEXT,      -- the config (push) key, encrypted with the master key
    ssh_key_cfg_pub TEXT
);
CREATE TABLE IF NOT EXISTS client_members (
    client_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    role TEXT NOT NULL DEFAULT 'viewer',
    PRIMARY KEY (client_id, user_id)
);
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    space TEXT NOT NULL DEFAULT 'production',
    name TEXT NOT NULL,
    data TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL DEFAULT '',
    UNIQUE (client_id, space, name)
);
CREATE TABLE IF NOT EXISTS maps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id INTEGER NOT NULL,
    space TEXT NOT NULL DEFAULT 'production',
    name TEXT NOT NULL,
    data TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL DEFAULT '',
    UNIQUE (client_id, space, name)
);
"""


# ------------------------------------------------------------- migration
def migrate(conn: sqlite3.Connection, folder: Path) -> None:
    """Create the client tables, and move data from before clients existed into a first client."""
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    old_projects = "projects" in tables and "owner_id" in {
        r[1] for r in conn.execute("PRAGMA table_info(projects)")}
    if old_projects:
        conn.execute("ALTER TABLE projects RENAME TO projects_old")
    conn.executescript(SCHEMA)
    _add_space(conn)
    _add_key_columns(conn)
    if "clients" not in tables:  # first start with clients: make the first one
        conn.execute("INSERT INTO clients (name, created_at) VALUES (?, ?)", (FIRST_CLIENT, auth._now()))
    first = conn.execute("SELECT id FROM clients ORDER BY id LIMIT 1").fetchone()
    if old_projects:
        cid = first[0] if first else conn.execute(
            "INSERT INTO clients (name, created_at) VALUES (?, ?)", (FIRST_CLIENT, auth._now())).lastrowid
        rows = conn.execute("SELECT p.name, p.data, p.updated_at, p.owner_id, u.username, u.role FROM projects_old p "
                            "LEFT JOIN users u ON u.id = p.owner_id ORDER BY p.id").fetchall()
        used = set()
        for name, data, updated, owner, username, role in rows:
            new = name if name.lower() not in used else f"{name} ({username or owner})"
            used.add(new.lower())
            conn.execute("INSERT INTO projects (client_id, name, data, updated_at, updated_by) VALUES (?, ?, ?, ?, ?)",
                         (cid, new, data, updated, username or ""))
            if username and role != "admin":  # they keep seeing their own projects
                conn.execute("INSERT OR IGNORE INTO client_members (client_id, user_id, role) VALUES (?, ?, 'editor')",
                             (cid, owner))
        conn.execute("DROP TABLE projects_old")
        log.warning("Moved %d saved project(s) into the client '%s'.", len(rows), FIRST_CLIENT)
    from . import backups, eve
    eve.migrate(conn)
    backups.migrate(conn)
    from . import logs, nightly, promote, push
    promote.migrate(conn)
    push.migrate(conn)
    nightly.migrate(conn)
    logs.migrate(conn)
    from . import samples   # after every table exists: ready-made training clients, added once
    samples.migrate(conn)
    old_known = folder / "ssh_known_hosts"
    if old_known.exists() and first:
        dest = client_folder(first[0], folder)
        dest.mkdir(parents=True, exist_ok=True)
        if not (dest / "ssh_known_hosts").exists():
            shutil.move(str(old_known), dest / "ssh_known_hosts")


def _add_key_columns(conn: sqlite3.Connection) -> None:
    """Clients from before the config key: add its columns (their old key is the read-only key)."""
    cols = {r[1] for r in conn.execute("PRAGMA table_info(clients)")}
    for col, kind in (("ssh_user_cfg", "TEXT NOT NULL DEFAULT ''"), ("ssh_key_cfg", "TEXT"), ("ssh_key_cfg_pub", "TEXT")):
        if col not in cols:
            conn.execute(f"ALTER TABLE clients ADD COLUMN {col} {kind}")


def _add_space(conn: sqlite3.Connection) -> None:
    """Projects and maps from before Lab / Production existed: rebuild them with a space column (production)."""
    for table in ("projects", "maps"):
        cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        if "space" in cols:
            continue
        conn.execute(f"ALTER TABLE {table} RENAME TO {table}_before_spaces")
        conn.executescript(SCHEMA)
        conn.execute(f"INSERT INTO {table} (id, client_id, space, name, data, updated_at, updated_by) "
                     f"SELECT id, client_id, 'production', name, data, updated_at, updated_by FROM {table}_before_spaces")
        conn.execute(f"DROP TABLE {table}_before_spaces")
        conn.commit()
        log.warning("Saved %s now belong to the Production space.", table)


# ------------------------------------------------------------- helpers
def client_folder(cid: int, folder: Path | None = None) -> Path:
    return (folder or auth.data_dir()) / "clients" / str(int(cid))


def _is_server_admin(user=None) -> bool:
    user = user or auth.current_user()
    return bool(user) and user["role"] == "admin"


def my_clients() -> list[dict]:
    """The clients the signed-in user can open, with their role in each."""
    if "my_clients" in g:
        return g.my_clients
    user = auth.current_user()
    if user is None:
        return []
    if _is_server_admin(user):
        rows = auth.db().execute("SELECT id, name, 'admin' AS role, sample FROM clients ORDER BY name COLLATE NOCASE")
        g.my_clients = [dict(r) for r in rows]
        return g.my_clients
    everywhere = user["all_clients"] if "all_clients" in user.keys() and user["all_clients"] in RANK else None
    rows = auth.db().execute(
        "SELECT c.id, c.name, c.sample, m.role FROM clients c LEFT JOIN client_members m ON m.client_id = c.id "
        "AND m.user_id = ? WHERE m.user_id IS NOT NULL OR ? OR c.sample IS NOT NULL ORDER BY c.name COLLATE NOCASE",
        (user["id"], everywhere is not None))
    out = []
    for r in rows:
        # Sample clients (training labs that ship with the app) are open to everyone, Read-only.
        roles = [x for x in (r["role"], everywhere, "viewer" if r["sample"] else None) if x in RANK]
        out.append({"id": r["id"], "name": r["name"], "role": max(roles, key=RANK.get), "sample": r["sample"]})
    g.my_clients = out
    return g.my_clients


def can_see_secrets(c: dict | None = None) -> bool:
    """Read-only people see projects, maps and configs with passwords and keys hidden."""
    c = c if c is not None else current()
    return bool(c) and RANK.get(c["role"], 0) >= RANK["editor"]


def space() -> str:
    """The space picked after sign-in: 'production' (the default) or 'lab'."""
    s = session.get("space")
    return s if s in SPACES else "production"


def current() -> dict | None:
    """The client picked in the switcher (or the first one the user can open), with the space."""
    mine = my_clients()
    want = session.get("client_id")
    for c in mine:
        if c["id"] == want:
            return {**c, "space": space()}
    return {**mine[0], "space": space()} if mine else None


def role_in(cid: int) -> str | None:
    for c in my_clients():
        if c["id"] == cid:
            return c["role"]
    return None


def need(role: str) -> dict:
    """The current client if the user has at least ``role`` there, else a JSON error."""
    c = current()
    if c is None:
        _json_abort(409, "You are not in any client yet. Ask an admin to add you to one.")
    if RANK[c["role"]] < RANK[role]:
        _json_abort(403, f"You need the {role} role in {c['name']} for this.")
    return c


def _json_abort(code: int, message: str):
    resp = jsonify(error=message)
    resp.status_code = code
    abort(resp)


def row(cid: int) -> sqlite3.Row | None:
    return auth.db().execute("SELECT * FROM clients WHERE id = ?", (cid,)).fetchone()


# ------------------------------------------------------ key encryption
def _fernet():
    from cryptography.fernet import Fernet
    path = Path(os.environ.get("EXB_MASTER_KEY_FILE") or auth.data_dir() / "master_key")
    if not path.exists():
        if os.environ.get("EXB_MASTER_KEY_FILE"):
            raise RuntimeError(f"EXB_MASTER_KEY_FILE {path} does not exist")
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(base64.urlsafe_b64encode(secrets.token_bytes(32)))
        except FileExistsError:
            pass
    raw = path.read_bytes().strip()
    try:
        return Fernet(raw)
    except ValueError:  # any other secret: derive a Fernet key from it
        import hashlib
        return Fernet(base64.urlsafe_b64encode(hashlib.sha256(raw).digest()))


# kind -> (private key column, public key column, switch username column)
KEY_COLS = {"ro": ("ssh_key", "ssh_key_pub", "ssh_user"), "cfg": ("ssh_key_cfg", "ssh_key_cfg_pub", "ssh_user_cfg")}


def ssh_key_for(client_row, kind: str = "ro") -> object | None:
    """A client's key as a paramiko key (or None).

    ``ro``: the client's read-only key, else the server-wide key (EXB_SSH_KEY_FILE).
    ``cfg``: the client's config key only; the server-wide key is never used to push.
    """
    col = KEY_COLS[kind][0]
    if client_row[col]:
        return sshfetch.load_key(_fernet().decrypt(client_row[col].encode()).decode())
    return sshfetch.server_key() if kind == "ro" else None


def key_user_for(client_row, kind: str = "ro") -> str:
    """The switch username for a client's key (the server-wide key's user as a fallback for read-only)."""
    user = client_row[KEY_COLS[kind][2]] or ""
    return user or (sshfetch.key_user() if kind == "ro" else "")


def ssh_settings() -> dict:
    """What the builder page needs to know about SSH for the current client (never secrets)."""
    c = current()
    out = {"enabled": False, "allow": [], "key": False, "key_user": "", "client": c["name"] if c else "",
           "can_fetch": False, "can_password": False, "cfg_key": False, "cfg_user": "", "off": sshfetch.disabled()}
    if c is None:
        return out
    r = row(c["id"])
    nets, _ = sshfetch.check_networks(r["ssh_networks"])
    key = bool(r["ssh_key"]) or bool(sshfetch.key_file())
    admin = c["role"] == "admin"
    # Everyone in the client may fetch with the read-only key; only admins type passwords or see the config key.
    out.update(enabled=bool(nets) and not sshfetch.disabled(), allow=[str(n) for n in nets], key=key,
               key_user=key_user_for(r), can_fetch=admin or key, can_password=admin)
    if admin:
        out.update(cfg_key=bool(r["ssh_key_cfg"]), cfg_user=r["ssh_user_cfg"] or "")
    return out


# ------------------------------------------------------------ the switcher
@bp.post("/clients/select")
def select():
    try:
        cid = int(request.form.get("client_id", ""))
    except ValueError:
        abort(400)
    if role_in(cid) is None:
        abort(403)
    session["client_id"] = cid
    session["client_chosen"] = True
    back = request.form.get("next") or landing()
    if back.split("?")[0] == url_for("clients.start_page"):
        # Picked in the top bar while on the Production/Lab page: remember it, so the page
        # reloading itself doesn't forget the choice and send you to "Which client?" anyway.
        session["client_picked_on_start"] = True
    else:
        session.pop("client_picked_on_start", None)
    return redirect(auth._safe_next(back))


@bp.get("/start")
def start_page():
    """After sign-in (and Home in the top bar): Production or Lab, then the client again."""
    if not session.get("client_picked_on_start"):
        session.pop("client_chosen", None)
    return render_template("start.html", spaces=SPACES, space=session.get("space"))


@bp.post("/space")
def set_space():
    """Pick Production or Lab (the first step after sign-in, or the switch in the top bar)."""
    want = request.form.get("space", "")
    if want not in SPACES:
        abort(400)
    session["space"] = want
    session.pop("client_picked_on_start", None)  # used up: the next Home visit asks for the client again
    back = request.form.get("next")
    return redirect(auth._safe_next(back) if back else landing())


@bp.get("/clients/pick")
def pick_page():
    """After sign-in: pick the client to work on."""
    want = request.args.get("next") or ""
    next_url = want if want.startswith("/") and not want.startswith("//") and "\\" not in want else ""
    return render_template("pick_client.html", space=space(), spaces=SPACES, next_url=next_url,
                           server_admin=_is_server_admin())


def need_lab(role: str) -> dict:
    """Like need(), but only in the Lab space (EVE-NG is a lab tool)."""
    c = need(role)
    if c["space"] != "lab":
        _json_abort(409, "EVE-NG labs are in the Lab space. Switch to Lab at the top of the page.")
    return c


def landing() -> str:
    """Where you land once Production / Lab and the client are picked: the client's network on Global.

    It shows what the client already has at a glance (or how to start, for a new client). The vendor
    screen stays one click away (Vendors in the top bar).
    """
    return url_for("overview.global_page")


def start_redirect():
    """Where a signed-in user still has to go before the vendor screen, or None."""
    if session.get("space") not in SPACES:
        return redirect(url_for("clients.start_page"))
    mine = my_clients()
    if len(mine) > 1 and not session.get("client_chosen"):
        return redirect(url_for("clients.pick_page"))
    return None


# ------------------------------------------------------------ client pages
@bp.get("/clients")
def clients_page():
    mine = my_clients()
    counts = {}
    if mine:
        ids = [c["id"] for c in mine]
        q = ",".join("?" * len(ids))
        for what in ("projects", "maps", "client_members", "config_backups"):
            for cid, n in auth.db().execute(f"SELECT client_id, COUNT(*) FROM {what} WHERE client_id IN ({q}) "
                                            "GROUP BY client_id", ids):
                counts.setdefault(cid, {})[what] = n
    from . import samples
    return render_template("auth/clients.html", clients=mine, counts=counts, server_admin=_is_server_admin(),
                           sample_notes=samples.descriptions(),
                           samples_missing=samples.missing(auth.db()) if _is_server_admin() else [])


@bp.post("/clients/samples")
@auth.admin_required
def samples_add():
    """Add a sample client back (after it was deleted), or every missing one."""
    from . import samples
    want = request.form.get("key", "")
    todo = [s for s in samples.missing(auth.db()) if want in ("all", s["key"])]
    if not todo:
        flash("That sample client is already here.", "error")
        return redirect(url_for("clients.clients_page"))
    for s in todo:
        samples.add(auth.db(), s)
    auth.db().commit()
    g.pop("my_clients", None)
    log.warning("audit: %r added the sample client(s) %s", auth.current_user()["username"],
                ", ".join(repr(s["name"]) for s in todo))
    flash(f"Added {', '.join(s['name'] for s in todo)}. Everyone can open sample clients as Read-only.", "ok")
    return redirect(url_for("clients.clients_page"))


def create(name: str) -> tuple[int | None, str]:
    """Make a client. Returns (id, '') or (None, why not)."""
    if not NAME_RE.match(name):
        return None, "Client names are 1 to 80 characters, without < > quotes or backslashes."
    if auth.db().execute("SELECT 1 FROM clients WHERE name = ?", (name,)).fetchone():
        return None, f"A client called {name} already exists."
    cid = auth.db().execute("INSERT INTO clients (name, created_at) VALUES (?, ?)", (name, auth._now())).lastrowid
    auth.db().commit()
    g.pop("my_clients", None)
    log.warning("audit: %r created client %r", auth.current_user()["username"], name)
    return cid, ""


@bp.post("/clients")
@auth.admin_required
def clients_create():
    name = request.form.get("name", "").strip()
    from_pick = request.form.get("from") == "pick"
    cid, error = create(name)
    if error:
        flash(error, "error")
        return redirect(url_for("clients.pick_page") if from_pick else url_for("clients.clients_page"))
    if from_pick:
        # Made from the "Which client?" picker: that new client is the one you're working on now.
        session["client_id"] = cid
        session["client_chosen"] = True
    flash(f"Client {name} created. Add its people and switch networks below.", "ok")
    return redirect(url_for("clients.client_page", cid=cid))


def _client_admin(cid: int) -> sqlite3.Row:
    r = row(cid)
    if r is None:
        abort(404)
    if role_in(cid) != "admin":
        abort(403)
    return r


@bp.get("/clients/<int:cid>")
def client_page(cid: int):
    r = _client_admin(cid)
    members = auth.db().execute("SELECT u.id, u.username, u.active, m.role FROM client_members m JOIN users u "
                                "ON u.id = m.user_id WHERE m.client_id = ? ORDER BY u.username COLLATE NOCASE",
                                (cid,)).fetchall()
    nets, problems = sshfetch.check_networks(r["ssh_networks"])
    from . import eve
    n_backups = auth.db().execute("SELECT COUNT(*), COUNT(DISTINCT host) FROM config_backups WHERE client_id = ?",
                                  (cid,)).fetchone()
    everywhere = [dict(u, level="Super Admin" if u["role"] == "admin" else LABELS[u["all_clients"]])
                  for u in auth.db().execute("SELECT username, active, role, all_clients FROM users WHERE role = 'admin' "
                                             "OR all_clients IN ('viewer', 'editor', 'admin') ORDER BY username COLLATE NOCASE")]
    return render_template("auth/client.html", c=r, everywhere=everywhere, n_backups=n_backups, eve=eve.settings(r), members=members, roles=ROLES, server_admin=_is_server_admin(),
                           problems=problems, ceiling=[str(n) for n in sshfetch.ceiling()],
                           ssh_off=sshfetch.disabled(), server_key=bool(sshfetch.key_file()), key_setup=_key_setup(r),
                           known=sshfetch.known_hosts(client_folder(cid)))


def _key_setup(r) -> list[dict]:
    """Both key slots for the client page: label, public key and the switch commands for each vendor."""
    from .. import keysetup
    out = []
    for kind in keysetup.KINDS:
        _, pub_col, user_col = KEY_COLS[kind]
        pub = r[pub_col] or ""
        out.append({"kind": kind, "label": keysetup.LABELS[kind], "pub": pub,
                    "user": r[user_col] or keysetup.DEFAULT_USER[kind],
                    "commands": keysetup.commands(kind, r[user_col], pub) if pub else []})
    return out


@bp.post("/clients/<int:cid>")
def client_update(cid: int):
    r = _client_admin(cid)
    me = auth.current_user()["username"]
    action = request.form.get("action")
    db = auth.db()

    def audit(what: str) -> None:
        log.warning("audit: %r %s (client %r)", me, what, r["name"])

    if action == "rename" and _is_server_admin():
        name = request.form.get("name", "").strip()
        if not NAME_RE.match(name):
            flash("Client names are 1 to 80 characters, without < > quotes or backslashes.", "error")
        elif db.execute("SELECT 1 FROM clients WHERE name = ? AND id != ?", (name, cid)).fetchone():
            flash(f"A client called {name} already exists.", "error")
        else:
            db.execute("UPDATE clients SET name = ? WHERE id = ?", (name, cid))
            audit(f"renamed the client to {name!r}")
            flash(f"Renamed to {name}.", "ok")
    elif action == "delete" and _is_server_admin():
        if request.form.get("confirm", "").strip() != r["name"]:
            flash("Type the client's name exactly to delete it.", "error")
            return redirect(url_for("clients.client_page", cid=cid))
        tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        # Everything kept per client (newer features' tables too, some made only when first used),
        # so no settings, tokens or schedules of a deleted client stay behind. The audit log is kept.
        for table in ("projects", "maps", "client_members", "eve_labs", "eve_jobs", "config_backups", "project_reviews",
                      "config_pushes", "nightly_settings", "nightly_runs", "syslog_settings", "netbox_settings",
                      "global_layouts", "compliance_standards", "firmware_policy"):
            if table in tables:
                db.execute(f"DELETE FROM {table} WHERE client_id = ?", (cid,))
        db.execute("DELETE FROM clients WHERE id = ?", (cid,))
        db.commit()
        shutil.rmtree(client_folder(cid), ignore_errors=True)
        try:   # its switch logs (the syslog server keeps them in a database of its own)
            from . import logs
            logs.delete_client_logs(cid)
        except Exception:   # noqa: BLE001 - the client is gone either way; old logs expire with retention
            log.exception("could not delete the switch logs of client %s", cid)
        audit("deleted the client with its projects, maps and config backups")
        if r["sample"]:
            flash(f"Sample client {r['name']} deleted. It stays gone; add it back on this page any time.", "ok")
        else:
            flash(f"Client {r['name']} deleted.", "ok")
        return redirect(url_for("clients.clients_page"))
    elif action == "member_add":
        username = request.form.get("username", "").strip()
        role = request.form.get("role", "viewer")
        user = db.execute("SELECT id, role FROM users WHERE username = ?", (username,)).fetchone()
        if role not in ROLES:
            flash("Unknown role.", "error")
        elif user is None:
            flash(f"There is no user called {username}. A server admin adds users on the Users page first.", "error")
        else:
            db.execute("INSERT INTO client_members (client_id, user_id, role) VALUES (?, ?, ?) "
                       "ON CONFLICT (client_id, user_id) DO UPDATE SET role = excluded.role", (cid, user["id"], role))
            audit(f"added {username!r} as {role}")
            flash(f"{username} is now {role} in {r['name']}.", "ok")
    elif action in ("member_role", "member_remove"):
        try:
            uid = int(request.form.get("user_id", ""))
        except ValueError:
            abort(400)
        m = db.execute("SELECT u.username FROM client_members m JOIN users u ON u.id = m.user_id "
                       "WHERE m.client_id = ? AND m.user_id = ?", (cid, uid)).fetchone()
        if m is None:
            abort(404)
        if action == "member_remove":
            db.execute("DELETE FROM client_members WHERE client_id = ? AND user_id = ?", (cid, uid))
            audit(f"removed {m['username']!r}")
            flash(f"{m['username']} removed from {r['name']}.", "ok")
        else:
            role = request.form.get("role")
            if role not in ROLES:
                abort(400)
            db.execute("UPDATE client_members SET role = ? WHERE client_id = ? AND user_id = ?", (role, cid, uid))
            audit(f"made {m['username']!r} {role}")
            flash(f"{m['username']} is now {role}.", "ok")
    elif action == "ssh":
        text = request.form.get("networks", "")
        nets, problems = sshfetch.check_networks(text)
        user = request.form.get("ssh_user", "").strip()
        user_cfg = request.form.get("ssh_user_cfg", r["ssh_user_cfg"] or "").strip()
        if problems:
            for p in problems:
                flash(p, "error")
        elif any(u and not auth.USERNAME_RE.match(u) for u in (user, user_cfg)):
            flash("The switch username has characters that are not allowed.", "error")
        elif user and user == user_cfg:
            flash("Use two different switch usernames for the read-only and the config key.", "error")
        else:
            db.execute("UPDATE clients SET ssh_networks = ?, ssh_user = ?, ssh_user_cfg = ? WHERE id = ?",
                       (", ".join(map(str, nets)), user, user_cfg, cid))
            audit(f"set SSH networks to {', '.join(map(str, nets)) or 'none'}, read-only key user to {user!r} "
                  f"and config key user to {user_cfg!r}")
            flash("SSH settings saved." if nets else "SSH settings saved. SSH fetch is off for this client "
                  "until you add the switch networks.", "ok")
    elif action in ("key_generate", "key_delete"):
        kind = request.form.get("kind", "ro")
        if kind not in KEY_COLS:
            abort(400)
        priv_col, pub_col, _ = KEY_COLS[kind]
        label = "read-only" if kind == "ro" else "config"
        if action == "key_generate":
            slug = re.sub(r'[^A-Za-z0-9]+', '-', r['name']).strip('-')
            private, public = sshfetch.generate_key(f"switchbuilder-{kind}-{slug}")
            db.execute(f"UPDATE clients SET {priv_col} = ?, {pub_col} = ? WHERE id = ?",
                       (_fernet().encrypt(private.encode()).decode(), public, cid))
            del private
            audit(f"made a new {label} SSH key")
            flash(f"New {label} SSH key made. Add its public key to the {label} account on each switch "
                  "(the commands are below).", "ok")
        else:
            db.execute(f"UPDATE clients SET {priv_col} = NULL, {pub_col} = NULL WHERE id = ?", (cid,))
            audit(f"deleted the {label} SSH key")
            flash(f"{label.capitalize()} SSH key deleted.", "ok")
        db.commit()
        return redirect(url_for("clients.client_page", cid=cid) + "#ssh")
    elif action == "eve":
        from . import eve
        problems = eve.save_settings(cid, request.form)
        for p in problems:
            flash(p, "error")
        if not problems:
            audit(f"set EVE-NG to {request.form.get('eve_url', '').strip() or 'none'}")
            flash("EVE-NG settings saved.", "ok")
    elif action == "eve_test":
        from .. import eveng
        from . import eve
        try:
            flash(eve.test(dict(row(cid))), "ok")
        except eveng.EveError as exc:
            flash(str(exc), "error")
        return redirect(url_for("clients.client_page", cid=cid) + "#eve")
    elif action == "forget_host":
        host = request.form.get("host", "")
        if sshfetch.forget_host(client_folder(cid), host):
            audit(f"cleared the SSH host key of {host}")
            flash(f"Forgot the key of {host}. The next fetch remembers its new key.", "ok")
    else:
        abort(400)
    db.commit()
    return redirect(url_for("clients.client_page", cid=cid))


# ------------------------------------------------------------ saved maps
def _stamp() -> str:
    return auth._now()


@bp.get("/maps")
def maps_list():
    c = need("viewer")
    rows = auth.db().execute("SELECT id, name, updated_at, updated_by FROM maps WHERE client_id = ? AND space = ? "
                             "ORDER BY name COLLATE NOCASE", (c["id"], c["space"]))
    return {"maps": [dict(r) for r in rows], "client": c["name"], "can_edit": RANK[c["role"]] >= RANK["editor"]}


@bp.get("/maps/<int:mid>")
def maps_get(mid: int):
    c = need("viewer")
    r = auth.db().execute("SELECT * FROM maps WHERE id = ? AND client_id = ? AND space = ?",
                          (mid, c["id"], c["space"])).fetchone()
    if r is None:
        abort(404)
    data = json.loads(r["data"])
    if not can_see_secrets(c):
        data = redact.map_data(data)
    return {"id": r["id"], "name": r["name"], "data": data, "redacted": not can_see_secrets(c)}


@bp.post("/maps")
def maps_save():
    c = need("editor")
    body = request.get_json(silent=True) or {}
    name = str(body.get("name") or "").strip()[:100]
    data = body.get("data")
    if not name or not isinstance(data, dict):
        return {"error": "Give the map a name."}, 400
    text = json.dumps(data)
    if len(text) > MAX_MAP_BYTES:
        return {"error": "This map is too large to save."}, 400
    db = auth.db()
    db.execute("INSERT INTO maps (client_id, space, name, data, updated_at, updated_by) VALUES (?, ?, ?, ?, ?, ?) "
               "ON CONFLICT (client_id, space, name) DO UPDATE SET data = excluded.data, "
               "updated_at = excluded.updated_at, updated_by = excluded.updated_by",
               (c["id"], c["space"], name, text, _stamp(), auth.current_user()["username"]))
    db.commit()
    mid = db.execute("SELECT id FROM maps WHERE client_id = ? AND space = ? AND name = ?",
                     (c["id"], c["space"], name)).fetchone()[0]
    return {"id": mid, "name": name}


@bp.post("/maps/<int:mid>/delete")
def maps_delete(mid: int):
    c = need("editor")
    cur = auth.db().execute("DELETE FROM maps WHERE id = ? AND client_id = ? AND space = ?", (mid, c["id"], c["space"]))
    auth.db().commit()
    if cur.rowcount == 0:
        abort(404)
    return {"deleted": mid}


# ------------------------------------------------------------------ setup
def init_app(app) -> None:
    app.register_blueprint(bp)
    app.jinja_env.filters["role_label"] = lambda r: LABELS.get(r, r)

    @app.context_processor
    def inject_clients():
        if auth.current_user() is None:
            return {}
        return {"my_clients": my_clients(), "current_client": current(), "spaces": SPACES, "current_space": space()}
