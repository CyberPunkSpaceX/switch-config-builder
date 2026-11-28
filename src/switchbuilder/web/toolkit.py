"""The engineer's toolkit: tools that work across many switches at once.

``/tools`` lists them. Each tool has its own page under ``/tools/<name>``. Tools that read or save
projects use the client and space picked at the top of the page, like the builders do.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from flask import Blueprint, Response, abort, render_template, request

from .. import __version__, bulk, calc, compliance, firmware, neighbors, prepush, sshfetch, vendors
from . import auth, clients

bp = Blueprint("toolkit", __name__, url_prefix="/tools")
log = logging.getLogger("switchbuilder.toolkit")
MAX_PROJECT_BYTES = 512 * 1024

# (endpoint, icon, title, one line). Later tools add themselves here.
TOOLS = [
    ("toolkit.bulk_page", "&#9638;", "Bulk build",
     "One template project plus a spreadsheet of hostnames and IPs gives you a config for every switch at once."),
    ("toolkit.checks_page", "&#10003;", "Pre-push checks",
     "Check several projects together before they go live: duplicate IPs and VLANs, links whose ends disagree, "
     "VLANs no uplink carries, MTU and spanning-tree mismatches."),
    ("toolkit.map_page", "&#9741;", "Auto network map",
     "Draw the network from LLDP and CDP neighbours, for every brand. Paste the output, or let it log in over SSH "
     "and follow the neighbours from switch to switch."),
    ("toolkit.compliance_page", "&#9745;", "Compliance",
     "Score every switch against your own standard: NTP, syslog, SNMPv3, banner, no telnet or plain HTTP, BPDU "
     "guard and more. Checks projects and running-config backups."),
    ("toolkit.calc_page", "&#8721;", "Calculators",
     "Subnet calculator and splitter, a VLAN address plan you can add to a project, and a PoE power budget."),
    ("toolkit.firmware_page", "&#8635;", "Firmware tracker",
     "Which software every switch runs, from its latest backup, against your minimum, recommended and known-bad "
     "versions."),
    ("netbox.page", "&#8645;", "NetBox sync",
     "Pull a NetBox site's switches into projects, or push your projects' devices, VLANs and IPs to NetBox."),
    ("audit.page", "&#9776;", "Audit log & API",
     "Who changed what and when, with sign-ins, for admins. And the scripting API: projects, configs and backups "
     "over HTTPS with your API token."),
]


@bp.get("/")
def hub():
    return render_template("tools/index.html", tools=TOOLS, version=__version__)


# ------------------------------------------------------------------ bulk build
@bp.get("/bulk")
def bulk_page():
    return render_template("tools/bulk.html", version=__version__, client=clients.current(),
                           vendors={k: v.name for k, v in vendors.VENDORS.items()},
                           well_known=sorted(bulk.WELL_KNOWN), max_rows=bulk.MAX_ROWS)


def _body() -> dict:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        abort(400, "Send a JSON object.")
    return data


def _template(body: dict) -> dict:
    """The template project: a saved project of the current client and space, or one sent as JSON."""
    pid = body.get("project_id")
    if pid not in (None, ""):
        c = clients.need("viewer")
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            abort(400, "Pick a saved project.")
        row = auth.db().execute("SELECT data FROM projects WHERE id = ? AND client_id = ? AND space = ?",
                                (pid, c["id"], c["space"])).fetchone()
        if row is None:
            abort(400, "That project is not in this client and space.")
        data = json.loads(row["data"])
        if not clients.can_see_secrets(c):
            # Read-only people may build from a saved project, but never see its passwords or communities.
            from .. import redact
            data = redact.project(data)
        return data
    tpl = body.get("template")
    if isinstance(tpl, str):
        try:
            tpl = json.loads(tpl)
        except ValueError:
            abort(400, "The template is not valid project JSON.")
    if not isinstance(tpl, dict):
        abort(400, "Pick a template project first.")
    if len(json.dumps(tpl)) > MAX_PROJECT_BYTES:
        abort(400, "The template is too large.")
    return tpl


def _run(body: dict) -> dict:
    try:
        return bulk.run(_template(body), str(body.get("csv") or ""))
    except bulk.BulkError as exc:
        abort(400, str(exc))


@bp.post("/bulk/run")
def bulk_run():
    result = _run(_body())
    log.info("audit: %s bulk-built %d switches (%d ok)", auth.current_user()["username"],
             result["summary"]["total"], result["summary"]["ok"])
    return result


@bp.post("/bulk/zip")
def bulk_zip():
    result = _run(_body())
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    return Response(bulk.to_zip(result), mimetype="application/zip",
                    headers={"Content-Disposition": f"attachment; filename=bulk-build-{stamp}.zip"})


@bp.post("/bulk/csv-template")
def bulk_csv_template():
    text = bulk.csv_template(_template(_body()))
    return Response(text, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=bulk-build-switches.csv"})


@bp.post("/bulk/save")
def bulk_save():
    """Save every switch that built as its own project in the current client and space."""
    body = _body()
    c = clients.need("editor")
    result = _run(body)
    good = [s for s in result["switches"] if s["ok"]]
    if not good:
        return {"error": "None of the switches built, so nothing was saved."}, 400
    db = auth.db()
    names = [s["hostname"][:100] for s in good]
    q = ",".join("?" * len(names))
    taken = [r[0] for r in db.execute(f"SELECT name FROM projects WHERE client_id = ? AND space = ? AND name IN ({q})",
                                      (c["id"], c["space"], *names))]
    if taken and not body.get("overwrite"):
        return {"error": f"{len(taken)} of these names are already projects here: {', '.join(taken[:10])}"
                         f"{'…' if len(taken) > 10 else ''}. Tick “Replace projects with the same name” to update them.",
                "exists": taken}, 409
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    user = auth.current_user()["username"]
    for s, name in zip(good, names):
        text = json.dumps(s["project"])
        if len(text) > MAX_PROJECT_BYTES:
            continue
        db.execute("INSERT INTO projects (client_id, space, name, data, updated_at, updated_by) VALUES (?, ?, ?, ?, ?, ?) "
                   "ON CONFLICT (client_id, space, name) DO UPDATE SET data = excluded.data, "
                   "updated_at = excluded.updated_at, updated_by = excluded.updated_by",
                   (c["id"], c["space"], name, text, now, user))
    db.commit()
    log.info("audit: %s saved %d bulk-built projects to %s (%s)", user, len(good), c["name"], c["space"])
    return {"saved": len(good), "client": c["name"], "space": c["space"], "skipped": len(result["switches"]) - len(good)}


# ------------------------------------------------------------ pre-push checks
@bp.get("/checks")
def checks_page():
    return render_template("tools/checks.html", version=__version__, client=clients.current(),
                           vendors={k: v.name for k, v in vendors.VENDORS.items()})


@bp.post("/checks/run")
def checks_run():
    """Check saved projects (project_ids, current client and space) or projects sent as JSON."""
    body = _body()
    projects = []
    ids = body.get("project_ids")
    if ids:
        c = clients.need("viewer")
        try:
            ids = [int(x) for x in ids][:prepush.MAX_SWITCHES]
        except (TypeError, ValueError):
            abort(400, "Pick saved projects.")
        q = ",".join("?" * len(ids))
        rows = auth.db().execute(f"SELECT id, name, data FROM projects WHERE client_id = ? AND space = ? AND id IN ({q})",
                                 (c["id"], c["space"], *ids)).fetchall()
        order = {pid: i for i, pid in enumerate(ids)}
        projects = [{"name": r["name"], "data": json.loads(r["data"])} for r in sorted(rows, key=lambda r: order[r["id"]])]
    elif isinstance(body.get("projects"), list):
        projects = [p for p in body["projects"] if isinstance(p, dict) and isinstance(p.get("data"), dict)]
        if len(json.dumps(projects)) > 20 * MAX_PROJECT_BYTES:
            abort(400, "Those projects are too large together.")
    if len(projects) < 1:
        abort(400, "Pick the projects to check.")
    links = [x for x in body.get("links") or [] if isinstance(x, dict)][:200]
    return prepush.check(projects, links)


# ------------------------------------------------------------ auto network map
@bp.get("/map")
def map_page():
    c = clients.current()
    ssh = False
    if c and clients.RANK[c["role"]] >= clients.RANK["admin"]:
        nets, _ = sshfetch.check_networks(clients.row(c["id"])["ssh_networks"])
        ssh = bool(nets) and not sshfetch.disabled()
    return render_template("tools/map.html", version=__version__, client=c, ssh=ssh, commands=neighbors.COMMANDS,
                           max_hosts=sshfetch.MAX_HOSTS)


@bp.post("/map/build")
def map_build():
    body = _body()
    items = [x for x in body.get("switches") or [] if isinstance(x, dict)][:neighbors.MAX_SWITCHES]
    if not items:
        abort(400, "Add the neighbour output of at least one switch.")
    if sum(len(str(x.get("text") or "")) for x in items) > 20_000_000:
        abort(400, "That output is too large together (20 MB at most).")
    return neighbors.build_map(items)


@bp.post("/map/discover")
def map_discover():
    """Log in to the seed switches over SSH and follow their neighbours (client admins, like SSH fetch)."""
    body = _body()
    c = clients.need("admin")
    row = clients.row(c["id"])
    nets, _ = sshfetch.check_networks(row["ssh_networks"])
    if sshfetch.disabled() or not nets:
        return {"error": f"SSH is off for {c['name']}. A client admin adds the switch networks on the client page."}, 403
    seeds = body.get("seeds") or []
    if isinstance(seeds, str):
        seeds = seeds.replace(",", "\n").split("\n")
    seeds = [str(h).strip() for h in seeds if str(h).strip()][:sshfetch.MAX_HOSTS]
    if not seeds:
        return {"error": "Enter at least one switch address to start from."}, 400
    username = str(body.get("username") or "").strip()
    password = str(body.get("password") or "")
    pkey = None
    if body.get("use_key"):
        pkey = clients.ssh_key_for(row, "ro")
        if pkey is None:
            return {"error": "This client has no read-only SSH key yet. A client admin makes one on the client page."}, 400
        username = username or clients.key_user_for(row, "ro")
        password = ""
    elif not (username and password):
        return {"error": "Enter the switch username and password, or sign in with the SSH key."}, 400
    try:
        port = int(body.get("port") or 22)
        limit = int(body.get("limit") or sshfetch.MAX_HOSTS)
        if not 1 <= port <= 65535:
            raise ValueError
    except (TypeError, ValueError):
        return {"error": "SSH port must be 1-65535."}, 400
    me = auth.current_user()["username"]
    try:
        sshfetch.check_rate(me)
    except sshfetch.FetchError as exc:
        return {"error": str(exc)}, 429
    out = neighbors.discover(seeds, username, password, clients.client_folder(c["id"]), nets, port, pkey,
                             limit=limit, follow=bool(body.get("follow", True)))
    del password
    for r in out["fetched"]:
        sshfetch.log.warning("audit: neighbour discovery by %r for client %r: %s as %r -> %s", me, c["name"], r["host"],
                             username, "ok" if r["ok"] else r["error"] or "failed")
    return out


# ------------------------------------------------------------------ compliance
COMPLIANCE_SCHEMA = """
CREATE TABLE IF NOT EXISTS compliance_standards (
    client_id INTEGER PRIMARY KEY,
    data TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL
);
"""


def _standard(cid: int) -> tuple[dict, str]:
    db = auth.db()
    db.executescript(COMPLIANCE_SCHEMA)
    r = db.execute("SELECT data, updated_at, updated_by FROM compliance_standards WHERE client_id = ?", (cid,)).fetchone()
    if r is None:
        return compliance.default_standard(), ""
    return compliance.clean_standard(json.loads(r["data"])), f"{r['updated_at']} by {r['updated_by']}"


@bp.get("/compliance")
def compliance_page():
    c = clients.current()
    std, updated = _standard(c["id"]) if c else (compliance.default_standard(), "")
    return render_template("tools/compliance.html", version=__version__, client=c, std=std, updated=updated,
                           rules=compliance.RULES, can_edit=bool(c) and c["role"] == "admin",
                           vendors={k: v.name for k, v in vendors.VENDORS.items()})


@bp.post("/compliance/standard")
def compliance_save():
    c = clients.need("admin")
    std = compliance.clean_standard(_body())
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    db = auth.db()
    db.executescript(COMPLIANCE_SCHEMA)
    db.execute("INSERT INTO compliance_standards (client_id, data, updated_at, updated_by) VALUES (?, ?, ?, ?) "
               "ON CONFLICT (client_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at, "
               "updated_by = excluded.updated_by", (c["id"], json.dumps(std), now, auth.current_user()["username"]))
    db.commit()
    log.info("audit: %s changed the compliance standard of client %r", auth.current_user()["username"], c["name"])
    return {"ok": True, "standard": std}


@bp.post("/compliance/run")
def compliance_run():
    """Score saved projects (project_ids), config backups (backup_ids) and pasted configs against the client's standard."""
    body = _body()
    c = clients.need("viewer")
    std, _ = _standard(c["id"])
    db = auth.db()
    targets = []

    def ids(key):
        return [int(x) for x in body.get(key) or [] if str(x).isdigit()][:200]

    for pid in ids("project_ids"):
        r = db.execute("SELECT name, data FROM projects WHERE id = ? AND client_id = ? AND space = ?",
                       (pid, c["id"], c["space"])).fetchone()
        if r:
            data = json.loads(r["data"])
            targets.append(compliance.Target(f"{r['name']} (project)", vendors.get(data.get("vendor")).key, data))
    for bid in ids("backup_ids"):
        r = db.execute("SELECT host, text, created_at FROM config_backups WHERE id = ? AND client_id = ? AND space = ?",
                       (bid, c["id"], c["space"])).fetchone()
        if r:
            targets.append(compliance.from_config(f"{r['host']} (backup {r['created_at']})", r["text"]))
    for item in (body.get("configs") or [])[:50]:
        if isinstance(item, dict) and str(item.get("text") or "").strip():
            text = str(item["text"])[:2_000_000]
            vendor = str(item.get("vendor") or "")
            targets.append(compliance.from_config(str(item.get("name") or "pasted config")[:80], text,
                                                  vendor if vendors.known(vendor) else ""))
    if not targets:
        abort(400, "Pick projects or backups, or paste a config.")
    out = compliance.run(targets, std)
    out["names"] = {k: v.name for k, v in vendors.VENDORS.items()}
    return out


# ----------------------------------------------------------------- calculators
@bp.get("/calc")
def calc_page():
    return render_template("tools/calc.html", version=__version__, client=clients.current(),
                           poe_devices=calc.POE_DEVICES, poe_classes=calc.POE_CLASSES)


def _calc(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except calc.CalcError as exc:
        abort(400, str(exc))


def _int(v):
    try:
        return int(v) if v is not None and str(v).strip() else None
    except (TypeError, ValueError):
        abort(400, "Use whole numbers.")


@bp.post("/calc/subnet")
def calc_subnet():
    return _calc(calc.subnet, str(_body().get("address") or ""))


@bp.post("/calc/split")
def calc_split():
    b = _body()
    return _calc(calc.split, str(b.get("network") or ""), _int(b.get("prefix")), _int(b.get("count")), _int(b.get("hosts")))


@bp.post("/calc/vlans")
def calc_vlans():
    b = _body()
    rows = [r for r in b.get("vlans") or [] if isinstance(r, dict)]
    return _calc(calc.vlan_plan, str(b.get("supernet") or ""), rows, str(b.get("gateway") or "first"),
                 _int(b.get("spare")) or 0)


@bp.post("/calc/vlans/apply")
def calc_vlans_apply():
    """Add the planned VLANs (name, ID, VLAN interface address) to a saved project of the current client and space."""
    b = _body()
    c = clients.need("editor")
    pid = _int(b.get("project_id"))
    db = auth.db()
    row = db.execute("SELECT name, data FROM projects WHERE id = ? AND client_id = ? AND space = ?",
                     (pid, c["id"], c["space"])).fetchone()
    if row is None:
        abort(400, "Pick a saved project.")
    data = json.loads(row["data"])
    have = data.setdefault("vlans", [])
    ids = {str(v.get("id")) for v in have if isinstance(v, dict)}
    names = {str(v.get("name", "")).lower() for v in have if isinstance(v, dict)}
    added, skipped = [], []
    for v in [x for x in b.get("vlans") or [] if isinstance(x, dict)][:calc.MAX_VLANS]:
        name, vid, irb = str(v.get("name") or ""), str(v.get("id") or ""), str(v.get("irb") or "")
        if vid in ids or name.lower() in names:
            skipped.append(f"{vid} {name}")
            continue
        row_ = {"name": name, "id": vid}
        if irb and b.get("with_irb", True):
            row_["irb"] = irb
        have.append(row_)
        ids.add(vid)
        names.add(name.lower())
        added.append(f"{vid} {name}")
    text = json.dumps(data)
    if len(text) > MAX_PROJECT_BYTES:
        abort(400, "The project would be too large.")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    db.execute("UPDATE projects SET data = ?, updated_at = ?, updated_by = ? WHERE id = ?",
               (text, now, auth.current_user()["username"], pid))
    db.commit()
    return {"project": row["name"], "added": added, "skipped": skipped}


@bp.post("/calc/poe")
def calc_poe():
    b = _body()
    rows = [r for r in b.get("devices") or [] if isinstance(r, dict)]
    return _calc(calc.poe_budget, b.get("budget"), rows, "actual" if b.get("reserve") == "actual" else "class")


# ------------------------------------------------------------ firmware tracker
FIRMWARE_SCHEMA = """
CREATE TABLE IF NOT EXISTS firmware_policy (
    client_id INTEGER PRIMARY KEY,
    data TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL
);
"""


def _fw_policy(cid: int) -> tuple[dict, str]:
    db = auth.db()
    db.executescript(FIRMWARE_SCHEMA)
    r = db.execute("SELECT data, updated_at, updated_by FROM firmware_policy WHERE client_id = ?", (cid,)).fetchone()
    if r is None:
        return {"rows": []}, ""
    return firmware.clean_policy(json.loads(r["data"])), f"{r['updated_at']} by {r['updated_by']}"


@bp.get("/firmware")
def firmware_page():
    c = clients.current()
    policy, updated = _fw_policy(c["id"]) if c else ({"rows": []}, "")
    return render_template("tools/firmware.html", version=__version__, client=c, policy=policy, updated=updated,
                           can_edit=bool(c) and c["role"] == "admin",
                           vendors={k: v.name for k, v in vendors.VENDORS.items()})


@bp.post("/firmware/policy")
def firmware_policy_save():
    c = clients.need("admin")
    policy = firmware.clean_policy(_body())
    unknown = [r["vendor"] for r in policy["rows"] if not vendors.known(r["vendor"])]
    if unknown:
        abort(400, f"Unknown brand: {', '.join(unknown)}.")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    db = auth.db()
    db.executescript(FIRMWARE_SCHEMA)
    db.execute("INSERT INTO firmware_policy (client_id, data, updated_at, updated_by) VALUES (?, ?, ?, ?) "
               "ON CONFLICT (client_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at, "
               "updated_by = excluded.updated_by", (c["id"], json.dumps(policy), now, auth.current_user()["username"]))
    db.commit()
    log.info("audit: %s changed the firmware policy of client %r", auth.current_user()["username"], c["name"])
    return {"ok": True, "policy": policy}


@bp.post("/firmware/run")
def firmware_run():
    """The latest backup of every switch in the current client and space, plus pasted show-version output."""
    body = _body()
    c = clients.need("viewer")
    policy, _ = _fw_policy(c["id"])
    rows = auth.db().execute(
        "SELECT b.host, b.text, b.created_at FROM config_backups b JOIN (SELECT host, MAX(id) AS id FROM config_backups "
        "WHERE client_id = ? AND space = ? GROUP BY host) last ON last.id = b.id ORDER BY b.host COLLATE NOCASE",
        (c["id"], c["space"])).fetchall()
    items = [{"name": r["host"], "text": r["text"], "when": r["created_at"]} for r in rows]
    for p in (body.get("pasted") or [])[:50]:
        if isinstance(p, dict) and str(p.get("text") or "").strip():
            items.append({"name": str(p.get("name") or "pasted")[:80], "text": str(p["text"])[:2_000_000], "when": "pasted"})
    out = firmware.report(items, policy)
    out["names"] = {k: v.name for k, v in vendors.VENDORS.items()}
    return out


def init_app(app) -> None:
    app.register_blueprint(bp)
