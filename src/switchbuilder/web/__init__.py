"""Web GUI for Multi-Vendor Switch Config Builder.

The page is a single-page form. Every change is sent to ``/generate`` as JSON
and the config comes back; nothing is stored unless the user saves the
project. Saved projects and network maps belong to a client (see clients.py)
and live in the same SQLite database as the users.

Settings (environment variables):

* ``EXB_DATA_DIR``: where users, projects and the session key are stored (default /data).
* ``EXB_USERNAME`` / ``EXB_PASSWORD`` (or ``EXB_PASSWORD_FILE``): the first
  admin, created on first start when there are no users. Without them the
  first sign-in is admin / admin with a forced password change. See auth.py.
* ``EXB_SECURE_COOKIES``: set to true once the UI is served over HTTPS.
* ``EXB_REQUIRE_2FA``: make two-factor sign-in compulsory.
* ``EXB_REQUIRE_2FA_ADMINS``: server admins must use it (default true).
"""

from __future__ import annotations

import copy
import json
import zoneinfo
from pathlib import Path
from datetime import datetime, timezone

from flask import Flask, Response, abort, flash, redirect, render_template, request, session, url_for

from .. import __version__, redact, evelab, aoscx_models, aoss_models, eos_models, exos_models, fabric, fastiron_models, fortiswitch_models, ios_models, nxos_models, os10_models, routeros_models, unifi_models, importer, models, sshfetch, topology, vendors, xlsx
from ..generator import DEFAULTS, build
from . import audit, auth, backups, clients, converter, eve, logs, netboxsync, nightly, promote, push, saml, sso, toolkit

MAX_PROJECT_BYTES = 512 * 1024


def _timezones() -> list[str]:
    try:
        zones = zoneinfo.available_timezones()
    except Exception:  # noqa: BLE001 - no tz database: offer UTC only
        zones = set()
    return ["UTC", *sorted(z for z in zones if "/" in z and not z.startswith(("Etc/", "SystemV/", "posix/", "right/")))]


def _project_from_request() -> dict:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        abort(400, "Send the project as a JSON object.")
    return data


_VENDOR_MODELS = {"arista": eos_models, "cisco": ios_models, "ruckus": fastiron_models, "aruba": aoscx_models, "procurve": aoss_models,
                  "nexus": nxos_models, "dell": os10_models,
                  "extreme": exos_models, "fortiswitch": fortiswitch_models, "mikrotik": routeros_models, "unifi": unifi_models}


def _catalog(vendor: str) -> list[dict]:
    return (_VENDOR_MODELS.get(vendor) or models).catalog()


def _aliases(vendor: str) -> dict:
    mod = _VENDOR_MODELS.get(vendor)
    return mod.ALIASES if mod else {}


def _defaults(vendor: str) -> dict:
    """The blank project for a vendor's builder."""
    d = copy.deepcopy(DEFAULTS)
    d["vendor"] = vendor
    if vendor == "arista":
        d["switch"]["members"] = [{"fpc": 0, "model": "720XP-48Y6", "serial": "", "role": "routing-engine"}]
        d["system"]["mgmt_interface"] = ""
    elif vendor == "cisco":
        d["switch"]["members"] = [{"fpc": 1, "model": "C9300-48P", "serial": "", "role": "routing-engine"}]
    elif vendor == "fortiswitch":
        d["switch"]["members"] = [{"fpc": 1, "model": "FS-448E-FPOE", "serial": "", "role": "routing-engine"}]
        d["system"]["mgmt_interface"] = ""
    elif vendor == "unifi":
        d["switch"]["members"] = [{"fpc": 1, "model": "USW-Pro-24-PoE", "serial": "", "role": "routing-engine"}]
        d["system"]["mgmt_interface"] = ""
    elif vendor == "mikrotik":
        d["switch"]["members"] = [{"fpc": 1, "model": "CRS328-24P-4S+", "serial": "", "role": "routing-engine"}]
        d["system"]["mgmt_interface"] = ""
    elif vendor == "extreme":
        d["switch"]["members"] = [{"fpc": 1, "model": "X440-G2-48p-10GE4", "serial": "", "role": "routing-engine"}]
        d["system"]["mgmt_interface"] = ""
    elif vendor == "dell":
        d["switch"]["members"] = [{"fpc": 1, "model": "N3248TE-ON", "serial": "", "role": "routing-engine"}]
        d["system"]["mgmt_interface"] = ""
    elif vendor == "nexus":
        d["switch"]["members"] = [{"fpc": 1, "model": "N9K-C93180YC-FX", "serial": "", "role": "routing-engine"}]
        d["system"]["mgmt_interface"] = ""
        d["system"]["mgmt_vrf"] = True
    elif vendor == "procurve":
        d["switch"]["members"] = [{"fpc": 1, "model": "2930F-48G-PoE+-4SFP+", "serial": "", "role": "routing-engine"}]
    elif vendor == "aruba":
        d["switch"]["members"] = [{"fpc": 1, "model": "6300M-48G-CL4-4SFP56", "serial": "", "role": "routing-engine"}]
        d["system"]["mgmt_vrf"] = True
    elif vendor == "ruckus":
        d["switch"]["members"] = [{"fpc": 1, "model": "ICX7150-48P", "serial": "", "role": "routing-engine"}]
    return d


_EXAMPLES = Path(__file__).resolve().parent.parent / "vendor_examples"


def _examples(vendor: str) -> dict:
    """Example projects for vendors other than Juniper (Juniper's are in the page)."""
    out = {}
    for f in sorted(_EXAMPLES.glob(f"{vendor}-*.json")):
        try:
            out[f.stem[len(vendor) + 1:]] = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
    return out


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

    @app.before_request
    def _bigger_uploads_for_the_map():
        # Many switch configs at once: allow more than the usual 2 MB.
        if request.path in ("/map", "/map/unzip", "/maps", "/backups", "/backups/upload", "/clients/restore") or (
                request.path.startswith("/clients/") and request.path.endswith("/import")):
            request.max_content_length = 25 * 1024 * 1024
    auth.init_app(app)
    sso.init_app(app)
    saml.init_app(app)
    clients.init_app(app)
    eve.init_app(app)
    backups.init_app(app)
    promote.init_app(app)
    push.init_app(app)
    converter.init_app(app)
    nightly.init_app(app)
    logs.init_app(app)
    toolkit.init_app(app)
    netboxsync.init_app(app)
    audit.init_app(app)
    zones = _timezones()

    @app.after_request
    def headers(resp: Response) -> Response:
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        return resp

    from . import overview   # Global: the client's switches on one page, and each switch's history
    overview.init_app(app)

    @app.get("/")
    def index():
        """The vendor screen, once Production / Lab and the client are picked."""
        if (step := clients.start_redirect()) is not None:
            return step
        here, elsewhere = _project_counts()
        return render_template("vendors.html", vendors=vendors.VENDORS.values(), version=__version__,
                               last=session.get("vendor"), here=here, elsewhere=elsewhere)

    def _project_counts() -> tuple[dict, dict]:
        """Saved projects per vendor for the current client: in this space, and in the other one."""
        c = clients.current()
        here, elsewhere = {}, {}
        if c is None:
            return here, elsewhere
        for row in auth.db().execute("SELECT space, data FROM projects WHERE client_id = ?", (c["id"],)):
            try:
                key = vendors.get(json.loads(row["data"]).get("vendor")).key
            except (TypeError, ValueError, AttributeError):
                key = vendors.DEFAULT
            into = here if row["space"] == c["space"] else elsewhere.setdefault(row["space"], {})
            into[key] = into.get(key, 0) + 1
        return here, elsewhere

    @app.get("/help")
    def help_page():
        """The built-in how-to guide."""
        return render_template("help.html", version=__version__)

    @app.get("/build")
    def build_default():
        return redirect(url_for("builder", vendor=vendors.DEFAULT))

    @app.get("/build/<vendor>")
    def builder(vendor: str):
        v = vendors.VENDORS.get(vendor.lower())
        if v is None:
            abort(404)
        if not v.ready:
            flash(f"The {v.name} builder is not ready yet. It is coming in a later update.", "info")
            return redirect(url_for("index"))
        session["vendor"] = v.key
        return render_template("builder.html", vendor=v.to_dict(), version=__version__, catalog=_catalog(v.key),
                               defaults=_defaults(v.key), port_aliases=_aliases(v.key), examples=_examples(v.key), timezones=zones, fabric_templates=fabric.TEMPLATES,
                               fabric_flavors=fabric.FLAVORS, fabric_defaults=fabric.DEFAULTS,
                               ssh=clients.ssh_settings(), client=clients.current(),
                               eve=eve.page_settings(), eve_lab=evelab.catalog().get(v.key),
                               eve_labs_all=evelab.catalog())

    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "version": __version__}

    @app.post("/generate")
    def generate():
        return build(_project_from_request()).to_dict()

    # ------------------------------------------------------- fabric wizard
    def _fabric_result() -> dict:
        body = _project_from_request()
        spec, base = body.get("fabric"), body.get("base") or {}
        if not isinstance(spec, dict) or not isinstance(base, dict):
            abort(400, "Send {fabric: {...}, base: {...}}.")
        return fabric.generate(spec, base)

    @app.post("/fabric")
    def fabric_generate():
        result = _fabric_result()
        return (result, 400) if "error" in result else result

    @app.post("/fabric/zip")
    def fabric_zip():
        result = _fabric_result()
        if "error" in result:
            return result, 400
        return Response(fabric.to_zip(result), mimetype="application/zip",
                        headers={"Content-Disposition": "attachment; filename=fabric-configs.zip"})

    # ------------------------------------------------- import and Excel
    @app.post("/import/config")
    def import_config():
        body = _project_from_request()
        text = str(body.get("text") or "")
        if len(text) > 1_500_000:
            return {"error": "That config is too large."}, 400
        chosen = str(body.get("model") or "")
        if chosen and not models.get(chosen):
            chosen = ""
        detected = importer.detect_models(text)
        result = importer.check(text, chosen, detected["members"])
        if "error" in result:
            return result, 400
        first = detected["members"].get(0, {})
        result["model"] = chosen or first.get("model", "")
        result["model_how"] = "chosen" if chosen else first.get("how", "")
        result["detected"] = [{"fpc": f, **d} for f, d in sorted(detected["members"].items())]
        result["unknown_models"] = detected["unknown"]
        return result

    # ------------------------------------------------------ network map
    @app.post("/map")
    def network_map():
        body = _project_from_request()
        items = [x for x in body.get("switches") or [] if isinstance(x, dict)]
        if not items:
            return {"error": "Add at least one switch config."}, 400
        if sum(len(str(x.get("text") or "")) + len(str(x.get("lldp") or "")) for x in items) > 20_000_000:
            return {"error": "Those configs are too large together (20 MB at most)."}, 400
        return topology.analyze(items)

    @app.get("/map/example")
    def network_map_example():
        from importlib import resources
        folder = resources.files("switchbuilder") / "map_examples"
        files = sorted((f for f in folder.iterdir() if f.name.endswith(".conf")), key=lambda f: f.name)
        files.sort(key=lambda f: not f.name.startswith("core"))
        return {"files": [{"name": f.name[:-5], "text": f.read_text()} for f in files]}

    # -------------------------------------------- fetch configs over SSH
    @app.post("/ssh/fetch")
    def ssh_fetch():
        body = _project_from_request()
        c = clients.need("viewer")
        admin = c["role"] == "admin"
        row = clients.row(c["id"])
        nets, _ = sshfetch.check_networks(row["ssh_networks"])
        if not admin and not body.get("use_key"):
            return {"error": f"Only admins of {c['name']} sign in to switches with a password. You can fetch with "
                             "the client's read-only SSH key."}, 403
        if sshfetch.disabled() or not nets:
            return {"error": f"SSH fetch is off for {c['name']}. A client admin adds the switch networks on "
                             "the client page."}, 403
        hosts = body.get("hosts") or []
        if isinstance(hosts, str):
            hosts = hosts.replace(",", "\n").split("\n")
        hosts = [str(h).strip() for h in hosts if str(h).strip()]
        if not hosts:
            return {"error": "Enter at least one switch address."}, 400
        if len(hosts) > sshfetch.MAX_HOSTS:
            return {"error": f"At most {sshfetch.MAX_HOSTS} switches at a time."}, 400
        use_key = bool(body.get("use_key"))
        username = str(body.get("username") or "").strip()
        password = str(body.get("password") or "")
        pkey = None
        if use_key:
            pkey = clients.ssh_key_for(row, "ro")   # fetching only ever uses the read-only key
            if pkey is None:
                return {"error": "This client has no read-only SSH key yet. A client admin makes one on the client "
                                 "page."}, 400
            # Only admins may point the key at another switch account.
            username = (username if admin else "") or clients.key_user_for(row, "ro")
            if not username:
                return {"error": "Enter the switch username for the key."}, 400
            password = ""
        elif not (username and password):
            return {"error": "Enter the switch username and password, or sign in with the SSH key."}, 400
        try:
            port = int(body.get("port") or 22)
            if not 1 <= port <= 65535:
                raise ValueError
        except (TypeError, ValueError):
            return {"error": "SSH port must be 1-65535."}, 400
        me = auth.current_user()["username"]
        try:
            sshfetch.check_rate(me)
        except sshfetch.FetchError as exc:
            return {"error": str(exc)}, 429
        results = sshfetch.fetch(hosts, username, password, clients.client_folder(c["id"]), me, port,
                                 nets=nets, pkey=pkey, client=c["name"])
        del password
        # Every config fetched is kept as a backup of the client (unchanged ones only once).
        ok = [r for r in results if r["ok"]]
        if ok:
            saved = backups.store(auth.db(), c["id"], [{"name": r["host"], "address": r["host"], "text": r["text"]}
                                                       for r in ok], "ssh", me, space=c["space"])
            for r, s in zip(ok, saved):
                r["backup"] = s
        return {"results": results}

    @app.get("/ssh/known")
    def ssh_known():
        c = clients.need("admin")
        return {"hosts": sshfetch.known_hosts(clients.client_folder(c["id"]))}

    @app.post("/ssh/forget")
    def ssh_forget():
        c = clients.need("admin")
        host = str(_project_from_request().get("host") or "")
        if not sshfetch.forget_host(clients.client_folder(c["id"]), host):
            return {"error": "Not a known switch."}, 404
        sshfetch.log.warning("audit: %r cleared the SSH host key of %s (client %r)",
                             auth.current_user()["username"], host, c["name"])
        return {"ok": True}

    @app.post("/map/unzip")
    def network_map_unzip():
        """A zip of configs -> [{name, text}] so the page can list them."""
        import io
        import zipfile
        f = request.files.get("file")
        if f is None:
            return {"error": "Choose a .zip file."}, 400
        try:
            zf = zipfile.ZipFile(io.BytesIO(f.read()))
        except zipfile.BadZipFile:
            return {"error": "That is not a zip file."}, 400
        out, total = [], 0
        for info in zf.infolist():
            name = info.filename.rsplit("/", 1)[-1]
            if info.is_dir() or not name or name.startswith(".") or info.file_size > 2_000_000:
                continue
            total += info.file_size
            if total > 20_000_000 or len(out) >= topology.MAX_SWITCHES:
                break
            text = zf.read(info).decode("utf-8", "replace")
            if importer.to_set_lines(text):
                out.append({"name": name.rsplit(".", 1)[0], "text": text})
        if not out:
            return {"error": "No switch configs found in that zip."}, 400
        return {"files": out}

    def _xlsx_response(data: bytes, name: str) -> Response:
        return Response(data, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        headers={"Content-Disposition": f"attachment; filename={name}"})

    @app.get("/excel/template")
    def excel_template():
        return _xlsx_response(xlsx.workbook(), "ex-switch-template.xlsx")

    @app.post("/excel/export")
    def excel_export():
        project = _project_from_request()
        name = "".join(c if c.isalnum() or c in "-_." else "-" for c in
                       str((project.get("system") or {}).get("hostname") or "ex-switch"))[:60] or "ex-switch"
        return _xlsx_response(xlsx.workbook(project), f"{name}.xlsx")

    @app.post("/import/excel")
    def import_excel():
        f = request.files.get("file")
        if f is None:
            return {"error": "Choose an Excel file (.xlsx)."}, 400
        try:
            project = xlsx.read(f.read())
        except xlsx.WorkbookError as exc:
            return {"error": str(exc)}, 400
        built = build(project)
        return {"project": project, "errors": built.errors, "warnings": built.warnings,
                "recommendations": importer.recommendations(project, [], [])}

    # -------------------------------------------------------- saved projects
    # Projects belong to the client picked at the top of the page.
    @app.get("/projects")
    def projects_list():
        c = clients.need("viewer")
        rows = auth.db().execute("SELECT id, name, updated_at, updated_by FROM projects WHERE client_id = ? "
                                 "AND space = ? ORDER BY name COLLATE NOCASE", (c["id"], c["space"]))
        return {"projects": [dict(r) for r in rows], "client": c["name"],
                "can_edit": clients.RANK[c["role"]] >= clients.RANK["editor"]}

    @app.get("/projects/<int:pid>")
    def projects_get(pid: int):
        c = clients.need("viewer")
        row = auth.db().execute("SELECT * FROM projects WHERE id = ? AND client_id = ? AND space = ?",
                                (pid, c["id"], c["space"])).fetchone()
        if row is None:
            abort(404)
        data = json.loads(row["data"])
        if not clients.can_see_secrets(c):
            data = redact.project(data)
        return {"id": row["id"], "name": row["name"], "data": data, "redacted": not clients.can_see_secrets(c)}

    @app.post("/projects")
    def projects_save():
        body = _project_from_request()
        c = clients.need("editor")
        name = str(body.get("name") or "").strip()[:100]
        data = body.get("data")
        if not name or not isinstance(data, dict):
            return {"error": "Give the project a name."}, 400
        text = json.dumps(data)
        if len(text) > MAX_PROJECT_BYTES:
            return {"error": "Project is too large."}, 400
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        db = auth.db()
        db.execute("INSERT INTO projects (client_id, space, name, data, updated_at, updated_by) VALUES (?, ?, ?, ?, ?, ?) "
                   "ON CONFLICT (client_id, space, name) DO UPDATE SET data = excluded.data, "
                   "updated_at = excluded.updated_at, updated_by = excluded.updated_by",
                   (c["id"], c["space"], name, text, now, auth.current_user()["username"]))
        db.commit()
        pid = db.execute("SELECT id FROM projects WHERE client_id = ? AND space = ? AND name = ?",
                         (c["id"], c["space"], name)).fetchone()[0]
        return {"id": pid, "name": name, "updated_at": now, "client": c["name"]}

    @app.post("/projects/<int:pid>/delete")
    def projects_delete(pid: int):
        c = clients.need("editor")
        db = auth.db()
        cur = db.execute("DELETE FROM projects WHERE id = ? AND client_id = ? AND space = ?", (pid, c["id"], c["space"]))
        db.commit()
        if cur.rowcount == 0:
            abort(404)
        return {"deleted": pid}

    # -------------------------------------------------------------- scripts
    @app.get("/api/models")
    def api_models():
        return {"models": models.catalog()}

    @app.post("/api/generate")
    def api_generate():
        """For scripts.

        curl -u user:TOKEN -H 'Content-Type: application/json' --data @project.json \\
             'https://host/api/generate?format=set'
        """
        result = build(_project_from_request())
        fmt = request.args.get("format", "json")
        if fmt in ("set", "hierarchy"):
            if result.errors:
                return {"errors": result.errors, "warnings": result.warnings}, 422
            return Response(result.set_text if fmt == "set" else result.hier_text, mimetype="text/plain")
        return result.to_dict()

    @app.errorhandler(400)
    def bad_request(err):
        if request.is_json or request.path != "/":
            return {"error": getattr(err, "description", "Bad request")}, 400
        return err

    return app
