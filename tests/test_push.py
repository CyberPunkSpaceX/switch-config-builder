"""Push to switch: preview with backup, commit confirmed, check, confirm or roll back (against a fake Junos CLI)."""

import json
import re
import socket
import threading
import time
from pathlib import Path

import pytest

paramiko = pytest.importorskip("paramiko")
flask = pytest.importorskip("flask")

from switchbuilder import push as engine  # noqa: E402
from switchbuilder import sshfetch  # noqa: E402
from test_auth import ADMIN, add_user, app, admin, csrf, login  # noqa: F401,E402
from test_builder_web import pick_space, token  # noqa: E402
from test_clients import _bob, _form  # noqa: E402

PROJECT = json.loads((Path(__file__).parent.parent / "examples" / "office-switch.json").read_text())
PROJECT["access"]["root_password"] = "Root-pass-123"
for u in PROJECT["access"]["users"]:
    u["password"] = "User-pass-123"
HOST = PROJECT["system"]["hostname"]


class Res:
    def __init__(self, set_text, hier_text=""):
        self.set_text, self.hier_text = set_text, hier_text


class Cli:
    """Just enough of the Junos CLI: operational and private configuration mode, load set, commit confirmed."""

    def __init__(self, hostname=HOST):
        self.running = [f"system host-name {hostname}", "interfaces me0 unit 0 family inet address 10.0.0.5/24"]
        self.prev = list(self.running)
        self.candidate = None
        self.pending = 0
        self.dirty_shared = False
        self.log = []

    def prompt(self):
        return "\r\n[edit]\r\nnetops@sw# " if self.candidate is not None else "\r\nnetops@sw> "

    def handle(self, line):
        self.log.append(line)
        if line.startswith("set cli"):
            return ""
        if line == "show configuration | display set | no-more":
            return "\r\n".join("set " + x for x in self.running)
        if line == "show system commit | no-more":
            head = f"0   2026-11-25 23:50:00 UTC by netops via cli commit confirmed, rollback in {self.pending}mins\r\n" \
                if self.pending else "0   2026-11-25 23:50:00 UTC by netops via cli\r\n"
            return head + "1   2026-11-25 20:00:00 UTC by root via cli"
        if self.candidate is None:
            if line == "configure private":
                if self.dirty_shared:
                    return "error: shared configuration database modified\r\nUsers currently editing: root"
                self.candidate = list(self.running)
                return "Entering configuration mode"
            return f"unknown command: {line}"
        if line == "show | compare | no-more":
            add = [x for x in self.candidate if x not in self.running]
            gone = [x for x in self.running if x not in self.candidate]
            return "[edit]\r\n" + "\r\n".join(["+ " + x for x in add] + ["- " + x for x in gone])
        if line == "commit check":
            return "configuration check succeeds"
        m = re.match(r"commit confirmed (\d+) comment", line)
        if m:
            self.prev, self.running, self.pending = self.running, list(self.candidate), int(m.group(1))
            return f"commit confirmed will be automatically rolled back in {m.group(1)} minutes unless confirmed\r\n" \
                   "commit complete"
        if line.startswith("commit comment"):
            self.running, self.pending = list(self.candidate), 0
            return "commit complete"
        if line == "rollback 0":
            self.candidate = list(self.running)
            return "load complete"
        if line == "rollback 1":
            self.candidate = list(self.prev)
            return "load complete"
        if line == "exit configuration-mode":
            self.candidate = None
            return "Exiting configuration mode"
        return f"syntax error: {line}"

    def load(self, text):
        errors = 0
        out = []
        for n, ln in enumerate(text.split("\n"), 1):
            ln = ln.strip()
            if ln.startswith("set "):
                if ln[4:] not in self.candidate:
                    self.candidate.append(ln[4:])
            elif ln.startswith("delete "):
                what = ln[7:]
                self.candidate = [x for x in self.candidate if not x.startswith(what)]
            elif ln:
                errors += 1
                out.append(f"terminal:{n}:(1) syntax error: {ln[:20]}")
        out.append("load complete" + (f" ({errors} errors)" if errors else ""))
        return "\r\n".join(out)


class Server(paramiko.ServerInterface):
    def __init__(self, cli):
        self.cli = cli

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    pubkeys: dict = {}   # switch username -> base64 of the public key it accepts

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_auth_publickey(self, username, key):
        return paramiko.AUTH_SUCCESSFUL if Server.pubkeys.get(username) == key.get_base64() else paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL if (username, password) == ("netops", "Secret-123") else paramiko.AUTH_FAILED

    def check_channel_pty_request(self, *a):
        return True

    def check_channel_shell_request(self, channel):
        threading.Thread(target=self.session, args=(channel,), daemon=True).start()
        return True

    def session(self, chan):
        cli = self.cli
        chan.sendall(("--- JUNOS 23.4R2 built 2026-01-01\r\n" + cli.prompt().lstrip()).encode())
        buf = ""
        loading = False
        try:
            while True:
                data = chan.recv(65536)
                if not data:
                    return
                buf += data.decode()
                while True:
                    if loading:
                        if "\x04" not in buf:
                            break
                        text, buf = buf.split("\x04", 1)
                        chan.sendall((text.replace("\n", "\r\n") + "\r\n" + cli.load(text) + cli.prompt()).encode())
                        loading = False
                        continue
                    if "\n" not in buf:
                        break
                    line, buf = buf.split("\n", 1)
                    line = line.strip()
                    if line in ("load set terminal", "load override terminal"):
                        cli.log.append(line)
                        chan.sendall(f"{line}\r\n[Type ^D at a new line to end input]\r\n".encode())
                        loading = True
                        continue
                    out = cli.handle(line)
                    chan.sendall((line + "\r\n" + out + cli.prompt()).encode())
        except (OSError, EOFError):
            return


@pytest.fixture
def switch():
    state = {"key": paramiko.RSAKey.generate(2048), "cli": Cli()}
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    stop = threading.Event()

    def serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            t = paramiko.Transport(conn)
            t.add_server_key(state["key"])
            try:
                t.start_server(server=Server(state["cli"]))
            except (paramiko.SSHException, EOFError):
                continue

    th = threading.Thread(target=serve, daemon=True)
    th.start()
    state["port"] = srv.getsockname()[1]
    yield state
    stop.set()
    th.join(2)
    srv.close()


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("EXB_SSH_ALLOW", "127.0.0.0/8")
    monkeypatch.setenv("EXB_SSH_TIMEOUT", "3")
    monkeypatch.setenv("EXB_SSH_RATE", "100")
    monkeypatch.delenv("EXB_SSH_DISABLE", raising=False)
    monkeypatch.delenv("EXB_PUSH_DISABLE", raising=False)
    sshfetch._recent.clear()


def _post(client, url, body=None):
    return client.post(url, json=body or {}, headers={"X-CSRF-Token": token(client)})


def _know(app, switch, cid=1):
    from switchbuilder.web import auth
    with app.app_context():
        folder = auth.data_dir() / "clients" / str(cid)
    folder.mkdir(parents=True, exist_ok=True)
    k = switch["key"]
    (folder / "ssh_known_hosts").write_text(f"[127.0.0.1]:{switch['port']} {k.get_name()} {k.get_base64()}\n")


def _approved_project(admin, data=PROJECT, name="Office"):
    """Lab -> approve -> promote, then back in Production. Returns the Production project id."""
    pick_space(admin, "lab")
    lab = _post(admin, "/projects", {"name": name, "data": data}).json["id"]
    rid = _post(admin, "/promote/request", {"project_id": lab}).json["id"]
    assert _post(admin, f"/promote/{rid}/approve").json["status"] == "approved"
    pid = _post(admin, f"/promote/{rid}/promote").json["production_project_id"]
    pick_space(admin, "production")
    return pid


def _setup(app, admin, switch):
    _form(admin, "/clients/1", action="ssh", networks="127.0.0.0/8", ssh_user="")
    _know(app, switch)
    return _approved_project(admin)


def _creds(switch, **kw):
    return {"username": "netops", "password": "Secret-123", "port": switch["port"], **kw}


def test_preview_push_check_confirm(app, admin, switch):
    pid = _setup(app, admin, switch)
    page = admin.get("/build/juniper").get_data(as_text=True)
    assert 'id="push-box"' in page and 'id="push-preview"' in page
    listing = admin.get("/push").json
    (proj,) = listing["projects"]
    assert proj["approved"] and proj["ready"] and proj["hostname"] == HOST
    assert listing["support"]["juniper"]["ready"] and not listing["support"]["unifi"]["ready"]

    r = _post(admin, "/push/preview", _creds(switch, project_id=pid, host="127.0.0.1"))
    assert r.status_code == 200, r.json
    prev = r.json
    assert prev["check_ok"] and "+ vlans" in prev["diff"] and not prev["hostname_mismatch"]
    cli = switch["cli"]
    assert cli.running[0] == f"system host-name {HOST}" and len(cli.running) == 2   # nothing changed yet
    assert cli.candidate is None and "rollback 0" in cli.log and "load set terminal" in cli.log
    # The running config was kept as a backup before anything else.
    b = admin.get(f"/backups/{prev['backup']['id']}").json
    assert b["source"] == "prepush" and "10.0.0.5/24" in b["text"]

    assert _post(admin, f"/push/{prev['id']}/apply", _creds(switch, minutes=0)).status_code == 400
    assert _post(admin, f"/push/{prev['id']}/apply", _creds(switch, minutes=61)).status_code == 400
    r = _post(admin, f"/push/{prev['id']}/apply", _creds(switch, minutes=3))
    assert r.status_code == 200, r.json
    assert r.json["status"] == "waiting" and 170 < r.json["seconds_left"] <= 180
    assert cli.pending == 3 and any(x.startswith("commit confirmed 3 comment") for x in cli.log)
    assert any(x.startswith("vlans") for x in cli.running)
    # No second push to the same switch while one waits.
    again = _post(admin, "/push/preview", _creds(switch, project_id=pid, host="127.0.0.1")).json["id"]
    assert _post(admin, f"/push/{again}/apply", _creds(switch)).status_code == 409

    r = _post(admin, f"/push/{prev['id']}/check", _creds(switch))
    assert r.json["reachable"] and "rollback in 3mins" in r.json["pending"]

    r = _post(admin, f"/push/{prev['id']}/confirm", _creds(switch))
    assert r.json["status"] == "confirmed" and cli.pending == 0
    row = next(p for p in admin.get("/push").json["pushes"] if p["id"] == prev["id"])
    assert row["status"] == "confirmed" and row["after_backup_id"] and row["pushed_by"] == ADMIN[0]
    assert _post(admin, f"/push/{prev['id']}/confirm", _creds(switch)).status_code == 409


def test_roll_back_now(app, admin, switch):
    pid = _setup(app, admin, switch)
    before = list(switch["cli"].running)
    prev = _post(admin, "/push/preview", _creds(switch, project_id=pid, host="127.0.0.1")).json
    assert _post(admin, f"/push/{prev['id']}/apply", _creds(switch)).json["status"] == "waiting"
    assert switch["cli"].pending == engine.DEFAULT_MINUTES
    r = _post(admin, f"/push/{prev['id']}/rollback", _creds(switch))
    assert r.json["status"] == "rolled_back"
    assert switch["cli"].running == before and switch["cli"].pending == 0


def test_timer_runs_out(app, admin, switch):
    pid = _setup(app, admin, switch)
    prev = _post(admin, "/push/preview", _creds(switch, project_id=pid, host="127.0.0.1")).json
    _post(admin, f"/push/{prev['id']}/apply", _creds(switch, minutes=1))
    from switchbuilder.web import auth
    with app.app_context():
        auth.db().execute("UPDATE config_pushes SET deadline = ?", (time.time() - 1,))
        auth.db().commit()
    row = admin.get("/push").json["pushes"][0]
    assert row["status"] == "expired" and "by itself" in row["message"]
    assert _post(admin, f"/push/{prev['id']}/confirm", _creds(switch)).status_code == 409


def test_refusals(app, admin, switch):
    pid = _setup(app, admin, switch)
    # Not approved: saved straight into Production.
    other = _post(admin, "/projects", {"name": "Direct", "data": PROJECT}).json["id"]
    r = _post(admin, "/push/preview", _creds(switch, project_id=other, host="127.0.0.1"))
    assert r.status_code == 403 and "not an approved config" in r.json["error"]
    # Only from Production.
    pick_space(admin, "lab")
    assert _post(admin, "/push/preview", _creds(switch, project_id=pid, host="127.0.0.1")).status_code == 409
    pick_space(admin, "production")
    # Unknown host key: nothing is sent.
    _form(admin, "/clients/1", action="forget_host", host=f"[127.0.0.1]:{switch['port']}")
    r = _post(admin, "/push/preview", _creds(switch, project_id=pid, host="127.0.0.1"))
    assert r.status_code == 502 and "not known yet" in r.json["error"]
    _know(app, switch)
    # Outside the client's networks.
    r = _post(admin, "/push/preview", _creds(switch, project_id=pid, host="10.9.9.9"))
    assert r.status_code == 502 and "outside the allowed networks" in r.json["error"]
    # Kill switch.
    import os
    os.environ["EXB_PUSH_DISABLE"] = "true"
    try:
        assert _post(admin, "/push/preview", _creds(switch, project_id=pid, host="127.0.0.1")).status_code == 403
    finally:
        del os.environ["EXB_PUSH_DISABLE"]
    # The switch changed between preview and push.
    prev = _post(admin, "/push/preview", _creds(switch, project_id=pid, host="127.0.0.1")).json
    switch["cli"].running.append("snmp location somewhere-else")
    r = _post(admin, f"/push/{prev['id']}/apply", _creds(switch))
    assert r.status_code == 409 and "changed after the preview" in r.json["error"]
    assert switch["cli"].pending == 0


def test_wrong_switch_needs_a_tick(app, admin, switch):
    switch["cli"].running[0] = "system host-name some-other-switch"
    pid = _setup(app, admin, switch)
    prev = _post(admin, "/push/preview", _creds(switch, project_id=pid, host="127.0.0.1")).json
    assert prev["hostname_mismatch"] and "some-other-switch" in prev["warnings"][0]
    r = _post(admin, f"/push/{prev['id']}/apply", _creds(switch))
    assert r.status_code == 409 and "push anyway" in r.json["error"] and switch["cli"].pending == 0
    assert _post(admin, f"/push/{prev['id']}/apply", _creds(switch, hostname_ok=True)).json["status"] == "waiting"


def test_shared_config_in_use(app, admin, switch):
    pid = _setup(app, admin, switch)
    switch["cli"].dirty_shared = True
    r = _post(admin, "/push/preview", _creds(switch, project_id=pid, host="127.0.0.1"))
    assert r.status_code == 502 and "uncommitted changes" in r.json["error"]


def test_roles(app, admin, switch):
    pid = _setup(app, admin, switch)
    prev = _post(admin, "/push/preview", _creds(switch, project_id=pid, host="127.0.0.1")).json
    editor = _bob(app, admin, "editor")
    pick_space(editor, "production")
    assert _post(editor, "/push/preview", _creds(switch, project_id=pid, host="127.0.0.1")).status_code == 403
    assert _post(editor, f"/push/{prev['id']}/apply", _creds(switch)).status_code == 403
    assert "diff" in editor.get("/push").json["pushes"][0]
    _form(admin, "/clients/1", action="member_add", username="bob", role="viewer")
    assert "diff" not in editor.get("/push").json["pushes"][0]


def test_load_errors_stop_the_push(switch, tmp_path):
    k = switch["key"]
    (tmp_path / "ssh_known_hosts").write_text(f"[127.0.0.1]:{switch['port']} {k.get_name()} {k.get_base64()}\n")
    nets = [sshfetch.ipaddress.ip_network("127.0.0.0/8")]
    shell, drv = engine.connect("juniper", "127.0.0.1", "netops", "Secret-123", tmp_path, switch["port"], nets)
    try:
        with pytest.raises(engine.PushError, match="did not accept"):
            drv.apply(Res("set vlans X vlan-id 5\nbogus line here\n"), "merge", 5, "1", "t")
        assert switch["cli"].pending == 0 and switch["cli"].candidate is None
        with pytest.raises(engine.PushError, match="no commit waiting"):
            drv.confirm("1", "t")
    finally:
        shell.close()
    with pytest.raises(engine.PushError, match="not available yet"):
        engine.connect("unifi", "127.0.0.1", "netops", "x", tmp_path, switch["port"], nets)


def test_push_with_a_key_uses_the_config_key_only(app, admin, switch):
    import re as _re
    pid = _setup(app, admin, switch)
    key_body = {"project_id": pid, "host": "127.0.0.1", "port": switch["port"], "use_key": True}
    # Only a read-only key (on its own switch account): pushing with a key is refused, nothing is sent.
    _form(admin, "/clients/1", action="key_generate", kind="ro")
    _form(admin, "/clients/1", action="ssh", networks="127.0.0.0/8", ssh_user="sb-ro", ssh_user_cfg="sb-cfg")
    page = admin.get("/clients/1").get_data(as_text=True)
    ro_pub = _re.search(r'id="pub-ro"[^>]*>ssh-ed25519 (\S+)', page).group(1)
    Server.pubkeys = {"sb-ro": ro_pub}
    r = _post(admin, "/push/preview", key_body)
    assert r.status_code == 400 and "config SSH key" in r.json["error"]
    assert "load set terminal" not in switch["cli"].log
    build = admin.get("/build/juniper").get_data(as_text=True)
    assert 'name="push-auth" value="key" disabled' in build and "No config key yet" in build
    # The config key: its own key and switch user, used for the push.
    _form(admin, "/clients/1", action="key_generate", kind="cfg")
    page = admin.get("/clients/1").get_data(as_text=True)
    cfg_pub = _re.search(r'id="pub-cfg"[^>]*>ssh-ed25519 (\S+)', page).group(1)
    assert cfg_pub != ro_pub and "class switchbuilder-cfg permissions all" in page
    assert "set system login class switchbuilder-ro permissions view-configuration" in page
    Server.pubkeys = {"sb-ro": ro_pub, "sb-cfg": cfg_pub}
    r = _post(admin, "/push/preview", key_body)
    assert r.status_code == 200, r.json
    # The read-only key on the config account would not do: the push really signed in with the config key.
    Server.pubkeys = {"sb-cfg": ro_pub}
    r = _post(admin, "/push/preview", key_body)
    assert r.status_code == 502 and "sign-in failed" in r.json["error"]
    Server.pubkeys = {}
