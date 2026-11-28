import socket
import threading

import pytest

paramiko = pytest.importorskip("paramiko")

from switchbuilder import sshfetch  # noqa: E402

CONFIG = "set version 23.4R2\nset system host-name lab-sw1\nset vlans USERS vlan-id 20\n"
LLDP = ("Local Interface    Parent Interface    Chassis Id          Port info          System Name\n"
        "xe-0/1/0           -                   2c:6b:f5:aa:00:01   xe-0/1/2           core-sw1\n")


class FakeJunos(paramiko.ServerInterface):
    def __init__(self, log):
        self.log = log

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    pubkey = None  # a key the fake switch accepts

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_auth_publickey(self, username, key):
        ok = self.pubkey is not None and username == "exbuilder-ro" and key.get_base64() == self.pubkey
        return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL if (username, password) == ("netops", "Secret-123") else paramiko.AUTH_FAILED

    def check_channel_exec_request(self, channel, command):
        command = command.decode()
        self.log.append(command)
        out = (CONFIG if command.startswith("show configuration") else LLDP if "lldp" in command
               else "Hostname: lab-sw1\nModel: ex4300-48p\nJunos: 23.4R2\n" if "version" in command
               else "error: virtual-chassis is not available\n")

        def answer():  # after the exec request has been acknowledged
            channel.sendall(out.encode())
            channel.send_exit_status(0)
            channel.close()
        threading.Timer(0.05, answer).start()
        return True


@pytest.fixture
def switch():
    """A tiny SSH server on 127.0.0.1 that answers like a Junos switch."""
    state = {"key": paramiko.RSAKey.generate(2048), "commands": []}
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
                t.start_server(server=FakeJunos(state["commands"]))
            except (paramiko.SSHException, EOFError):
                continue

    th = threading.Thread(target=serve, daemon=True)
    th.start()
    state["port"] = srv.getsockname()[1]
    yield state
    stop.set()
    th.join(2)
    srv.close()


NETS = [sshfetch.ipaddress.ip_network("127.0.0.0/8")]


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("EXB_SSH_ALLOW", "127.0.0.0/8")
    monkeypatch.delenv("EXB_SSH_DISABLE", raising=False)
    FakeJunos.pubkey = None
    monkeypatch.setenv("EXB_SSH_TIMEOUT", "5")
    sshfetch._recent.clear()


def test_allow_list(monkeypatch):
    assert sshfetch.resolve("127.0.0.1", NETS) == "127.0.0.1"
    with pytest.raises(sshfetch.FetchError, match="outside the allowed networks"):
        sshfetch.resolve("127.0.0.1", [sshfetch.ipaddress.ip_network("10.0.0.0/8")])
    with pytest.raises(sshfetch.FetchError, match="not a host"):
        sshfetch.resolve("-oProxyCommand=x", NETS)
    with pytest.raises(sshfetch.FetchError, match="turned off"):
        sshfetch.resolve("127.0.0.1", [])
    monkeypatch.setenv("EXB_SSH_DISABLE", "true")
    with pytest.raises(sshfetch.FetchError, match="turned off"):
        sshfetch.resolve("127.0.0.1", NETS)
    monkeypatch.delenv("EXB_SSH_DISABLE")
    # The server-wide ceiling still applies, even if a client's list is wider.
    monkeypatch.setenv("EXB_SSH_ALLOW", "127.0.0.2/32")
    with pytest.raises(sshfetch.FetchError, match="outside"):
        sshfetch.resolve("127.0.0.1", NETS)


def test_client_networks_are_checked(monkeypatch):
    monkeypatch.delenv("EXB_SSH_ALLOW")
    nets, problems = sshfetch.check_networks("10.40.10.0/24\n192.168.1.0/24")
    assert [str(n) for n in nets] == ["10.40.10.0/24", "192.168.1.0/24"] and not problems
    _, problems = sshfetch.check_networks("8.8.8.0/24, nope, 10.0.0.0/4")
    assert len(problems) == 3 and any("outside" in p for p in problems) and any("too large" in p for p in problems)
    monkeypatch.setenv("EXB_SSH_ALLOW", "10.40.0.0/16")
    assert sshfetch.check_networks("10.41.0.0/24")[1] and not sshfetch.check_networks("10.40.3.0/24")[1]


def test_key_login(switch, tmp_path):
    private, public = sshfetch.generate_key("test")
    assert public.startswith("ssh-ed25519 ") and public.endswith(" test")
    FakeJunos.pubkey = public.split()[1]
    r = sshfetch.fetch_one("127.0.0.1", "exbuilder-ro", "", tmp_path, port=switch["port"], nets=NETS,
                           pkey=sshfetch.load_key(private))
    assert r["ok"], r
    other = sshfetch.load_key(sshfetch.generate_key()[0])
    r = sshfetch.fetch_one("127.0.0.1", "exbuilder-ro", "", tmp_path, port=switch["port"], nets=NETS, pkey=other)
    assert not r["ok"] and "sign-in failed" in r["error"]


def test_fetch_remembers_and_checks_the_host_key(switch, tmp_path):
    r = sshfetch.fetch_one("127.0.0.1", "netops", "Secret-123", tmp_path, port=switch["port"], nets=NETS)
    assert r["ok"] and r["new_key"] and "host-name lab-sw1" in r["text"] and "core-sw1" in r["text"]
    assert "Model: ex4300-48p" in r["text"] and "error:" not in r["text"]
    from switchbuilder import importer
    assert importer.detect_models(r["text"])["members"][0]["model"] == "EX4300-48P"
    assert switch["commands"] == list(sshfetch.COMMANDS)
    (known,) = sshfetch.known_hosts(tmp_path)
    assert known["host"] == f"[127.0.0.1]:{switch['port']}" and known["fingerprint"] == r["fingerprint"]
    assert "Secret-123" not in (tmp_path / "ssh_known_hosts").read_text()
    again = sshfetch.fetch_one("127.0.0.1", "netops", "Secret-123", tmp_path, port=switch["port"], nets=NETS)
    assert again["ok"] and not again.get("new_key")
    switch["key"] = paramiko.RSAKey.generate(2048)       # the "switch" gets a new key
    bad = sshfetch.fetch_one("127.0.0.1", "netops", "Secret-123", tmp_path, port=switch["port"], nets=NETS)
    assert not bad["ok"] and "CHANGED" in bad["error"]
    assert sshfetch.forget_host(tmp_path, known["host"])
    assert sshfetch.fetch_one("127.0.0.1", "netops", "Secret-123", tmp_path, port=switch["port"], nets=NETS)["ok"]


def test_wrong_password_and_rate_limit(switch, tmp_path, monkeypatch):
    r = sshfetch.fetch_one("127.0.0.1", "netops", "nope", tmp_path, port=switch["port"], nets=NETS)
    assert not r["ok"] and "sign-in failed" in r["error"]
    monkeypatch.setenv("EXB_SSH_RATE", "2")
    sshfetch.check_rate("u")
    sshfetch.check_rate("u")
    with pytest.raises(sshfetch.FetchError, match="Too many"):
        sshfetch.check_rate("u")


def test_web_route_per_client(switch, monkeypatch, caplog, tmp_path):
    pytest.importorskip("flask")
    from test_auth import ADMIN, add_user, csrf, login  # noqa: F401
    from test_builder_web import token
    from switchbuilder.web import create_app
    monkeypatch.setenv("EXB_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("EXB_USERNAME", ADMIN[0])
    monkeypatch.setenv("EXB_PASSWORD", ADMIN[1])
    application = create_app()
    application.config["TESTING"] = True
    client = application.test_client()
    assert login(client, *ADMIN).status_code == 302
    hdr = {"X-CSRF-Token": token(client)}
    body = {"hosts": "127.0.0.1", "username": "netops", "password": "Secret-123", "port": switch["port"]}
    # No networks for the client yet: off.
    assert 'id="ssh-go"' not in client.get("/build/juniper").get_data(as_text=True)
    assert client.post("/ssh/fetch", json=body, headers=hdr).status_code == 403
    form = {"csrf_token": csrf(client, "/clients/1"), "action": "ssh", "networks": "127.0.0.0/24", "ssh_user": ""}
    assert client.post("/clients/1", data=form).status_code == 302
    page = client.get("/build/juniper").get_data(as_text=True)
    assert 'id="ssh-go"' in page and "127.0.0.0/24" in page
    with caplog.at_level("WARNING", logger="switchbuilder.ssh"):
        resp = client.post("/ssh/fetch", json=body, headers=hdr)
    assert resp.status_code == 200 and resp.json["results"][0]["ok"]
    assert resp.json["results"][0]["backup"]["unchanged"] is False      # kept as a config backup
    (bk,) = client.get("/backups").json["backups"]
    assert bk["source"] == "ssh" and bk["address"] == "127.0.0.1"
    assert "audit: ssh fetch" in caplog.text and "'Default'" in caplog.text and "Secret-123" not in caplog.text
    assert client.post("/ssh/fetch", json={**body, "password": ""}, headers=hdr).status_code == 400
    assert client.get("/ssh/known").json["hosts"]
    assert (tmp_path / "clients" / "1" / "ssh_known_hosts").exists()
    # The client's own key: made on the client page, stored encrypted, used for the fetch.
    assert client.post("/ssh/fetch", json={**body, "use_key": True}, headers=hdr).status_code == 400  # no key yet
    client.post("/clients/1", data={"csrf_token": form["csrf_token"], "action": "key_generate"})
    client.post("/clients/1", data={**form, "ssh_user": "exbuilder-ro"})
    page = client.get("/clients/1").get_data(as_text=True)
    pub = page.split("ssh-ed25519 ")[1].split()[0]
    import sqlite3
    stored = sqlite3.connect(tmp_path / "users.db").execute("SELECT ssh_key FROM clients WHERE id = 1").fetchone()[0]
    assert "PRIVATE KEY" not in stored and stored.startswith("gAAAA")
    FakeJunos.pubkey = pub
    resp = client.post("/ssh/fetch", json={"hosts": "127.0.0.1", "use_key": True, "port": switch["port"]}, headers=hdr)
    assert resp.json["results"][0]["ok"], resp.json
    assert resp.json["results"][0]["backup"]["unchanged"] is True       # same config: not kept twice
    assert len(client.get("/backups").json["backups"]) == 1
    # Other members (Read-only too) fetch only with the read-only key, as its own switch user.
    add_user(client, "bob", "bob-password-1")
    client.post("/clients/1", data={"csrf_token": form["csrf_token"], "action": "member_add", "username": "bob",
                                     "role": "viewer"})
    bob = application.test_client()
    assert login(bob, "bob", "bob-password-1").status_code == 302
    page = bob.get("/build/juniper").get_data(as_text=True)
    assert 'id="ssh-go"' in page and 'value="password"' not in page.split('id="ssh-box"')[1].split("</details>")[0]
    assert 'id="ssh-known-btn"' not in page
    bh = {"X-CSRF-Token": token(bob)}
    assert bob.post("/ssh/fetch", json=body, headers=bh).status_code == 403        # no passwords for non-admins
    with caplog.at_level("WARNING", logger="switchbuilder.ssh"):
        resp = bob.post("/ssh/fetch", json={**body, "use_key": True, "username": "root"}, headers=bh)
    assert resp.status_code == 200 and resp.json["results"][0]["ok"], resp.json
    assert "as 'exbuilder-ro' (key)" in caplog.text and "as 'root'" not in caplog.text
    assert bob.get("/ssh/known").status_code == 403
    # Without a read-only key, non-admins can't fetch at all.
    client.post("/clients/1", data={"csrf_token": form["csrf_token"], "action": "key_delete", "kind": "ro"})
    assert 'id="ssh-go"' not in bob.get("/build/juniper").get_data(as_text=True)
    assert bob.post("/ssh/fetch", json={**body, "use_key": True}, headers=bh).status_code == 400
    assert bob.get("/clients/1").status_code == 403
    client.post("/clients/1", data={"csrf_token": form["csrf_token"], "action": "member_role", "user_id": "2",
                                     "role": "admin"})
    assert bob.post("/ssh/fetch", json=body, headers={"X-CSRF-Token": token(bob)}).status_code == 200
    # Server-wide kill switch.
    monkeypatch.setenv("EXB_SSH_DISABLE", "true")
    assert client.post("/ssh/fetch", json=body, headers=hdr).status_code == 403
