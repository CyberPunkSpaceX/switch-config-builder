"""Two SSH keys per client: read-only (fetch, backups) and config (push)."""

import sqlite3

import pytest

flask = pytest.importorskip("flask")
pytest.importorskip("paramiko")

from switchbuilder import keysetup  # noqa: E402
from test_auth import ADMIN, add_user, app, admin, login  # noqa: F401,E402
from test_clients import _form  # noqa: E402


def test_commands_per_kind():
    pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample switchbuilder-ro-x"
    ro = {c["vendor"]: c for c in keysetup.commands("ro", "", pub)}
    cfg = {c["vendor"]: c for c in keysetup.commands("cfg", "pushy", pub)}
    j = ro["Juniper Junos"]["text"]
    assert "permissions view-configuration" in j and "permissions all" not in j and "user switchbuilder-ro " in j
    assert 'authentication ssh-ed25519 "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExample"' in j
    j = cfg["Juniper Junos"]["text"]
    assert "class switchbuilder-cfg permissions all" in j and "deny-commands" in j and "user pushy " in j
    assert "network-operator" in ro["Arista EOS"]["text"] and "network-admin" in cfg["Arista EOS"]["text"]
    assert "group=read" in ro["MikroTik RouterOS"]["text"] and "group=full" in cfg["MikroTik RouterOS"]["text"]
    assert not ro["Cisco IOS-XE"]["text"] and "RSA" in ro["Cisco IOS-XE"]["note"]
    with pytest.raises(ValueError):
        keysetup.commands("root", "", pub)


def test_two_keys_stored_encrypted_and_separate(app, admin, tmp_path):
    for kind in ("ro", "cfg"):
        assert _form(admin, "/clients/1", action="key_generate", kind=kind).status_code == 302
    db = sqlite3.connect(tmp_path / "users.db")
    ro, ro_pub, cfg, cfg_pub = db.execute("SELECT ssh_key, ssh_key_pub, ssh_key_cfg, ssh_key_cfg_pub FROM clients "
                                          "WHERE id = 1").fetchone()
    assert ro.startswith("gAAAA") and cfg.startswith("gAAAA") and "PRIVATE" not in ro + cfg
    assert ro_pub != cfg_pub and "switchbuilder-ro-" in ro_pub and "switchbuilder-cfg-" in cfg_pub
    # Same username for both keys is refused (each key needs its own switch account).
    _form(admin, "/clients/1", action="ssh", networks="", ssh_user="sb", ssh_user_cfg="sb")
    assert db.execute("SELECT ssh_user_cfg FROM clients WHERE id = 1").fetchone()[0] == ""
    # Deleting one leaves the other.
    _form(admin, "/clients/1", action="key_delete", kind="cfg")
    assert db.execute("SELECT ssh_key IS NOT NULL, ssh_key_cfg IS NULL FROM clients WHERE id = 1").fetchone() == (1, 1)
    assert _form(admin, "/clients/1", action="key_generate", kind="nope").status_code == 400


def test_non_admins_never_see_the_config_key(app, admin):
    _form(admin, "/clients/1", action="key_generate", kind="cfg")
    _form(admin, "/clients/1", action="ssh", networks="10.0.0.0/24", ssh_user="", ssh_user_cfg="sb-cfg")
    add_user(admin, "vera", "vera-password-1")
    _form(admin, "/clients/1", action="member_add", username="vera", role="viewer")
    vera = app.test_client()
    assert login(vera, "vera", "vera-password-1").status_code == 302
    page = vera.get("/build/juniper").get_data(as_text=True)
    assert '"cfg_key": false' in page and '"cfg_user": ""' in page and "sb-cfg" not in page
    assert vera.get("/clients/1").status_code == 403
    assert vera.post("/clients/1", data={"action": "key_generate", "kind": "cfg"}).status_code in (400, 403)


def test_old_clients_table_gets_the_config_key_columns(tmp_path):
    from switchbuilder.web import clients
    conn = sqlite3.connect(tmp_path / "old.db")
    conn.execute("CREATE TABLE clients (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE, "
                 "created_at TEXT NOT NULL, ssh_networks TEXT NOT NULL DEFAULT '', ssh_user TEXT NOT NULL DEFAULT '', "
                 "ssh_key TEXT, ssh_key_pub TEXT)")
    conn.execute("INSERT INTO clients (name, created_at, ssh_key) VALUES ('Old', 'x', 'gAAAAold')")
    clients._add_key_columns(conn)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(clients)")}
    assert {"ssh_user_cfg", "ssh_key_cfg", "ssh_key_cfg_pub"} <= cols
    # The old key stays where it was: it is now the read-only key.
    assert conn.execute("SELECT ssh_key, ssh_key_cfg FROM clients").fetchone() == ("gAAAAold", None)
