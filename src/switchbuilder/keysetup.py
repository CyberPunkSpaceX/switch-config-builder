"""Switch commands that add a client's SSH key to an account on each switch.

A client can have two keys, each for its own switch account:

* ``ro`` (read-only): SSH fetch, compare, nightly backups and network discovery.
  It only needs to show the config.
* ``cfg`` (config): pushing approved configs. It needs to change the whole
  config (the builder can replace all of it), so it gets full config rights,
  with the commands that can wreck a switch for good (reboot, zeroize, shell)
  taken away where the vendor lets us.

The commands follow the same role names the builder uses on the Users tab.
"""

from __future__ import annotations

KINDS = ("ro", "cfg")
LABELS = {"ro": "Read-only", "cfg": "Config"}
DEFAULT_USER = {"ro": "switchbuilder-ro", "cfg": "switchbuilder-cfg"}


def _key(pub: str) -> tuple[str, str]:
    """'ssh-ed25519 AAAA... comment' -> ('ssh-ed25519', 'AAAA...')."""
    parts = (pub or "").split()
    return (parts[0], parts[1]) if len(parts) >= 2 else ("ssh-ed25519", "PUBLIC-KEY")


def commands(kind: str, user: str, pub: str) -> list[dict]:
    """[{vendor, text, note}] for the switches that can use the client's ed25519 key."""
    if kind not in KINDS:
        raise ValueError(kind)
    user = user or DEFAULT_USER[kind]
    algo, blob = _key(pub)
    line = f"{algo} {blob}"
    ro = kind == "ro"
    cls = "switchbuilder-ro" if ro else "switchbuilder-cfg"
    out = []
    if ro:
        junos = (f"set system login class {cls} permissions view\n"
                 f"set system login class {cls} permissions view-configuration\n")
    else:
        junos = (f"set system login class {cls} permissions all\n"
                 f'set system login class {cls} deny-commands "(request system (reboot|halt|power-off|zeroize))|(start shell)"\n')
    out.append({"vendor": "Juniper Junos", "text": junos +
                f'set system login user {user} class {cls} authentication {algo} "{line}"',
                "note": "" if ro else "The push can replace the whole config, so the class needs all permissions. "
                "Reboot, halt, zeroize and the shell stay blocked."})
    role = "network-operator" if ro else "network-admin"
    out.append({"vendor": "Arista EOS", "text": f"username {user} privilege 15 role {role} nopassword\n"
                f"username {user} ssh-key {line}",
                "note": ("Privilege 15 lets the account run show running-config; the network-operator role keeps it "
                         "read-only. " if ro else "") +
                "EOS only enforces roles with 'aaa authorization commands all default local'."})
    out.append({"vendor": "Cisco Nexus (NX-OS)",
                "text": f"username {user} role {'network-operator' if ro else 'network-admin'}\n"
                        f"username {user} sshkey {line}",
                "note": "NX-OS keeps one SSH key per user."})
    out.append({"vendor": "Aruba CX (AOS-CX)",
                "text": f"user {user} group {'operators' if ro else 'administrators'}\n"
                        f"user {user} authorized-key 1 {line}", "note": ""})
    out.append({"vendor": "MikroTik RouterOS",
                "text": f"/user add name={user} group={'read' if ro else 'full'} password=\"<a long random password>\"\n"
                        f'/user ssh-keys add user={user} key="{line}"',
                "note": "RouterOS 7.12 or later. Every user needs a password; pick a long random one nobody uses."})
    out.append({"vendor": "Cisco IOS-XE", "text": "",
                "note": "IOS-XE only takes RSA keys for users, and this key is ed25519. "
                + ("Use a password with a privilege 1 account here." if ro else
                   "Push with the password of a privilege 15 account here.")})
    return out
