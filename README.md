# Multi-Vendor Switch Config Builder

A web GUI (and a small CLI) that builds switch configuration. After you sign in,
pick a vendor:

| Vendor | Writes config for | Status |
|---|---|---|
| Juniper | Junos ELS: EX2300, EX3400, EX4100, EX4300, EX4400 | ready |
| Arista | EOS: 720XP, 722XPM, 7010, 7050X3, vEOS and cEOS lab | ready |
| Cisco | IOS-XE and IOS: Catalyst 9200, 9300, 9500, older 2960-X, 3650, 3850, and Cat9kv lab | ready |
| Cisco Nexus | NX-OS: Nexus 9200, 9300, older 3000, and Nexus 9000v lab | ready |
| Dell | SmartFabric OS10: N3200, N2200, S5200 and OS10 virtual lab | ready |
| Extreme Networks | EXOS / Switch Engine: X440-G2, X450-G2, X460-G2, 5320, 5420 and EXOS VM | ready |
| Fortinet FortiSwitch | FortiSwitchOS (standalone): FS-100F, 200E, 400E, 1000E | ready |
| MikroTik | RouterOS v7 script: CRS326, CRS328, CRS354, CRS310, CRS317 and CHR lab | ready |
| Ubiquiti UniFi | UniFi Network settings sheet: USW Lite, Standard, Pro, Pro Max and Aggregation | ready |
| Brocade / Ruckus | FastIron: ICX 7000 and 6000, FCX, FGS, FLS | ready |
| HPE Aruba CX | AOS-CX: CX 6000, 6100, 6200, 6300, 8320, 8325, 8360 | ready |
| HPE Aruba / ProCurve | AOS-S: 2530, 2540, 2920, 2930F, 2930M, 3810M, 5400R, older ProCurve | ready |

A beginner's guide is built in: **Help** in the top bar (`/help`), with the loading steps for every vendor.

Fill in forms, and the config appears live, ready to copy or download (for Juniper
as `set` commands and as the hierarchical, curly brace, format). Clients, saved
projects, network maps and backups are shared by all vendors.

The project used to be called *EX Config Builder*. The Python package and the
`EXB_` settings keep their old names, so existing installs upgrade in place.

**VLAN translation.** On a trunk port (Advanced mode) write pairs such as
`120>20, 130>30`: frames that arrive tagged 120 join VLAN 20 on this switch and
leave tagged 120 again. On Juniper this is `vlan-rewrite translate`, which the
EX4100, EX4300 and EX4400 support (EX2300 and EX3400 do not, and you get a warning).

![The builder in Basic mode with the office example loaded](docs/screenshots/01-builder-basic.png)

## How to use it

1. **Pick Basic or Advanced** (top left). Basic shows what a normal access switch
   needs: system, users, SNMP and logs, VLANs, ports, LAGs, static routes and
   services. Advanced adds OSPF, BGP, policies, EVPN-VXLAN and the less common
   fields (speed, MTU, MAC limit, VC pre-provisioning and so on). Settings you
   already made stay in the config when you switch to Basic. The menu is split
   into **Essentials**, **Advanced** and **Tools**. In Advanced mode the extra
   fields of each card or port group sit together in a purple dashed
   **Advanced options** box, and advanced-only tabs and cards have a purple edge,
   so you can always tell the basics from the extras.
2. **Start from something.** Choose a model on the Switch tab, load an example,
   import your current config, or fill in the Excel template (see below).
3. **Work through the tabs.** Click ports on the port map to make a port group or
   a LAG, or add them to an existing one (Shift-click picks a range). Click a
   port that is already in a group to edit that group: its ports light up, click
   ports to add or remove them, then **Save group**. A port added to one group is
   taken out of any other. The config on the right updates as you type, with errors in red
   (Junos would refuse them) and warnings in orange. Anything missing or wrong, such
   as an empty host name or root password, is outlined in red right on the field (or
   its row in a table), and the tab it sits on turns red with a count. Click an
   error in the list to jump straight to that field.
4. **Copy or download** the set commands or the hierarchical config, then load it
   on the switch as described in [Applying the config](#applying-the-config-on-a-switch).

![Port groups and the port map](docs/screenshots/02-ports.png)

![Advanced mode: the extra fields in a purple Advanced options box](docs/screenshots/07-advanced-options.png)

The port map colours each port by what it does: access, trunk, routed, LAG
member, phones (or a voice VLAN), Wi-Fi access points and cameras ("Connected
devices" on a port group). Ports that are not provisioned have a dashed border;
disabled ports are crossed out.

### Voice, QoS, PoE and port security (Services tab)

- **Voice VLAN:** pick one per access port group, or tick "Voice VLAN" on a
  VLAN to give it to every access port. Phones learn it through LLDP-MED.
- **QoS presets:** "voice only" or "voice and video". Voice (EF) goes in a
  strict-priority queue, video and call signalling (AF41, CS3) get their own
  share, and network control keeps 5%. Custom percentages are in Advanced mode.
- **PoE:** on all ports, per-group priority, maximum power or off, perpetual and
  fast PoE, and (Advanced) power management mode and guard band.
- **Port security:** MAC limit with drop, log or shutdown, sticky MAC, DHCP
  snooping, ARP inspection and IP source guard per VLAN, storm control, BPDU
  block, root guard and loop protection on uplinks, auto-recovery, and
  802.1X / MAB with RADIUS servers, a server-fail action and a guest VLAN.

![PoE, port security and QoS](docs/screenshots/06-poe-security-qos.png)

### Import and check an existing config

Click **Import…**, paste the output of `show configuration | display set` (or
the curly-brace config), or drop a `.conf`/`.txt` file, then **Check config**.

- Every line is either read into the builder's tabs or listed under "not
  imported", so nothing is lost silently.
- The config gets a score out of 100 and a list of recommendations, the
  important ones first. Examples: Telnet or HTTP turned on, SNMP `public`,
  root SSH login, no NTP or syslog server, no BPDU protection, storm control or
  DHCP snooping, LAGs without LACP.
- The switch model is picked for you. Paste the output of `show version` or
  `show virtual-chassis` with the config and the exact model of every Virtual
  Chassis member is used (with serial numbers and roles from
  `show virtual-chassis`). Without it, the model is guessed from the ports in
  use, PoE settings and the management port (`em0` means EX4100/EX4400), and the
  page says it is a guess. SSH fetch runs both commands by itself.
- **Load as it is** puts the config in the tabs. **Load with recommended fixes**
  also applies the safe fixes (deny root SSH, login retry limits, SSH limits,
  banner, RSTP edge ports, BPDU block, storm control, LLDP).

![Import and check with recommendations](docs/screenshots/05-import-check.png)

### Network map (several switches)

The **Network map** tab (under Tools) reads the configs of many switches at once:
drop several files or a .zip, or paste them one by one. It draws each switch and
the links between them, and checks that both ends of every link agree.

- **Links** come from `show lldp neighbors` output (paste it under a config or in
  its LLDP box; most accurate), from routed ports in the same /30 or /31, and from
  port descriptions that name another switch (`uplink to core-sw1 xe-0/1/0`). LAG
  members on both ends fold into one thick LAG line.
- **Checks on each link:** trunk VLANs allowed on one end only, VLANs that are not
  defined on the switch, native VLAN, access VLAN, port mode, MTU, a LAG on one
  end only, and disabled ports.
- **Checks across switches:** duplicate host names and IP addresses, one VLAN ID
  with different names, and which switch is the spanning-tree root (marked ★).
- Drag switches to arrange them (the layout is remembered in your browser), click
  a link or switch for details, **Save SVG/PNG** for documentation, and
  **Open in builder** to edit one switch. **Load the example** shows three
  switches with a few deliberate mistakes.

![Network map with three switches](docs/screenshots/08-network-map.png)

**Fetch from switches over SSH** (on the Network map tab): enter
the switch addresses, and the builder runs `show configuration | display set`,
`show lldp neighbors`, `show version` and `show virtual-chassis` on each one and adds them to the map. Each client sets
its own switch networks and SSH key under **Clients → (client) → Fetching
configs over SSH**; it is off for a client until its networks are set. Safety
rules, all on by default:

- client admins can fetch with a key or a password; every other member of the
  client (Configurator and Read-only) can fetch only with the client's
  **read-only key**, as its switch user. Only addresses inside its networks
  are reached (every address a name resolves to is checked). The server limits
  what a client may enter: `EXB_SSH_ALLOW` if set, otherwise the private ranges.
  `EXB_SSH_DISABLE=true` turns it off for everyone;
- only those four read-only commands run; nothing you type is sent as a command;
- you choose how to sign in: **SSH key** (recommended) or **Password**. A
  password is used for that fetch and dropped, never saved or logged, but it
  still passes through the server, so the page warns about it and suggests a
  read-only account with its own password;
- each client can have two keys, both made by the server: a **read-only key**
  (fetch, compare, nightly backups, discovery) and a **config key** (pushes
  only; a push with a key never uses the read-only key or the server-wide
  key). Each has its own switch username. Only client admins make, see or use
  the config key. Only the public half is shown, and the private half is stored encrypted with a master
  key (`EXB_MASTER_KEY_FILE`, best as a Docker secret; otherwise
  `<data>/master_key` is made on first use);
- each switch's SSH host key is remembered on first contact
  (`<data>/clients/<id>/ssh_known_hosts`); a changed key stops the fetch until a
  client admin clears it under **Known switches**;
- every attempt is logged (`audit: ssh fetch by … for client …`, without
  secrets), and each user gets at most `EXB_SSH_RATE` fetches a minute (default 10).

For each key, the client page shows the commands that make its account on
Junos, Arista EOS, NX-OS, Aruba CX and MikroTik (Cisco IOS-XE only takes RSA
user keys, so use a password there). For Junos:

```
# read-only key
set system login class switchbuilder-ro permissions view
set system login class switchbuilder-ro permissions view-configuration
set system login user switchbuilder-ro class switchbuilder-ro authentication ssh-ed25519 "ssh-ed25519 AAAA..."
# config key (a push may replace the whole config, so all permissions, minus reboot/zeroize/shell)
set system login class switchbuilder-cfg permissions all
set system login class switchbuilder-cfg deny-commands "(request system (reboot|halt|power-off|zeroize))|(start shell)"
set system login user switchbuilder-cfg class switchbuilder-cfg authentication ssh-ed25519 "ssh-ed25519 AAAA..."
```

A server-wide key (`EXB_SSH_KEY_FILE` plus `EXB_SSH_KEY_USER`, from a Docker
secret) still works as the read-only key for clients that have none of their
own. It is never used to push.

### From Lab to Production (approval and promote)

A project tested in a client's **Lab** space reaches **Production** only
through an approval:

1. In Lab, save the project, then **Projects → Ask for approval** (editor or
   admin), with an optional note on what was tested. The saved project is
   frozen as a snapshot and must build with no errors.
2. A client admin or a Super Admin opens the snapshot and clicks **Approve**
   or **Reject** (a reason is required). Admins and Super Admins may approve
   their own requests; a Configurator's request needs one of them.
3. A client admin clicks **Promote to Production**. The approved snapshot is
   copied into Production under the same name. If the Lab project changed after
   approval, it must be approved again. A Production project with that name is
   replaced; **Undo** restores it (or removes the project if it was new).

Every step is in the client's list (who, when, notes) and the audit log
(`audit: … promote …`).

### Test in an EVE-NG lab (push and pull)

With an [EVE-NG](https://www.eve-ng.net/) server you can try the configs on
virtual switches before they go near production. Labs are built in the **Lab**
space only.

| Vendor | Lab node | Lab ports | Needs about |
| --- | --- | --- | --- |
| Juniper | vJunos-switch | ge-0/0/0-9 | 4 CPU, 5 GB |
| Arista | vEOS-lab | Ethernet1-12 | 2 CPU, 4 GB |
| Cisco Catalyst | Cat9kv | Gi1/0/1-8 | 4 CPU, 18 GB |
| Cisco Nexus | Nexus 9000v | Ethernet1/1-16 | 2 CPU, 10 GB |
| Dell | OS10 virtual | ethernet1/1/1-16 | 2 CPU, 4 GB |
| Extreme | EXOS VM | 1-8 | 1 CPU, 1 GB |
| HPE Aruba CX | AOS-CX simulator | 1/1/1-8 | 2 CPU, 4 GB |
| MikroTik | CHR | ether1-8 | 1 CPU, 0.5 GB |

FortiSwitch, Brocade/Ruckus ICX, ProCurve/AOS-S and UniFi have no virtual
switch image, so the EVE-NG lab tab says so for them.

**Set it up once per client** (client admin): **Clients → (client) → EVE-NG lab
server**. Enter the EVE-NG address, an EVE-NG account made for the builder, and
the folder for its labs (default `/exbuilder`), then **Test the connection**.
It lists the lab images installed on EVE-NG. The address must be inside the
networks the server may reach (`EXB_SSH_ALLOW`, or the private ranges), and the
password is stored encrypted with the master key.

**One switch, any vendor** (EVE-NG lab tab → **Build this switch in EVE-NG**):
the project open in the builder is moved onto the vendor's lab switch. The
ports it uses go, in order, onto the lab ports (every port group and LAG gets at
least one; the mapping is listed under the lab); other stack members, the
management address and the banner are left out; a lab login, `exb-lab`, with a
random password is added. The lab starts, the builder answers the first-boot
questions on the console (ZTP/POAP, initial dialog, the new admin password),
types the config in line by line, lists any line the switch refuses, and saves
it. **Pull configs** reads it back (`show running-config`, `/export`, ...)
with the project's port names and without the lab login.

**Several Juniper switches from the map** (EVE-NG lab tab → **Build lab from
the map**):

1. Put the switches on the map and draw it, so the links between them are known
   (LLDP output, /30-/31 addresses or port descriptions).
2. Name the lab, pick the vJunos-switch image and click **Build lab from the
   map** (client admins).
3. Each switch becomes a node and each link between two switches a cable. The
   real ports are mapped onto the lab node's ports, `ge-0/0/0` to `ge-0/0/9`, in
   port order, and the configs are rewritten to match: lines for ports not
   linked to another switch on the map, `chassis` (except LAG device counts),
   Virtual Chassis, PoE, `version` and the management port are left out.
4. With **Start the lab and load the configs** ticked, the lab starts and each
   config is typed into its node's console (`load set terminal`, then
   `commit and-quit`). vJunos takes 5 to 10 minutes to boot; progress shows on
   the page and you can leave it.
5. **Pull configs** reads every node's config back, maps the ports back to the
   real names, and offers **Put them on the map** or **Download**. Junos configs
   pulled from a lab are also kept under Backups & compare.

Labs can be started, stopped and deleted from the same list. Every build and
change is in the audit log (`audit: … EVE-NG … lab …`). The console dialogues
for the non-Juniper OSes are tested against simulated consoles; try a first lab
per vendor and watch the progress list.

![Building a lab in EVE-NG from the network map](docs/screenshots/10-eve-ng-lab.png)

### Config backups and compare

The **Backups & compare** tab (under Tools) keeps the configs of each client's
switches and compares any two configs.

**Config backups.** Every config fetched over SSH and every config pulled back
from an EVE-NG lab is kept as a backup, with its date, where it came from and
who got it. A config that has not changed since the last backup of that switch
is not kept again, and the newest 50 versions of each switch are kept. Editors
can also **Upload configs** (files or a .zip), **Keep the map's switches** or
**Keep the builder's config**. Download one version, or **Download newest of
each switch** as a .zip. Only client admins delete backups.

**Compare.** Pick a config for side A and side B:

* **Live switch**: fetched now over SSH (client admins, or any member with the
  client's read-only key), and kept as a backup too.
* **A config backup**, for example last week's.
* **The builder's config**: what the builder makes for the current project.
* **A switch on the network map**, for example one pulled from an EVE-NG lab.
* **Pasted** text.

Both sides are read as `set` lines, so the order and the format do not matter.
The differences are listed per interface, unit, VLAN or protocol, with a few
unchanged lines around them. Encrypted passwords and keys (`$9$…`, `$6$…`) are
ignored by default, because Junos re-encrypts them every time. Below the
differences are the commands that **make A like B** and **make B like A**: a
whole interface or VLAN that is missing is deleted with one line, and a changed
value is simply set again. Read them before you use them, then on the switch:
`configure`, paste, `show | compare`, `commit check` and `commit confirmed 5`.
Things written differently but meaning the same (an `interface-range` against
single ports, for example) show up as differences.

Typical uses: *drift* (live switch against its last backup or against the
builder's project), *before a change* (builder against live, then paste the
"make A like B" commands), and *after a lab test* (lab pull against the
builder's config).

Other vendors' configs (Cisco, Arista, Nexus, Dell, Aruba, ProCurve, Ruckus,
Extreme, FortiSwitch, MikroTik) are compared block by block (each interface,
VLAN or router section, in config order), without "make A like B" commands.
Lines that change on every fetch without a real change (the "Last configuration
change" stamp, `ntp clock-period`, the RouterOS export date) are left out, so
they never count as a new version either. **Changes** on a backup shows what
changed since the version before it.

### Nightly backups and change alerts

On a client's page, **Set up nightly backups** (client admins): list the
switches (`address vendor [port]`, one per line), pick the time and time zone,
and who gets alerts: email addresses and/or webhooks for Microsoft Teams
(channel > Workflows > "Post to a channel when a webhook request is received"),
Slack, Discord or any JSON webhook. Every night the **jobs** service signs in
to each switch with the client's SSH key (never a stored password), runs the
vendor's read-only command (`show configuration | display set`,
`show running-config`, `show running-configuration`, `show configuration`,
`show`, `/export terse`) and keeps the config as a Production backup. The
alert lists the changed lines of each switch (passwords and keys hidden) and
every switch that could not be read. **Back up now** and **Send a test alert**
are on the same page, with the last runs below. Webhook addresses are stored
encrypted with the master key. UniFi has no SSH config to read.

The jobs service is a second service in the stack (`switchbuilder jobs`, same
image and data volume, same node). Email needs `EXB_SMTP_HOST`, `EXB_SMTP_PORT`,
`EXB_SMTP_TLS` (`starttls`, `ssl` or `none`), `EXB_SMTP_USER`,
`EXB_SMTP_PASSWORD_FILE` and `EXB_SMTP_FROM`; `EXB_PUBLIC_URL` adds a link to
the alerts.

### Switch logs (built-in syslog server)

The jobs service is also a syslog server (UDP and TCP port 514, published in
host mode so the switches' real addresses are seen). On a client's page, **Set
up switch logs** (client admins): turn logs on, list the networks the switches
send from (empty = the client's SSH switch networks), and the days to keep
(default 30). A message goes to the client whose networks contain the sender
(the most specific network wins); messages from addresses no client lists are
dropped, so clients never see each other's logs. Logs live in their own
database, `/data/syslog.db`.

The **Logs** page (top bar) shows the current client's logs, newest first, with
search, switch, level and time filters, a live view and a CSV download. An
optional alert sends serious messages (for example "error or worse", optionally
only those containing a word) to the nightly backup alert targets, at most once
every 5 minutes. The settings page lists the syslog commands for each vendor.
Limits: `EXB_SYSLOG_RATE` messages a second per sender (200),
`EXB_SYSLOG_MAX_ROWS` messages per client (2 million), 8 KB per message.
`EXB_SYSLOG_ADDRESS` is the address shown on the settings page.

![Comparing a backup with the builder's config](docs/screenshots/11-backups-compare.png)

### Back up and restore a client

On a client's page (**Clients → the client**), **Download a backup** saves one
JSON file with the client's projects, network maps, config backups, settings
and people. Tick **Leave out the switch config backups** for a smaller file.
The SSH keys and the EVE-NG password are left out unless you tick **Include the
SSH keys and the EVE-NG password**; even then they stay encrypted with this
server's master key and only work on this server. The file still holds the
switch configs, with the switches' own secrets in them, so store it like a
password.

**Load a backup** adds the projects, maps and config backups from a file to the
client (nothing is deleted). Projects and maps with the same name are replaced,
or kept if you pick **skip**. Settings and people are only restored when you
tick them; people are only added if their user exists on this server. Server
admins can also **Make a client from a backup** on the Clients page, for
example to move a client to another server. Each export and import is in the
audit log.

### Clients (several networks or customers)

Every saved project and network map belongs to a **client**. Pick the client at
the top of the page; **Save to (client)** and the **Projects** tab use it.
People only see the clients they are added to. Each person has one of four
access levels:

| Level | Can |
| --- | --- |
| Read-only | open the client's projects, maps and config backups; passwords, password hashes, keys and SNMP communities are hidden |
| Configurator | also build, save and delete them, run the converter and ask for approval; sees the secrets |
| Admin | also add people, set the SSH and EVE-NG settings, approve Lab work and fetch configs over SSH |
| Super Admin | everything in every client, plus the Users page and creating, renaming and deleting clients; must use 2FA |

When a Super Admin adds a user on the **Users** page, they pick the level and
either **All clients, also ones added later** or **Only these clients**. A
client's Admin can still add a person to that client with another level on the
client's page; where both apply, the higher level wins. Internally the client
roles are still called `viewer`, `editor` and `admin`, and Super Admin is the
`admin` user role, so existing users keep exactly the access they had.

Super Admins create, rename and delete clients under **Clients**.

### Sign in with a company account (LDAP, Entra ID, Google, Okta, SAML)

A Super Admin sets this up under **Sign-in** in the top bar:

- **LDAP / Active Directory**: people type their directory username and
  password on the normal sign-in page. Use `ldaps://` (or StartTLS) and a
  read-only service account. Groups inside groups work on AD.
- **OpenID Connect**: Microsoft Entra ID (Azure AD), Google Workspace, Okta,
  Authentik, Keycloak. Register the app with the redirect URI shown on the
  page; a "Sign in with ..." button appears on the sign-in page.
- **SAML 2.0**: Entra ID, ADFS, Okta, Google, Authentik, JumpCloud. Give the
  provider the entity ID and reply (ACS) URL shown, or paste its metadata.
  Sign the assertion, leave assertion encryption off.

Each provider has group rules, one per line: `group = level @ clients`, for
example `Network Engineers = configurator @ all` or
`Helpdesk = readonly @ Acme, Default`. Access is set from the person's groups
at every sign-in. Without a matching group the sign-in is refused (unless you
tick "Let people in without a matching group"). Local accounts always keep
working, so a local Super Admin can sign in if the directory is down.
OIDC and SAML users use the provider's MFA instead of this app's codes;
LDAP users follow this app's 2FA rules. Set **App address** to the https
address people use so the links back from the provider are right behind
Nginx Proxy Manager. Deleting a client asks you to type
its name, and removes its projects, maps, config backups and settings. On the first start after
upgrading, everything saved before moves into a client called **Default**
(rename it to suit), and people who had saved projects become its editors.

![A client's settings page](docs/screenshots/09-client.png)

### Excel workbook

**Import… → Download the Excel template** gives a workbook with a Settings sheet
and one sheet each for Users, SNMP, SNMPv3, VLANs, Ports, LAGs and static
routes, with drop-down lists. Fill it in and drop it on the Import page; the
tabs fill themselves. **Save as Excel** (top right) exports the switch you are
working on in the same format, so you can edit it in Excel and import it again.
OSPF, BGP, policies and EVPN-VXLAN stay in the builder.

### EVPN-VXLAN fabric wizard (Advanced)

The EVPN-VXLAN tab opens with a wizard: pick a template or a fabric type (each
has a small picture showing where the gateway lives), the number of spines and
leaves, the ports between them, and your VLANs and VRFs. It works out every
address, AS number, VNI and route target, draws the fabric, and writes one
config per switch.

![Fabric wizard: templates and fabric types](docs/screenshots/03-fabric-wizard.png)

![Fabric wizard result: topology, switches and cabling](docs/screenshots/04-fabric-result.png)

## Converter

**Converter** (first screen after sign-in, or the top bar) turns a config from one vendor into another: paste a
Cisco Catalyst (IOS / IOS-XE), Cisco Nexus, Arista EOS, Dell OS10 or Juniper EX config, auto-detect or pick the source, pick the target vendor and
model, and get the target config plus a report of everything not carried over (unread lines, features the target
lacks, password hashes that must be retyped, the old-to-new port map). Ports move by position onto the target model.
Save the result to a client's Lab, test it, then promote it with the usual approval flow. Code: `src/switchbuilder/convert/`
(one reader per source vendor; `retarget()` and `portmap.py` are shared). Readers for the other vendors come next.

## What it covers

| Area | What you can set |
|---|---|
| Hardware | Model (EX2300 / EX3400 / EX4100 / EX4100-F / EX4300 / EX4400, incl. PoE and multigig), Virtual Chassis members, pre-provisioning with serial numbers, a clickable port map |
| System | Host name, domain, time zone, DNS servers and search domains, NTP (preferred server, source address), login banner, management port (me0/em0) with optional management VRF, auto-snapshot |
| Users | Root password and SSH key, local users with class, password and SSH keys. Passwords are turned into SHA-512 (`$6$`) hashes; plain text never reaches the output or a saved project |
| Remote access | SSH root login, connection and rate limits, NETCONF, J-Web, login retry limits |
| SNMP | Location, contact, v2c communities with allowed clients, v3 users (SHA/SHA-2 + AES/DES), v2c trap receivers |
| Logging | Local level, CLI command log, remote syslog servers with facility, level and port |
| VLANs | Name, ID, description, IRB (layer 3) addresses incl. IPv6, DHCP relay, DHCP snooping, ARP inspection, IP source guard |
| Ports | Port groups with ranges (`ge-0/0/0-23`): access (+ voice VLAN), trunk (+ native VLAN), routed (layer 3), disabled; PoE priority/off, speed, MTU, RSTP edge, MAC limit, DHCP-trusted |
| LAGs | ae interfaces with LACP active/passive/static, fast timers, minimum links; trunk, access or routed |
| Routing | Loopback, router ID, AS number, ECMP, IPv4 and IPv6 static routes (next hop, discard, reject, preference), DHCP relay servers |
| OSPF | Areas (normal, stub, NSSA), interfaces, passive and point-to-point interfaces, MD5 keys, reference bandwidth, export policies |
| BGP | Groups (eBGP / iBGP), neighbors with their own AS and description, local address, import/export policies, BFD, multipath, MD5 |
| Policies | Prefix lists, communities, policy statements with terms: from protocol / prefix list / route filter / community, then local preference, MED, community add, next-hop self, accept / reject / next term |
| EVPN-VXLAN | Leaf, collapsed-core or spine (route reflector) role, iBGP or eBGP overlay, VNI per VLAN, anycast gateway (virtual-gateway-address), tenant VRFs with EVPN type-5 routes, ESI-LAG multihoming. EX4100, EX4400 and EX4300-48MP |
| EVPN-VXLAN fabric wizard | Pick a template or a fabric type (collapsed core, edge-routed ERB, centrally-routed CRB, bridged overlay) with a small picture of each, set how many spines and leaves, the ports between them and the VLANs/VRFs. The wizard assigns loopbacks, /31 links, AS numbers, VNIs, route targets, anycast gateways and ESIs, draws the topology, and writes one config per switch (copy, download, zip of all, or open a switch in the builder). Also `POST /fabric` and `/fabric/zip` with `{fabric, base}` |
| Import and check | Read an existing set or curly-brace config into the tabs, score it, list recommendations, load it with or without the recommended fixes, and list the lines it did not import. Also `POST /import/config` with `{text, model}` |
| Excel | Download a template, fill it in and import it; export any project to Excel. `GET /excel/template`, `POST /excel/export`, `POST /import/excel` (file upload) |
| QoS | Voice and video presets (EF strict priority, AF41/CS3 video and signalling, network control), trust on access ports or all ports, custom percentages |
| Port security | 802.1X / MAB with RADIUS, server-fail action, guest VLAN, re-authentication, MAC limit action, sticky MAC, root guard, loop protection, BPDU auto-recovery |
| PoE | All ports, per-group priority / off / maximum power, perpetual and fast PoE, management mode, guard band |
| Services | LLDP, LLDP-MED, RSTP with bridge priority and BPDU guard on edge ports, storm control, IGMP snooping, PoE on all ports, disable unused ports, interface ranges |

It checks what you enter as you type: bad addresses, duplicate VLAN IDs, a port
used twice, a missing root password, VLANs that don't exist, ports the model
doesn't have, Virtual Chassis ports used as network ports, PoE on a non-PoE
model and more. Errors are things Junos would refuse; warnings are things to
double check.

Projects can be downloaded and opened as JSON files, or saved on the server in
the client picked at the top of the page (see **Clients**).

## Applying the config on a switch

**Push from the builder (Juniper, Arista, Cisco IOS-XE, Nexus, Aruba CX, MikroTik).** Client admins push an approved Production project from the Projects tab: preview (running config kept as a backup, the switch's own `show | compare` and `commit check`), then `commit confirmed N` (1-60 minutes, default 10), a reachability check over a new SSH session, and Keep or Roll back. Without a confirmation the switch reverts by itself. Every step is audited (`audit: push`) and listed per client. Per vendor: Junos `commit confirmed`, Arista config session `commit timer`, IOS-XE `configure terminal revert timer` + `configure confirm`, NX-OS checkpoint + one-time scheduler rollback job, AOS-CX `checkpoint auto`, MikroTik Safe Mode held open by the server. OS10, EXOS, FastIron and AOS-S have no automatic rollback and are not pushable. The Docker image runs gunicorn with a 300 s timeout because commits can be slow. `EXB_PUSH_DISABLE=true` turns it off.

1. Connect to the console or SSH, type `cli`, then `configure`.
2. Paste the **set** commands.
3. `show | compare` to see the change, `commit check` to test it.
4. `commit confirmed 5`. If you lose access, the switch rolls back by itself
   after 5 minutes. If you're still connected, type `commit` to keep it.

For the hierarchical format use `load merge terminal`, paste, then Ctrl+D. On a
factory-new switch, `load override terminal` replaces everything.

"Start with delete interfaces / delete vlans" (on by default) removes the
factory port settings first, so they can't clash with yours. Turn it off when
you only want to add to an existing config.

## Running it

**New here? Follow the step-by-step [install guide](INSTALL.md)**: installing Docker,
one server or Docker Swarm, first sign-in, HTTPS, upgrades and backups.
Quick start if you already have Docker:

```
docker compose -f deploy/docker-compose.yml up -d
```

Then open `http://<host>:8088` and sign in as `admin` / `admin`; you're asked
for a new password straight away. Users, two-factor sign-in (TOTP), API tokens
and sign-in lockout work the same as in firewall-converter.

## CLI and API

```
pip install '.[web]'
switchbuilder models                                 # list switch models and ports
switchbuilder build project.json                     # set commands to stdout
switchbuilder build project.json -f hierarchy -o sw1.conf
```

Scripts can call the server with a user name and an API token (from "My account"):

```
curl -u alice:exb_TOKEN -H 'Content-Type: application/json' \
     --data @project.json 'https://switchbuilder.example.com/api/generate?format=set'
```

`format=json` (the default) returns the set and hierarchical text, errors,
warnings and generated password hashes.

## Development

```
pip install -e '.[dev,web]'
pytest -q
switchbuilder serve          # http://127.0.0.1:8080, data in $EXB_DATA_DIR
```

The Python package lives in `src/switchbuilder` (it was `src/exbuilder` before; the `exbuilder` CLI name still works as an alias).

Layout: `src/switchbuilder/models.py` (switch models and port layouts),
`generator.py` (project JSON to config, with all checks), `junos.py` (config
tree that prints set or hierarchical format), `cryptpw.py` (SHA-512 crypt),
`web/` (Flask app, login and the builder page).

Model port layouts are the common factory layouts. A 1G optic in a 10G uplink
is named `ge-` instead of `xe-`; the builder accepts both.
