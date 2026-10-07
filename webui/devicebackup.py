# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""Device configuration backup and restore - the operator's undo.

Gateshift's own README makes a backup mandatory before anything touches a
firewall, and then leaves it as homework. For FortiGate it is not homework
but the ONLY undo: FortiOS has no staging at all (measured 30.09. on 7.6.7 -
`transaction-start` returns an id but the write is immediately visible and
`transaction-abort` fails HTTP 424). PA has a candidate, Check Point has a
session; FortiGate has nothing.

NOTHING IS PERSISTED. A backup is pulled into memory, sanity-checked and
handed to the operator; a restore is read from an upload, used and dropped.
It never reaches the database or the disk, because a device configuration
carries every secret on the box - a PA export's first bytes are literally
`<mgt-config><users><entry name="admin"><phash>` (measured 01.10.). This
keeps the promise the product already makes for uploaded configurations
("Secrets are never stored", docs/vendor-prerequisites.md).

Buffered rather than chunk-streamed, deliberately: a mid-transfer failure
would hand the operator a truncated file that still looks like a
configuration, and this project has already been bitten by exactly that
(a firewall that cut every HTTP/1.1 response at 64 KiB, and the result
looked like intact output).
Configuration backups are megabytes, so buffering costs nothing and buys a
plausibility check.

This is NOT a driver. A driver generates and pushes a MODELLED
configuration; a backup is an opaque blob that replaces the whole device.
Mixing the two would put a second, incompatible notion of "push" into the
driver contract.

An unregistered platform is a first-class state, not a gap: Check Point's
backup covers the whole management server rather than the gateway of a
device row, so it is out by decision, and `supported()` says so.
"""
import dataclasses
import re
import xml.etree.ElementTree as ET

import requests

from deploy.panw import _CONNECT_TIMEOUT, _api_url, _post_api_retry

# FIRST RELEASE: HIDDEN (decision 2026-10-01). The feature works - the tests
# and the measured notes below stand - but FortiOS denies an API restore to
# token admins, so the vendor this was built for ends up backup-only, and
# the documentation already makes backups the operator's duty. Shelved as a
# whole, like Optimize: this flag is the only entry point. It hides the row
# button, the restore block, the push-dialog reminder AND the endpoints
# (they answer 404). To bring it back: flip the flag and restore the docs
# from commit d790502 (vendor-prerequisites, KNOWN_LIMITATIONS, README).
ENABLED = False

# A PA-440's running config is ~265 KB; a loaded chassis is larger and the box
# renders it on demand, so the read timeout is generous while the connect
# timeout stays short.
_PULL_TIMEOUT = (_CONNECT_TIMEOUT, 180)
_RESTORE_TIMEOUT = (_CONNECT_TIMEOUT, 300)

# PAN-OS cannot delete a saved configuration with the API role our docs
# prescribe (superuser, measured 01.10.), so Gateshift must not accumulate
# files it can never clean up: ONE name, overwritten per restore.
_PA_RESTORE_NAME = "gateshift-restore.xml"


class BackupError(RuntimeError):
    """A backup or restore could not be completed. Message is operator-facing.

    `steps` carries whatever a restore managed before it failed - an upload
    that landed but did not load is a fact the log must keep."""

    def __init__(self, message: str, steps: list[dict] | None = None):
        super().__init__(message)
        self.steps = list(steps or [])


class BackupInvalid(BackupError):
    """The blob is not a usable configuration for this platform."""


class BackupIdentityMismatch(BackupError):
    """The file belongs to a different device than the one being restored."""


@dataclasses.dataclass
class Backup:
    blob: bytes
    filename: str
    content_type: str
    identity: dict
    # Operator-facing caveats about THIS backup, e.g. "the candidate holds
    # uncommitted changes that are not in here". Never a reason to refuse.
    warnings: list[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class Identity:
    """What a backup file says about its own origin.

    Fields are None when the format does not carry them. PA is the
    cautionary case: an exported configuration carries the hostname and the
    PAN-OS version and NOTHING else - no model, no serial (measured 01.10.,
    searched element-wise and byte-wise). Hostname is therefore the only
    identity a PA restore can check, which is why it is the hard check and
    the serial is informational.
    """
    hostname: str | None = None
    model: str | None = None
    version: str | None = None
    serial: str | None = None

    def as_dict(self) -> dict:
        return dataclasses.asdict(self)


# ── Palo Alto Networks ────────────────────────────────────────────────────
#
# Per-call privileges, measured 01.10. against PAN-OS 10.1.3 with the API
# role docs/vendor-prerequisites.md prescribes:
#
#   export running config  GET type=export&category=configuration   works
#   export a named config  + &from=<name>                           works
#   save candidate to name op <save><config><to>                    works
#   load on-box file       op <load><config><from>                  works
#   revert candidate       op <revert><config>                      works
#   UPLOAD a config        POST type=import&category=configuration  SUPERUSER
#   delete a saved config  op <delete><config><saved>               SUPERUSER
#
# So the backup half needs no new permissions and the restore half does. The
# gap is named when it fires (see _PA_HINTS) rather than demanded of
# everyone up front.

_PA_SUPERUSER_RE = re.compile(r"superuser", re.I)

_PA_HINTS = (
    (_PA_SUPERUSER_RE,
     "PAN-OS requires SUPERUSER privileges to import a configuration file. "
     "The API role for config read/write is not enough. Either use an API "
     "key of a superuser admin for the restore, or import this file on the "
     "firewall itself (Device > Setup > Operations > Import named "
     "configuration snapshot) and load it there."),
)


def _pa_hint(text_: str) -> str | None:
    for pattern, hint in _PA_HINTS:
        if pattern.search(text_ or ""):
            return hint
    return None


def _pa_op(device: dict, cmd: str) -> ET.Element:
    """PAN-OS operational command. Returns the parsed <response> element."""
    resp = _post_api_retry(
        f"{_api_url(device)}/api/",
        data={"type": "op", "cmd": cmd},
        headers={"X-PAN-KEY": device.get("api_key") or ""},
        timeout=_RESTORE_TIMEOUT,
    )
    resp.raise_for_status()
    return ET.fromstring(resp.text)


_PA_SHOW_RUNNING = "<show><config><running></running></config></show>"
_PA_PENDING = "<check><pending-changes></pending-changes></check>"


def _pa_pull(device: dict) -> Backup:
    """The RUNNING configuration, via `show config running`.

    NOT `type=export&category=configuration`. Measured 01.10. on 10.1.3: that
    call exports the CANDIDATE, and it silently ignores
    `from=running-config.xml` - a marker object set only in the candidate
    came back in every variant. A backup that quietly includes someone's
    uncommitted draft is not a backup of the device. `show config running`
    is the one call that excludes the draft, and its `<config>` payload has
    the same shape as an export (same attributes, same three children), so
    it loads back with `load config from`.

    One attempt, no push-grade backoff: this sits behind a click, and a
    clear error beats a four-minute retry ladder.
    """
    key = device.get("api_key") or ""
    if not key:
        raise BackupError("no API key configured for this device")
    resp = requests.post(
        f"{_api_url(device)}/api/",
        data={"type": "op", "cmd": _PA_SHOW_RUNNING},
        headers={"X-PAN-KEY": key},
        verify=False, timeout=_PULL_TIMEOUT,
    )
    if resp.status_code != 200 or not resp.content:
        raise BackupError(f"PAN-OS refused the read: HTTP {resp.status_code} "
                          f"{resp.text[:200]}")
    blob = _pa_unwrap(resp.content)
    ident = _pa_identity(blob)          # also validates the shape
    host = ident.hostname or device.get("host_name") or "panos"
    bk = Backup(blob=blob,
                filename=f"gateshift-backup-{_safe(host)}.xml",
                content_type="application/xml",
                identity=ident.as_dict())
    if _pa_pending_changes(device):
        bk.warnings.append(
            "The firewall's candidate configuration holds uncommitted changes. "
            "This backup is the RUNNING configuration and does not include "
            "them: commit or save them on the firewall first if they matter.")
    return bk


def _pa_unwrap(body: bytes) -> bytes:
    """`show config running|candidate` answers `<response><result><config>`;
    return the bare `<config>` document, which is what a restore loads.
    Raises BackupInvalid on an error response or a missing payload."""
    try:
        root = ET.fromstring(body)
    except ET.ParseError as e:
        raise BackupInvalid(f"the firewall's answer was not well-formed XML ({e})") from e
    if root.attrib.get("status") != "success":
        raise BackupError(f"PAN-OS refused the read: {_pa_msg(root) or body[:200]!r}")
    cfg = root.find("./result/config")
    if cfg is None:
        raise BackupInvalid("the firewall's answer carries no <config> payload")
    return ET.tostring(cfg, encoding="utf-8")


def _pa_pending_changes(device: dict) -> bool | None:
    """True when candidate != running. None when the check itself failed -
    a warning is never worth failing the backup over."""
    try:
        resp = requests.post(
            f"{_api_url(device)}/api/",
            data={"type": "op", "cmd": _PA_PENDING},
            headers={"X-PAN-KEY": device.get("api_key") or ""},
            verify=False, timeout=(_CONNECT_TIMEOUT, 30),
        )
        root = ET.fromstring(resp.content)
        return (root.findtext("./result") or "").strip().lower() == "yes"
    except Exception:
        return None


def _pa_verify(blob: bytes) -> ET.Element:
    """Parse and shape-check a PA export. Raises BackupInvalid.

    The checks come from the measured format: the root is <config> with a
    `version` attribute, and `devices` is one of its children (the others
    are `mgt-config` and `shared`). A truncated export fails the XML parse,
    which is the whole point of buffering before handing the file over.
    """
    if not blob:
        raise BackupInvalid("the file is empty")
    try:
        root = ET.fromstring(blob)
    except ET.ParseError as e:
        raise BackupInvalid(
            f"not a well-formed PAN-OS configuration (XML parse failed at "
            f"{e}). A truncated download or an edited file looks like this."
        ) from e
    if root.tag != "config":
        raise BackupInvalid(
            f"root element is <{root.tag}>, expected <config>: this is not a "
            "PAN-OS configuration export")
    if root.find("devices") is None:
        raise BackupInvalid(
            "the configuration has no <devices> section: a PAN-OS export "
            "always carries one")
    return root


def _pa_identity(blob: bytes) -> Identity:
    root = _pa_verify(blob)
    # devices/entry@name is always 'localhost.localdomain' and worthless for
    # identity; the hostname lives in deviceconfig. Model and serial are NOT
    # in the file at all (measured) - left None on purpose.
    return Identity(
        hostname=(root.findtext(".//deviceconfig/system/hostname") or "").strip() or None,
        version=root.attrib.get("detail-version") or root.attrib.get("version"),
    )


def _pa_restore(device: dict, blob: bytes) -> list[dict]:
    """Upload a configuration and load it into the CANDIDATE. No commit.

    Follows the product rule the prerequisites doc already states for PA
    ("Nothing is committed") instead of breaking it for the emergency case:
    the operator reviews the loaded candidate and commits it. That also
    means a restore is reversible until the commit.
    """
    _pa_verify(blob)
    key = device.get("api_key") or ""
    if not key:
        raise BackupError("no API key configured for this device")
    steps: list[dict] = []

    resp = _post_api_retry(
        f"{_api_url(device)}/api/",
        data=None,
        params={"type": "import", "category": "configuration"},
        headers={"X-PAN-KEY": key},
        files={"file": (_PA_RESTORE_NAME, blob, "application/xml")},
        timeout=_RESTORE_TIMEOUT,
    )
    body = resp.text or ""
    ok = resp.status_code == 200 and 'status="success"' in body
    if not ok:
        hint = _pa_hint(body)
        steps.append({"step": f"upload {_PA_RESTORE_NAME}", "success": False,
                      "detail": _pa_msg(body) or body[:200]})
        raise BackupError(
            f"upload to the firewall failed: {_pa_msg(body) or body[:200]}"
            + (f"\n\n{hint}" if hint else ""), steps)
    steps.append({"step": f"upload {_PA_RESTORE_NAME}", "success": True,
                  "detail": _pa_msg(body) or "stored on the firewall"})

    root = _pa_op(device, f"<load><config><from>{_PA_RESTORE_NAME}</from>"
                          "</config></load>")
    if root.attrib.get("status") != "success":
        body = ET.tostring(root, encoding="unicode")
        hint = _pa_hint(body)
        steps.append({"step": "load into candidate", "success": False,
                      "detail": _pa_msg(body) or body[:200]})
        raise BackupError(
            f"the file was uploaded but could not be loaded: "
            f"{_pa_msg(body) or body[:200]}"
            + (f"\n\n{hint}" if hint else ""), steps)
    steps.append({"step": "load into candidate", "success": True,
                  "detail": _pa_msg(ET.tostring(root, encoding='unicode'))
                            or "loaded"})
    steps.append({
        "step": "commit", "success": True,
        "detail": "NOT committed: review the candidate on the firewall and "
                  "commit it there. Until you commit, the running "
                  "configuration is unchanged.",
    })
    return steps


def _pa_msg(body: str) -> str:
    """Pull the human-readable line out of a PAN-OS response.

    PAN-OS nests freely (`<result><msg><line><msg><line>text`), so the
    first <line> found is often a wrapper with no text of its own; take the
    first element that actually carries text.
    """
    try:
        root = ET.fromstring(body) if isinstance(body, str) else body
    except Exception:
        return ""
    for xp in (".//line", ".//msg", "./result"):
        for el in root.iterfind(xp):
            t = (el.text or "").strip()
            if t:
                return " ".join(t.split())[:300]
    return ""


# ── FortiGate ────────────────────────────────────────────────────────────
#
# Measured 01.10. on FortiOS 7.6.7 build 3704 (FGVMA6 on AWS) with the REST
# API administrator our docs prescribe:
#
#   backup   POST monitor/system/config/backup {scope:global}   works (GET 405s)
#   restore  POST monitor/system/config/restore                 HTTP 403
#
# The 403 came back in 0.2 s, for a multipart upload and for a JSON body with
# base64 `file_content` alike, from an access profile carrying sysgrp
# read-write with no sub-restriction. So the restore half is not offered for
# FortiGate: the backup is handed over, and the operator restores it on the
# firewall itself. See `no_restore` in the registry for the operator text.
#
# The backup is a plaintext `.conf`: a `#config-version=` header naming the
# MODEL code, version and build, then `config ... end` blocks with the
# hostname in `config system global`. No serial anywhere (byte-searched
# against the box's real one). A complete file ends with `end`.

_FGT_HEADER_RE = re.compile(
    rb"^#config-version=(?P<model>[A-Za-z0-9_]+)-(?P<version>\d+\.\d+\.\d+)"
    rb"-FW-build(?P<build>\d+)-(?P<date>\d+)")
_FGT_HOSTNAME_RE = re.compile(rb'^\s*set hostname "?([^"\r\n]+?)"?\s*$', re.M)
_FGT_BACKUP_TIMEOUT = (_CONNECT_TIMEOUT, 120)


def _fgt_conn(device: dict):
    from deploy import _forti_common as fc
    from deploy.fortinet import _verify_tls
    return (fc.base_url_for(device), device.get("api_key") or "",
            fc.vdom_for(device), _verify_tls(device))


def _fgt_msg(resp) -> str:
    """The readable part of a FortiOS error answer, if any."""
    try:
        j = resp.json()
    except Exception:
        return (resp.text or "")[:200]
    for k in ("cli_error", "error_description", "message"):
        if j.get(k):
            return str(j[k])[:300]
    return f"status={j.get('status')} error={j.get('error')}" if j.get("error") is not None else ""


def _fgt_pull(device: dict) -> Backup:
    """The running configuration - FortiOS has no candidate, so this IS the
    device. Same call optimize.py has used in operation as its pre-delete
    restore point."""
    base, token, vdom, verify = _fgt_conn(device)
    if not token:
        raise BackupError("no API key configured for this device")
    resp = requests.post(f"{base}/api/v2/monitor/system/config/backup",
                         headers={"Authorization": f"Bearer {token}",
                                  "Content-Type": "application/json"},
                         data='{"scope":"global"}', verify=verify,
                         timeout=_FGT_BACKUP_TIMEOUT)
    if resp.status_code != 200 or not resp.content:
        raise BackupError(f"FortiOS refused the backup: HTTP {resp.status_code} "
                          f"{_fgt_msg(resp)}".rstrip())
    blob = resp.content
    ident = _fgt_identity(blob)         # also validates the shape
    host = ident.hostname or device.get("host_name") or "fortigate"
    bk = Backup(blob=blob,
                filename=f"gateshift-backup-{_safe(host)}.conf",
                content_type="text/plain; charset=utf-8",
                identity=ident.as_dict())
    ha = _fgt_ha_note(device, base, token, vdom, verify)
    if ha:
        bk.warnings.append(ha)
    return bk


def _fgt_ha_note(device, base, token, vdom, verify) -> str | None:
    """A cluster member's backup is the cluster's shared configuration as
    THIS member holds it - worth saying, never worth failing over. Reuses
    the push driver's HA read, which fails open on any error."""
    try:
        from deploy.fortinet import _read_ha_context
        ctx = _read_ha_context(device, base, token, vdom, verify)
        if ctx.get("enabled"):
            who = ctx.get("hostname") or "this member"
            return (f"This firewall is an HA cluster member ({who}). The backup "
                    "is the cluster's shared configuration as this member holds "
                    "it. Per-member settings of the other member are not in it.")
    except Exception:
        pass
    return None


def _fgt_verify(blob: bytes) -> dict:
    """Parse the header and shape-check a FortiOS backup. Raises BackupInvalid.

    Returns the header fields (model, version, build, date)."""
    if not blob:
        raise BackupInvalid("the file is empty")
    if not blob.startswith(b"#config-version="):
        raise BackupInvalid(
            "not a plaintext FortiOS configuration backup: the file does not "
            "start with '#config-version='. A backup made with a password is "
            "encrypted and cannot be read. Take one without a password.")
    m = _FGT_HEADER_RE.match(blob)
    if not m:
        head = blob.split(b"\n", 1)[0][:80].decode("latin-1")
        raise BackupInvalid(f"unrecognised #config-version header: {head}")
    last = blob.rstrip(b"\r\n\t ").rsplit(b"\n", 1)[-1].strip()
    if last != b"end":
        raise BackupInvalid(
            f"the file does not end with 'end' (last line: "
            f"{last[:40].decode('latin-1')!r}). A truncated download looks "
            "like this")
    return {k: v.decode("ascii") for k, v in m.groupdict().items()}


def _fgt_identity(blob: bytes) -> Identity:
    h = _fgt_verify(blob)
    m = _FGT_HOSTNAME_RE.search(blob)
    return Identity(
        hostname=m.group(1).decode("utf-8", "replace").strip() if m else None,
        model=h["model"],
        version=f"{h['version']} build {h['build']}",
    )


# ── Registry ─────────────────────────────────────────────────────────────
#
# An adapter without `restore` is a first-class state, not a gap: the
# download half satisfies the duty the README puts on the operator ("back up
# every system before Gateshift touches it"), and where the vendor refuses
# an API restore the operator restores on the firewall. `no_restore` is
# the sentence the UI and the docs quote for that. An unregistered platform
# (Check Point) is the same idea one level up - see NOT_OFFERED.

_ADAPTERS = {
    "panw": {
        "pull": _pa_pull,
        "identity": _pa_identity,
        "verify": _pa_verify,
        "restore": _pa_restore,
        "restore_note": "The configuration is loaded into the candidate. "
                        "Nothing is committed, so the running configuration "
                        "stays as it is until you commit on the firewall.",
    },
    "fortigate": {
        "pull": _fgt_pull,
        "identity": _fgt_identity,
        "verify": _fgt_verify,
        "restore": None,
        "no_restore": "FortiOS refuses a configuration restore from a REST API "
                      "token (HTTP 403 on 7.6.7, even with full system "
                      "permissions). Restore the downloaded file on the "
                      "firewall itself, System > Configuration > Backup & "
                      "Restore, which reboots it.",
    },
}

# Why a platform is absent, for the UI and the docs to quote rather than
# stay silent (the product's own habit: a limit is stated, never hidden).
NOT_OFFERED = {
    "checkpoint": "A Check Point backup covers the whole management server, "
                  "not the gateway of this device row.",
}


def supported(platform: str) -> bool:
    """Can this platform be backed up through Gateshift?"""
    return platform in _ADAPTERS


def can_restore(platform: str) -> bool:
    """Can a backup be written back through Gateshift? Narrower than
    supported(): FortiGate is backup-only by measurement."""
    return bool((_ADAPTERS.get(platform) or {}).get("restore"))


def no_restore_reason(platform: str) -> str:
    a = _ADAPTERS.get(platform)
    if a is None:
        return NOT_OFFERED.get(platform) or f"configuration backup is not available for {platform}"
    return a.get("no_restore") or ""


def _adapter(platform: str) -> dict:
    a = _ADAPTERS.get(platform)
    if a is None:
        raise BackupError(
            NOT_OFFERED.get(platform)
            or f"configuration backup is not available for {platform}")
    return a


def pull(device: dict) -> Backup:
    """Fetch the device's own configuration. Read-only on the device."""
    return _adapter(device.get("platform"))["pull"](device)


def read_identity(blob: bytes, platform: str) -> Identity:
    """What the file says about its origin. Raises BackupInvalid on junk."""
    return _adapter(platform)["identity"](blob)


def verify(blob: bytes, platform: str) -> None:
    """Shape-check a blob. Raises BackupInvalid with an operator-facing why."""
    _adapter(platform)["verify"](blob)


def restore_note(platform: str) -> str:
    return _adapter(platform).get("restore_note") or ""


def check_identity(blob: bytes, device: dict) -> Identity:
    """Hard gate: the file's hostname must match the device's.

    Hostname is the hard check and the serial is informational because for
    PA the serial is not in the file at all - and because a hostname match
    keeps the real recovery case working: an RMA replacement box has the
    same hostname and a different serial.
    """
    ident = read_identity(blob, device.get("platform"))
    want = (device.get("host_name") or "").strip()
    got = (ident.hostname or "").strip()
    if not got:
        raise BackupIdentityMismatch(
            "the file carries no hostname, so Gateshift cannot tell which "
            "device it belongs to")
    # A device row may carry an FQDN while the box knows only its short name.
    if got.lower() != want.lower() and got.lower() != want.split(".")[0].lower():
        raise BackupIdentityMismatch(
            f"this file is a backup of '{got}', but the device is '{want}'. "
            "Restoring one firewall's configuration onto another is the one "
            "mistake this check exists to prevent.")
    return ident


def restore(device: dict, blob: bytes) -> list[dict]:
    """Write a configuration back onto the device. Identity is checked first."""
    platform = device.get("platform") or ""
    adapter = _adapter(platform)
    if not adapter.get("restore"):
        raise BackupError(adapter.get("no_restore")
                          or f"restore is not available for {platform}")
    check_identity(blob, device)
    return adapter["restore"](device, blob)


_NAME_UNSAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _safe(name: str) -> str:
    """Filename-safe host name for the Content-Disposition header."""
    return _NAME_UNSAFE_RE.sub("-", (name or "").strip()).strip("-") or "device"
