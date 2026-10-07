# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""Shared OPNsense transport: auth, request helpers, error hints, naming.

Split out of the driver the way `_forti_common.py` is, so the import
handler in main.py can reuse it without importing the deploy driver (and
without the circular import that would cause).

Everything here was measured against a live 26.7 box; the notes name what
was surprising, because none of it is in the vendor documentation.

Credential model follows the FTD precedent: OPNsense needs a key AND a
secret but `fw_devices.api_key` is a single column, so the SECRET lives
there (Fernet-encrypted like every other credential) and the key id sits
in `config.opnsense.api_key_id`.
"""

import hashlib
import json
import re
import time
import urllib.parse
import xml.etree.ElementTree as ET

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Firewall management interfaces ship self-signed certificates; see
# SECURITY.md for the deliberate scope note about this.
VERIFY_TLS = False

# A read that a human is waiting on must fail fast; pushes get the longer
# budget. base.transport_fail_fast() flips this per call site.
_CONNECT_TIMEOUT = 5
_READ_TIMEOUT = 30


class OPNsenseError(RuntimeError):
    """An API call that came back with something other than success."""

    def __init__(self, message, *, status=None, payload=None, path=None):
        super().__init__(message)
        self.status = status
        self.payload = payload
        self.path = path


# ── Device / auth ────────────────────────────────────────────────

def api_key_id(device: dict) -> str:
    """The public half of the credential pair, out of the device config."""
    cfg = device.get("config")
    if isinstance(cfg, str):
        try:
            cfg = json.loads(cfg)
        except ValueError:
            cfg = {}
    return ((cfg or {}).get("opnsense") or {}).get("api_key_id") or ""


def base_url(device: dict) -> str:
    host = (device.get("mgmt_ip") or device.get("host_name") or "").strip()
    port = device.get("mgmt_port") or 443
    if "://" in host:
        host = urllib.parse.urlparse(host).netloc or host
    return f"https://{host}:{port}" if str(port) != "443" else f"https://{host}"


def session_for(device: dict) -> requests.Session:
    """A session carrying HTTP basic auth - OPNsense has no login step and
    no token, every call authenticates on its own."""
    sess = requests.Session()
    sess.verify = VERIFY_TLS
    sess.auth = (api_key_id(device), device.get("api_key") or "")
    return sess


def _timeouts():
    try:
        from deploy.base import transport_fail_fast
        if transport_fail_fast():
            return (_CONNECT_TIMEOUT, 10)
    except Exception:
        pass
    return (_CONNECT_TIMEOUT, _READ_TIMEOUT)


def api_get(sess, device, path: str):
    url = f"{base_url(device)}/api/{path.lstrip('/')}"
    resp = sess.get(url, timeout=_timeouts())
    return _decode(resp, path)


def api_post(sess, device, path: str, payload: dict | None = None):
    url = f"{base_url(device)}/api/{path.lstrip('/')}"
    resp = sess.post(url, json=payload if payload is not None else {},
                     timeout=_timeouts())
    return _decode(resp, path)


def _decode(resp, path):
    if resp.status_code == 401:
        raise OPNsenseError(
            "authentication failed: check the API key and secret, and that "
            "the user still exists", status=401, path=path)
    if resp.status_code == 404:
        raise OPNsenseError(
            f"endpoint not available on this OPNsense version: {path}",
            status=404, path=path)
    try:
        body = resp.json()
    except ValueError:
        raise OPNsenseError(
            f"non-JSON reply from {path} (HTTP {resp.status_code})",
            status=resp.status_code, path=path)
    if isinstance(body, dict) and body.get("errorMessage"):
        raise OPNsenseError(f"{body['errorMessage']} ({path})",
                            status=resp.status_code, payload=body, path=path)
    return body


# (!) OPNsense 26.7 TRUNCATES an HTTP/1.1 response at 65528 bytes - 64 KiB
# less 8 - and the body then ends mid-JSON. Measured on a live box: the same
# search over HTTP/2 returns 311408 bytes intact, over HTTP/1.1 it stops at
# 65528 every time, for every page size that would exceed it. Python's HTTP
# client speaks 1.1, so a search has to keep each PAGE under that ceiling.
#
# Rows are not a proxy for bytes here: a filter rule carries `alias_meta_*`
# blocks with rendered HTML, so one rule is 2-3 KB while an alias is a few
# hundred. A fixed page size is therefore a guess - 50 rules measured 65142
# bytes, which happens to fit only by 400 bytes. So the page size STARTS
# conservative and HALVES itself whenever a page comes back unreadable.
_SEARCH_PAGE_SIZE = 25
_SEARCH_PAGE_MIN = 1


def search_all(sess, device, path: str, page_size: int = _SEARCH_PAGE_SIZE
               ) -> list[dict]:
    """Every row of a `search_*` endpoint.

    (!) These endpoints are POST-only. A GET answers
    `{"status":400,"message":"Invalid JSON syntax"}`, which reads like a
    malformed request but is really "you used the wrong verb" - it cost an
    afternoon during the P0 recon.

    Pages shrink on a damaged reply rather than failing the caller: see the
    64 KiB note above. A page that stays broken at one row per request is a
    real error and is raised.
    """
    rows, page, size = [], 1, max(int(page_size), _SEARCH_PAGE_MIN)
    while True:
        try:
            body = api_post(sess, device, path,
                            {"current": page, "rowCount": size})
        except (OPNsenseError, requests.exceptions.RequestException) as exc:
            # A truncated body surfaces either as non-JSON (content-length
            # form) or as a chunked-encoding error (chunked form). Both mean
            # "this page was too big", so retry the SAME page smaller: the
            # rows already collected stay valid because paging is by offset.
            if size <= _SEARCH_PAGE_MIN or not _looks_truncated(exc):
                raise
            # Start the listing OVER at the smaller size instead of continuing
            # from the current offset. Offsets are page-based ((current-1) *
            # rowCount), so carrying rows across a size change would repeat or
            # skip a row at the boundary - and a repeated row means a second
            # delete attempt in the caller's wipe phase. Re-reading a few
            # pages is cheap; a listing with a hole in it is not.
            size = max(size // 2, _SEARCH_PAGE_MIN)
            rows, page = [], 1
            continue
        chunk = body.get("rows") or []
        rows.extend(chunk)
        total = body.get("total") or len(rows)
        if len(rows) >= total or not chunk:
            return rows
        page += 1


def _looks_truncated(exc: Exception) -> bool:
    """Whether this failure is the 64 KiB truncation rather than a real error."""
    if isinstance(exc, OPNsenseError):
        return "non-JSON reply" in str(exc)
    return isinstance(exc, (requests.exceptions.ChunkedEncodingError,
                            requests.exceptions.ContentDecodingError,
                            requests.exceptions.ConnectionError))


def fetch_config_xml(sess, device) -> str:
    """The full running config.

    This is the ONLY complete read of an OPNsense: the firewall API
    exposes just its own ruleset and cannot see classic rules at all.
    Needs the user privilege "Diagnostics: Configuration History".

    (!) The reply carries every secret on the box - private keys, PSKs,
    password hashes. Run parsers.opnsense_config.sanitize() on it before
    it is stored anywhere.
    """
    url = f"{base_url(device)}/api/core/backup/download/this"
    last = ""
    for attempt in range(4):
        try:
            resp = sess.get(url, timeout=(_CONNECT_TIMEOUT, 120))
        except requests.exceptions.RequestException as exc:
            last = f"transport error: {exc}"
            time.sleep(2)
            continue
        if resp.status_code == 403:
            raise OPNsenseError(
                "the API user may not download the configuration: grant it "
                "the 'Diagnostics: Configuration History' privilege",
                status=403)
        if resp.status_code != 200:
            raise OPNsenseError(
                f"config download failed (HTTP {resp.status_code})",
                status=resp.status_code)
        text = resp.text
        # (!) Parse it, do not just look at it. A large configuration comes
        # off this box with pieces MISSING from the middle while the
        # declared length stays right - a rule ended up spliced into a
        # later one, and only parsing caught it. Importing that quietly
        # would drop policy without anyone noticing, which is the one
        # failure mode a migration tool must not have.
        try:
            ET.fromstring(text)
        except ET.ParseError as exc:
            last = f"the configuration arrived damaged ({exc})"
            time.sleep(2)
            continue
        return text
    raise OPNsenseError(
        f"the firewall did not return a usable configuration - {last}. "
        "On OPNsense 26.7 the web server corrupts large responses over "
        "HTTP/1.1: the body arrives with a block missing from the middle "
        "while the length still matches, so retrying does not help. "
        "(Reproducible with curl: --http1.1 fails, HTTP/2 succeeds - it is "
        "the firewall, not the client.) Export the configuration under "
        "System > Configuration > Backups and upload it instead; the "
        "browser uses HTTP/2 and gets an intact file. Gateshift refuses "
        "rather than import a policy with holes in it.")


# Two steps on purpose. A single `<nat>.*?<outbound>.*?<mode>` matches ACROSS
# the closing </nat>, so an <outbound> belonging to a later section would be
# read as the NAT mode - a wrong all-clear, which is the one outcome this
# check must never produce. So: isolate the CLOSED <nat> block first, then
# look inside it. If the body was cut mid-block there is no </nat> and the
# answer is "could not verify", which is correct rather than unfortunate.
# Bytes, not text: the body may be cut mid-character.
_NAT_BLOCK_RE = re.compile(rb"<nat>(.*?)</nat>", re.S)
_NAT_MODE_RE = re.compile(
    rb"<outbound>.*?<mode>\s*([A-Za-z_]+)\s*</mode>", re.S)


def outbound_nat_mode(sess, device) -> tuple[str | None, str]:
    """Firewall > NAT > Outbound mode - the setting that has no API.

    (!) Deliberately does NOT require a well-formed document, and that is the
    whole point. OPNsense 26.7 truncates an HTTP/1.1 response at 65528 bytes,
    so a real firewall's configuration never arrives complete - which left
    this preflight permanently blind on every box with a real configuration
    while it insisted on parsing the whole file. But the block it needs sits
    EARLY: measured at bytes 7329-7400 on a seeded lab box, the block itself
    being 71 bytes. The readable prefix carries it.

    Returns (mode, note). `mode` is None when it could not be determined -
    the caller must then say so rather than assume the mode is fine. The
    remaining blind spot is a configuration whose <interfaces> section alone
    exceeds 64 KiB and pushes <nat> out of the window; that degrades to the
    same "could not verify" as before, never to a false all-clear.
    """
    url = f"{base_url(device)}/api/core/backup/download/this"
    try:
        resp = sess.get(url, timeout=(_CONNECT_TIMEOUT, 120))
    except requests.exceptions.RequestException as exc:
        return None, f"transport error: {exc}"
    if resp.status_code == 403:
        return None, ("the API user may not download the configuration: it "
                      "needs the 'Diagnostics: Configuration History' privilege")
    if resp.status_code != 200:
        return None, f"HTTP {resp.status_code} from the configuration download"
    block = _NAT_BLOCK_RE.search(resp.content)
    match = _NAT_MODE_RE.search(block.group(1)) if block else None
    if not match:
        return None, ("the outbound-NAT block was not in the part of the "
                      "configuration this firewall returned")
    return match.group(1).decode("ascii", "replace").lower(), ""


def product_version(sess, device) -> str | None:
    """Product version, e.g. '26.7'. Needed because the rules a push writes
    only surface as a first-class menu from 26.1 on."""
    body = api_get(sess, device, "core/firmware/status")
    prod = body.get("product") or {}
    return prod.get("product_version") or body.get("product_version")


def version_tuple(version: str | None) -> tuple[int, ...]:
    return tuple(int(p) for p in re.findall(r"\d+", version or "")[:2])


# ── Naming ───────────────────────────────────────────────────────

# Alias and interface-group names are identifiers, not labels: OPNsense
# rejects punctuation and spaces outright, so a migrated object whose name
# came from another vendor has to be folded into this shape.
_NAME_SAFE_RE = re.compile(r"[^A-Za-z0-9_]")
# (!) THIRTY-ONE, not 32. The firewall's own words: "be less than 32
# characters". A name of exactly 32 is rejected, which is what a 32-limit
# produced for every long rule name.
NAME_MAX = 31
# Room for "_" plus a 4-hex digest on a name that has to be shortened.
_HASH_LEN = 4


def safe_name(name: str, *, max_len: int = NAME_MAX) -> str:
    """Fold a name into an OPNsense identifier, keeping distinct names distinct.

    (!) Truncation alone is not safe here. A synthesised alias name encodes
    the rule AND the protocol (gs_svc_<rule>_tcp), so cutting the tail drops
    exactly the discriminator: the tcp and udp variants of one long rule
    would collapse onto the same name and the second write would silently
    take over the first one's alias. Any two source objects sharing a long
    prefix have the same problem.

    So a name that has to be shortened keeps a short digest of the ORIGINAL.
    The digest is deterministic, which matters as much as its uniqueness -
    the push reconciles what is on the firewall BY NAME, so the same source
    object has to fold to the same identifier on every push.
    """
    cleaned = _NAME_SAFE_RE.sub("_", (name or "").strip())
    if cleaned and cleaned[0].isdigit():
        cleaned = f"gs_{cleaned}"
    if not cleaned:
        return "gs_unnamed"
    if len(cleaned) <= max_len:
        return cleaned
    digest = hashlib.sha1(cleaned.encode()).hexdigest()[:_HASH_LEN]
    return f"{cleaned[:max_len - _HASH_LEN - 1]}_{digest}"


# ── What the firewall will accept as an interface ─────────────────
#
# (!) Ask the box, never infer. Both models publish their own option list,
# and the two lists DIFFER: a group may contain only ASSIGNED interfaces,
# while a rule may additionally name a group. Getting this from anywhere
# else would be guesswork about a validation we cannot see.

def assignable_interfaces(sess, device) -> set[str]:
    """Interfaces an interface GROUP may contain - the assigned ones.

    A VLAN or a tunnel that exists only as a device is NOT in here: it has
    to be assigned under Interfaces > Assignments first, and that step has
    no API (see KNOWN_LIMITATIONS.md).
    """
    body = api_post(sess, device, "firewall/group/get_item", {})
    members = ((body.get("group") or body) or {}).get("members") or {}
    return set(members) if isinstance(members, dict) else set()


def referenceable_interfaces(sess, device) -> set[str]:
    """What a RULE may name: the assigned interfaces plus existing groups."""
    body = api_post(sess, device, "firewall/filter/get_rule", {})
    ifaces = ((body.get("rule") or body) or {}).get("interface") or {}
    return set(ifaces) if isinstance(ifaces, dict) else set()


# ── Error hints ──────────────────────────────────────────────────

def _hint_group_not_applied(ctx: dict) -> str:
    # Creating an interface group is not enough to reference it: until
    # firewall/group/reconfigure has run, the filter model still validates
    # against the old interface list and rejects the rule with a message
    # that sounds like the group does not exist.
    msg = str(ctx.get("cli_error") or "")
    if "not in list" not in msg or not ctx.get("step", "").lower().startswith("rule"):
        return ""
    # A VLAN is the common case and it needs a different answer. The push
    # DOES create the VLAN (interfaces/vlan_settings), but that only makes it
    # a virtual device - a filter rule may only name an ASSIGNED interface
    # (lan / wan / optN) or an interface group, and assignment lives under
    # Interfaces > Assignments, which has no API. So the rule is unpushable
    # until a human assigns the VLAN, and saying "reconfigure the group"
    # would send the operator somewhere that cannot help.
    if _VLANISH_RE.search(msg):
        return (": this is a VLAN. The push created it, but a VLAN is only a "
                "virtual device until it is ASSIGNED an interface (lan / wan / "
                "optN), and assignment has no API. Assign it under Interfaces > "
                "Assignments on the firewall, then push again: a rule can only "
                "name an assigned interface or an interface group")
    return (": the interface or group named here is not applied on the "
            "target yet. Interface groups need firewall/group/reconfigure "
            "before a rule may reference them")


# "Option [opt1_200] not in list." / [wan_100] - a parent interface name
# followed by a VLAN tag is what a migrated subinterface folds to.
_VLANISH_RE = re.compile(r"\[[A-Za-z]+\d*_\d{1,4}\]")


def _hint_endpoint_missing(ctx: dict) -> str:
    if ctx.get("status_code") == 404 or "Endpoint not found" in str(
            ctx.get("cli_error") or ""):
        return (": this OPNsense version does not offer that API. Port "
                "forwards in particular have no API before the DNat "
                "controller ships")
    return ""


def _hint_auth(ctx: dict) -> str:
    if ctx.get("status_code") == 401:
        return (": the key/secret pair was rejected. Note the SECRET goes in "
                "the API-key field and the key id into the device config")
    return ""


_ERROR_HINTS = [
    _hint_group_not_applied,
    _hint_endpoint_missing,
    _hint_auth,
]
