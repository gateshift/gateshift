# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1
"""Manager discovery (docs/MANAGER_DISCOVERY_PLAN.md).

The Community Edition connects a central manager with the credentials the
operator types, reads its structure and shows the scope tree with counts:
Panorama (device groups, templates, template stacks, managed firewalls),
FortiManager and FortiManager Cloud (ADOMs, policy packages, devices), a
Check Point management (a SmartCenter or Smart-1 Cloud as one context, an
MDS per domain: packages, gateways) and Strata Cloud Manager (folders,
snippets, devices). Nothing is stored: the credentials travel in the one
request, the readers log out where the API has a session, no row and no
log line come out of a discovery. Importing, curating and pushing the
scopes is the Enterprise Edition, which reads the same managers with its
own readers; the transports here (the FortiManager JSON-RPC session, the
FortiManager Cloud login, the Strata Cloud Manager OAuth client) are the
ones it imports.

Every reader returns one shape:

    {"manager":   {"kind", "label", "name", "version", "model"},
     "nodes":     [{"type", "name", "parent", "counts": {rules, objects, devices}, "members"}],
     "firewalls": [{"name", "serial", "model", "version", "state", "scope"}],
     "skipped":   ["..."],         # what the reader left out, in words
     "truncated": ["..."]}         # bounds hit (MAX_DOMAINS and the like)

The calls are bounded (section 3, M5 of the plan): a manager with hundreds
of domains or folders answers within the dialog's patience, and the panel
says what was not read.
"""
from __future__ import annotations

import base64
import json
import re
import time
import xml.etree.ElementTree as ET

import requests
import urllib3

from deploy.base import management_host
from deploy import _forti_common as _forti

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_CONNECT_TIMEOUT = 5
_READ_TIMEOUT = 60

# the bounds (one manager, one dialog)
MAX_DOMAINS = 50          # Check Point domains logged into
MAX_ADOMS = 50            # FortiManager ADOMs read
MAX_PACKAGES = 100        # packages per context, policy packages per ADOM
MAX_FOLDERS = 100         # Strata Cloud Manager folders counted
MAX_SNIPPETS = 50         # Strata Cloud Manager snippets counted
MAX_FIREWALLS = 500       # firewalls listed

KINDS = {
    "panorama":     "Panorama",
    "fortimanager": "FortiManager",
    "fmgcloud":     "FortiManager Cloud",
    "checkpoint":   "Check Point management",
    "scm":          "Strata Cloud Manager",
}


class DiscoveryError(RuntimeError):
    """The sentence the panel shows. Never carries a credential."""


def _manager(kind: str, name: str = "", version: str = "", model: str = "") -> dict:
    return {"kind": kind, "label": KINDS.get(kind, kind), "name": name or "",
            "version": version or "", "model": model or ""}


def _node(ntype: str, name: str, parent: str | None = None, members: list | None = None,
          **counts) -> dict:
    return {"type": ntype, "name": name, "parent": parent,
            "counts": {k: int(v) for k, v in counts.items() if v is not None},
            "members": list(members) if members else []}


def _firewall(name: str, serial: str = "", model: str = "", version: str = "",
              state: str = "", scope: str = "") -> dict:
    return {"name": name or serial or "?", "serial": serial or "", "model": model or "",
            "version": version or "", "state": state or "", "scope": scope or ""}


def _result(manager: dict, nodes: list, firewalls: list, skipped=None, truncated=None) -> dict:
    return {"ok": True, "manager": manager, "nodes": nodes,
            "firewalls": firewalls[:MAX_FIREWALLS], "skipped": list(skipped or []),
            "truncated": list(truncated or [])
            + ([f"{len(firewalls) - MAX_FIREWALLS} more firewalls"] if len(firewalls) > MAX_FIREWALLS else [])}


def _host_port(text: str, default_port: int = 443) -> tuple[str, int]:
    """'host' or 'host:port' as the operator types it, scheme and path
    stripped. An IPv6 literal is refused by management_host."""
    s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", (text or "").strip(), flags=re.I)
    s = s.split("/", 1)[0]
    if s.startswith("["):
        host, _, rest = s[1:].partition("]")
        port_text = rest.lstrip(":")
    elif s.count(":") > 1:
        host, port_text = s, ""
    else:
        host, _, port_text = s.partition(":")
    port = int(port_text) if port_text.isdigit() else default_port
    return host.strip(), port


# ── Panorama ──────────────────────────────────────────────────────────────

_PANO_DEV = "/config/devices/entry[@name='localhost.localdomain']"


def _pano_transport(host: str, api_key: str, port: int):
    base = f"https://{host}:{port}/api/"
    hdr = {"X-PAN-KEY": api_key}

    def _call(params: dict) -> ET.Element:
        try:
            r = requests.get(base, params=params, headers=hdr, verify=False,
                             timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT))
        except requests.RequestException as exc:
            raise DiscoveryError(f"Panorama at {host} did not answer: {exc.__class__.__name__}")
        try:
            root = ET.fromstring(r.text)
        except ET.ParseError:
            raise DiscoveryError(f"Panorama at {host} answered HTTP {r.status_code} without XML")
        if root.get("status") != "success":
            msg = root.findtext(".//msg") or root.findtext(".//line") or f"HTTP {r.status_code}"
            raise DiscoveryError(f"Panorama at {host} refused the call: {msg}")
        return root

    def _op(cmd: str) -> ET.Element:
        return _call({"type": "op", "cmd": cmd})

    def _get(xpath: str) -> ET.Element:
        return _call({"type": "config", "action": "get", "xpath": xpath})

    return _op, _get


def discover_panorama(host_text: str, api_key: str, *, _op=None, _get=None) -> dict:
    """Shared, the device groups with their parents and rule counts, the
    templates and template stacks, the managed firewalls."""
    host, port = _host_port(host_text)
    host = management_host(host, "Panorama")
    if not api_key:
        raise DiscoveryError("Panorama needs an API key")
    if _op is None or _get is None:
        _op, _get = _pano_transport(host, api_key, port)

    info = _op("<show><system><info></info></system></show>")
    manager = _manager("panorama", info.findtext(".//system/hostname") or host,
                       info.findtext(".//system/sw-version") or "",
                       info.findtext(".//system/model") or "")

    parents: dict[str, str | None] = {}

    def _walk(el, parent):
        for dg in el.findall("dg"):
            n = dg.get("name")
            if n:
                parents[n] = parent
                _walk(dg, n)

    hier = _op("<show><dg-hierarchy></dg-hierarchy></show>").find(".//dg-hierarchy")
    if hier is not None:
        _walk(hier, None)

    def _rules(el) -> int:
        return (len(el.findall("pre-rulebase/security/rules/entry"))
                + len(el.findall("post-rulebase/security/rules/entry")))

    def _objects(el) -> int:
        return sum(len(el.findall(f"{k}/entry"))
                   for k in ("address", "address-group", "service", "service-group"))

    nodes: list = []
    shared = _get("/config/shared").find(".//shared")
    if shared is not None:
        nodes.append(_node("shared", "shared", None, rules=_rules(shared), objects=_objects(shared)))
    else:
        nodes.append(_node("shared", "shared", None))

    serial_scope: dict[str, str] = {}
    dgc = _get(f"{_PANO_DEV}/device-group").find(".//device-group")
    for e in (dgc.findall("entry") if dgc is not None else []):
        n = e.get("name")
        if not n:
            continue
        serials = [d.get("name") for d in e.findall("devices/entry") if d.get("name")]
        for s in serials:
            serial_scope.setdefault(s, n)
        nodes.append(_node("device-group", n, parents.get(n) or "shared",
                           rules=_rules(e), objects=_objects(e), devices=len(serials)))

    tc = _get(f"{_PANO_DEV}/template").find(".//template")
    for e in (tc.findall("entry") if tc is not None else []):
        if e.get("name"):
            nodes.append(_node("template", e.get("name"), None))
    sc = _get(f"{_PANO_DEV}/template-stack").find(".//template-stack")
    for e in (sc.findall("entry") if sc is not None else []):
        n = e.get("name")
        if not n:
            continue
        members = [m.text.strip() for m in e.findall("templates/member") if (m.text or "").strip()]
        serials = [d.get("name") for d in e.findall("devices/entry") if d.get("name")]
        nodes.append(_node("template-stack", n, None, members, devices=len(serials)))

    firewalls: list = []
    devs = _op("<show><devices><all></all></devices></show>").find(".//devices")
    for e in (devs.findall("entry") if devs is not None else []):
        serial = e.get("name") or e.findtext("serial") or ""
        connected = (e.findtext("connected") or "").strip().lower()
        firewalls.append(_firewall(e.findtext("hostname") or serial, serial,
                                   e.findtext("model") or "", e.findtext("sw-version") or "",
                                   "connected" if connected == "yes" else "disconnected",
                                   serial_scope.get(serial, "")))
    return _result(manager, nodes, firewalls)


# ── FortiManager and FortiManager Cloud ───────────────────────────────────

def _fmg_pkg_flat(items, prefix: str = "") -> list[tuple[str, str, list]]:
    """(name, oid, targets) of every policy package, folders flattened with
    their path, as /pm/pkg/adom/<adom> lists them."""
    out: list = []
    for p in items or []:
        if not isinstance(p, dict) or not p.get("name"):
            continue
        name = f"{prefix}{p['name']}"
        if (p.get("type") or "pkg") == "folder":
            out.extend(_fmg_pkg_flat(p.get("subobj") or [], f"{name}/"))
            continue
        targets = [f"{m.get('name')}" + (f"/{m['vdom']}" if m.get("vdom") else "")
                   for m in (p.get("scope member") or []) if isinstance(m, dict) and m.get("name")]
        out.append((name, str(p.get("oid") or ""), targets))
    return out


def _discover_fmg(kind: str, host: str, auth, port: int, _get) -> dict:
    status = _get("/sys/status") or {}
    version = str(status.get("Version") or "").split(" ")[0] if isinstance(status, dict) else ""
    manager = _manager(kind, (status.get("Hostname") if isinstance(status, dict) else "") or host,
                       version, (status.get("Platform Type") if isinstance(status, dict) else "") or "")
    nodes: list = []
    firewalls: list = []
    truncated: list = []
    g_objs = _get("/pm/config/global/obj/firewall/address", {"fields": ["name"]}) or []
    nodes.append(_node("global", "global", None, objects=len(g_objs) if isinstance(g_objs, list) else 0))
    adoms = [a for a in (_get("/dvmdb/adom") or []) if isinstance(a, dict) and a.get("name")
             and a.get("name") != "global"]
    if len(adoms) > MAX_ADOMS:
        truncated.append(f"{len(adoms) - MAX_ADOMS} more ADOMs")
        adoms = adoms[:MAX_ADOMS]
    for a in adoms:
        adom = a["name"]
        objs = _get(f"/pm/config/adom/{adom}/obj/firewall/address", {"fields": ["name"]}) or []
        devs = [d for d in (_get(f"/dvmdb/adom/{adom}/device") or []) if isinstance(d, dict) and d.get("name")]
        nodes.append(_node("adom", adom, "global",
                           objects=len(objs) if isinstance(objs, list) else 0, devices=len(devs)))
        for d in devs:
            conn = d.get("conn_status")
            firewalls.append(_firewall(d.get("name"), str(d.get("sn") or ""), str(d.get("platform_str") or ""),
                                       str(d.get("os_ver") or "") + (f".{d['mr']}" if d.get("mr") is not None else ""),
                                       "connected" if conn in (1, "1", "up") else "disconnected", adom))
        pkgs = _fmg_pkg_flat(_get(f"/pm/pkg/adom/{adom}") or [])
        if len(pkgs) > MAX_PACKAGES:
            truncated.append(f"{len(pkgs) - MAX_PACKAGES} more packages in {adom}")
            pkgs = pkgs[:MAX_PACKAGES]
        for name, _oid, targets in pkgs:
            rules = _get(f"/pm/config/adom/{adom}/pkg/{name}/firewall/policy", {"fields": ["policyid"]}) or []
            nodes.append(_node("package", f"{adom}/{name}", adom, targets,
                               rules=len(rules) if isinstance(rules, list) else 0))
    return _result(manager, nodes, firewalls, truncated=truncated)


def _fmg_getter(host: str, auth, port: int):
    def _get(url: str, extra: dict | None = None):
        ok, res, err = _forti.fmg_rpc(host, auth, "get", url, port=port, extra=extra)
        if not ok:
            # a missing table answers with an error code too (-3 object does
            # not exist): an empty list, not a failed discovery
            if any(x in (err or "") for x in ("-3:", "-6:")):
                return []
            raise DiscoveryError(f"FortiManager at {host} refused {url}: {err}")
        return res.get("data")
    return _get


def discover_fortimanager(host_text: str, api_key: str, *, _get=None) -> dict:
    """An on-prem FortiManager through its API token (Bearer)."""
    host, port = _host_port(host_text)
    host = management_host(host, "FortiManager")
    if not api_key:
        raise DiscoveryError("FortiManager needs an API token")
    if _get is None:
        _get = _fmg_getter(host, api_key, port)
    return _discover_fmg("fortimanager", host, api_key, port, _get)


def discover_fmg_cloud(host_text: str, api_id: str, password: str, *, _get=None) -> dict:
    """A FortiManager Cloud instance (https://<customer id>.<region>.fortimanager.forticloud.com)
    through a FortiCloud IAM API user; the session is closed at the end."""
    host, port = _host_port(host_text)
    if not host.endswith(".fortimanager.forticloud.com"):
        raise DiscoveryError("FortiManager Cloud is reached at <customer id>.<region>.fortimanager.forticloud.com")
    if not (api_id and password):
        raise DiscoveryError("FortiManager Cloud needs the IAM API user's id and password")
    auth = _forti.FmgCloudAuth(host, api_id, password)
    own = _get is None
    if own:
        _get = _fmg_getter(host, auth, port)
    try:
        return _discover_fmg("fmgcloud", host, auth, port, _get)
    finally:
        if own:
            _forti.fmg_logout(host, auth, port=port)


# ── Check Point management (SmartCenter, Smart-1 Cloud, MDS) ──────────────

def _cp_transport(address: str):
    from deploy.checkpoint import split_mgmt_address, _post_with_retry
    host, port, path = split_mgmt_address(address)
    host = management_host(host, "Check Point management")
    port = port or 443
    base = f"https://{host}:{port}/{path}/web_api" if path else f"https://{host}:{port}/web_api"

    def _api(cmd: str, payload: dict | None = None, sid: str | None = None):
        hdr = {"Content-Type": "application/json"}
        if sid:
            hdr["X-chkp-sid"] = sid
        try:
            r = _post_with_retry(f"{base}/{cmd}", headers=hdr, payload=payload or {}, timeout=60)
        except requests.RequestException as exc:
            raise DiscoveryError(f"Check Point management at {host} did not answer: {exc.__class__.__name__}")
        try:
            return r.status_code, (r.json() if r.text else {})
        except ValueError:
            raise DiscoveryError(f"Check Point management at {host} answered {cmd} with HTTP "
                                 f"{r.status_code} and no JSON (is the API user published, does the "
                                 "API server accept this client?)")
    return _api, host


def _cp_login(_api, api_key: str, domain: str | None = None) -> str:
    for attempt in range(4):
        payload = {"api-key": api_key}
        if domain:
            payload["domain"] = domain
        code, j = _api("login", payload)
        if code == 200 and j.get("sid"):
            return j["sid"]
        if j.get("code") == "err_too_many_requests":
            time.sleep(3 * (attempt + 1))
            continue
        raise DiscoveryError("Check Point management refused the login"
                             + (f" into domain {domain}" if domain else "")
                             + f": {j.get('message') or j.get('code') or f'HTTP {code}'}")
    raise DiscoveryError("Check Point management is rate-limiting logins, try again in a minute")


def _cp_total(_api, sid: str, cmd: str, payload: dict | None = None) -> int:
    code, j = _api(cmd, {**(payload or {}), "limit": 1, "details-level": "standard"}, sid)
    if code != 200:
        return 0
    return int(j.get("total") or len(j.get("objects") or j.get("rulebase") or []))


def _cp_context(_api, api_key: str, domain: str | None, ctx_name: str, ctx_type: str,
                parent: str | None, nodes: list, firewalls: list, truncated: list) -> None:
    sid = _cp_login(_api, api_key, domain)
    try:
        objects = sum(_cp_total(_api, sid, c) for c in ("show-hosts", "show-networks", "show-groups"))
        # 'full': the standard level carries neither the gateway's policy nor
        # a package's access layers and targets (measured on R81.20)
        code, g = _api("show-gateways-and-servers", {"limit": 100, "details-level": "full"}, sid)
        gws = [o for o in (g.get("objects") or []) if isinstance(o, dict) and o.get("name")] if code == 200 else []
        label = ctx_name
        devices = 0
        for o in gws:
            t = (o.get("type") or "").lower()
            if ctx_type == "management" and ("management" in t or t == "checkpoint-host"):
                label = o["name"]
                continue
            if t in ("simple-gateway", "simple-cluster", "cluster-member", "cpmiclustermember",
                     "cpmigatewaycluster", "cpmivsclusternetobj", "cpmivsxclusternetobj", "cpmivsnetobj"):
                devices += 1
                pol = o.get("policy") or {}
                firewalls.append(_firewall(o["name"], "", t, str(o.get("version") or ""),
                                           ("policy " + str(pol.get("access-policy-name")))
                                           if pol.get("access-policy-installed") else "no policy installed",
                                           ctx_name))
        nodes.append(_node(ctx_type, label, parent, objects=objects, devices=devices))
        code, p = _api("show-packages", {"limit": MAX_PACKAGES, "details-level": "full"}, sid)
        pkgs = [o for o in (p.get("packages") or []) if isinstance(o, dict) and o.get("name")] if code == 200 else []
        if int(p.get("total") or 0) > MAX_PACKAGES:
            truncated.append(f"{int(p['total']) - MAX_PACKAGES} more packages in {ctx_name}")
        for pk in pkgs:
            rules = 0
            for layer in (pk.get("access-layers") or []):
                ln = layer.get("name") if isinstance(layer, dict) else layer
                if ln:
                    rules += _cp_total(_api, sid, "show-access-rulebase", {"name": ln})
            targets = pk.get("installation-targets")
            members = ([t.get("name") for t in targets if isinstance(t, dict) and t.get("name")]
                       if isinstance(targets, list) else (["all gateways"] if targets == "all" else []))
            nodes.append(_node("package", f"{ctx_name}/{pk['name']}", label, members, rules=rules))
    finally:
        try:
            _api("logout", {}, sid)
        except Exception:
            pass


def discover_checkpoint(address: str, api_key: str, *, _api=None) -> dict:
    """A SmartCenter or Smart-1 Cloud tenant as one management context, an
    MDS as Global plus one context per domain (at most MAX_DOMAINS)."""
    if not (address or "").strip():
        raise DiscoveryError("Check Point management needs its address")
    if not api_key:
        raise DiscoveryError("Check Point management needs an API key")
    host = address
    if _api is None:
        _api, host = _cp_transport(address)
    sid = _cp_login(_api, api_key)
    try:
        code, d = _api("show-domains", {"limit": MAX_DOMAINS, "details-level": "standard"}, sid)
        domains = [o.get("name") for o in (d.get("objects") or []) if isinstance(o, dict) and o.get("name")] \
            if code == 200 else []
        total_domains = int(d.get("total") or len(domains)) if code == 200 else 0
        code, info = _api("show-api-versions", {}, sid)
        version = str(info.get("current-version") or "") if code == 200 else ""
    finally:
        try:
            _api("logout", {}, sid)
        except Exception:
            pass
    nodes: list = []
    firewalls: list = []
    truncated: list = []
    if domains:
        manager = _manager("checkpoint", f"MDS {host}", f"API {version}" if version else "", "Multi-Domain")
        nodes.append(_node("global", "Global", None))
        if total_domains > MAX_DOMAINS:
            truncated.append(f"{total_domains - MAX_DOMAINS} more domains")
        for dom in domains[:MAX_DOMAINS]:
            _cp_context(_api, api_key, dom, dom, "domain", "Global", nodes, firewalls, truncated)
    else:
        manager = _manager("checkpoint", host, f"API {version}" if version else "", "SmartCenter")
        _cp_context(_api, api_key, None, host, "management", None, nodes, firewalls, truncated)
        for n in nodes:
            if n["type"] == "management":
                manager["name"] = n["name"]
    return _result(manager, nodes, firewalls, truncated=truncated)


# ── Strata Cloud Manager: the OAuth client and the tenant structure ───────
# (moved here from the Enterprise module scm.py, which imports them back:
# the reader of the tenant's CONTENT stays there)

SCM_AUTH_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
SCM_API_HOST = "api.strata.paloaltonetworks.com"
SCM_API_BASE = f"https://{SCM_API_HOST}/config"
_PAGE_LIMIT = 200                      # the API's default and documented page size
_TOKEN_MARGIN = 120.0
_SCM_TOKENS: dict[tuple[str, str], tuple[str, float]] = {}   # (client_id, tsg_id) -> (token, exp)

# Folder trees that are Prisma Access, not firewalls (PANW docs "Folder
# Management"): skipped and declared. A root folder of type `cloud` counts
# as well, the NGFW tree's folders are `container` and `on-prem`.
PRISMA_ACCESS_ROOTS = {"prisma access", "mobile users", "remote networks",
                       "service connections", "mobile users container",
                       "mobile users explicit proxy"}


class ScmAuth:
    """OAuth2 client credentials of a service account, scoped to a tenant
    service group (pan.dev "Getting Started"): basic auth with client id
    and secret, grant_type client_credentials, scope tsg_id:<id>. The JWT
    is cached until shortly before its exp claim."""

    def __init__(self, tsg_id: str, client_id: str, client_secret: str):
        self.tsg_id, self.client_id, self.client_secret = tsg_id, client_id, client_secret

    def token(self, *, fresh: bool = False) -> str:
        if not (self.tsg_id and self.client_id and self.client_secret):
            raise RuntimeError("Strata Cloud Manager needs the TSG id, the client id and the client secret")
        key = (self.client_id, self.tsg_id)
        cached = _SCM_TOKENS.get(key)
        if cached and not fresh and cached[1] > time.time():
            return cached[0]
        resp = requests.post(SCM_AUTH_URL, auth=(self.client_id, self.client_secret),
                             data={"grant_type": "client_credentials", "scope": f"tsg_id:{self.tsg_id}"},
                             headers={"Content-Type": "application/x-www-form-urlencoded"},
                             timeout=(_CONNECT_TIMEOUT, 30))
        try:
            body = resp.json() or {}
        except ValueError:
            body = {}
        tok = body.get("access_token") if resp.status_code == 200 else None
        if not tok:
            msg = body.get("error_description") or body.get("error") or f"HTTP {resp.status_code}"
            raise RuntimeError(f"Strata Cloud Manager login refused: {msg}")
        exp = _jwt_exp(tok) or (time.time() + float(body.get("expires_in") or 900))
        _SCM_TOKENS[key] = (tok, exp - _TOKEN_MARGIN)
        return tok

    def __repr__(self) -> str:   # never the secret
        return f"ScmAuth(tsg {self.tsg_id}, client {self.client_id})"


def _jwt_exp(token: str) -> float | None:
    """The exp claim of a JWT, or None when the token is not one."""
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload.encode()).decode())
        return float(claims["exp"])
    except Exception:
        return None


class ScmClient:
    """Reads the configuration API. One scope parameter per call (folder,
    snippet or device), pages of 200, every page cached per call signature
    so the folder-chain walks of many devices do not re-read a folder."""

    def __init__(self, auth: ScmAuth):
        self.auth = auth
        self._cache: dict = {}

    # the HTTP seam (tests replace it)
    def _page(self, url: str, params: dict) -> dict:
        for attempt in range(4):
            r = requests.get(url, params=params,
                             headers={"Authorization": f"Bearer {self.auth.token()}",
                                      "Accept": "application/json"},
                             timeout=(_CONNECT_TIMEOUT, 60))
            if r.status_code == 429 and attempt < 3:
                time.sleep(2.0 * (attempt + 1))
                continue
            if r.status_code == 401 and attempt == 0:
                self.auth.token(fresh=True)
                continue
            if r.status_code != 200:
                try:
                    body = r.json() or {}
                except ValueError:
                    body = {}
                detail = body.get("_errors") or body.get("message") or body.get("error") or r.text[:200]
                raise RuntimeError(f"SCM {url.split('/v1', 1)[-1]} answered HTTP {r.status_code}: {detail}")
            return r.json() or {}
        raise RuntimeError(f"SCM {url} rate-limited (HTTP 429) four times")

    def get_all(self, area: str, path: str, scope: tuple | None = None, **extra) -> list[dict]:
        """Every item of a list endpoint. `scope` is ("folder" | "snippet" |
        "device", name); extra query parameters such as position=pre."""
        key = (area, path, scope, tuple(sorted(extra.items())))
        if key in self._cache:
            return self._cache[key]
        url = f"{SCM_API_BASE}/{area}/v1{path}"
        out: list[dict] = []
        offset = 0
        while True:
            params: dict = {"limit": _PAGE_LIMIT, "offset": offset}
            if scope:
                params[scope[0]] = scope[1]
            params.update(extra)
            body = self._page(url, params)
            data = body.get("data") if isinstance(body, dict) else body
            if not isinstance(data, list):
                data = []
            out.extend(d for d in data if isinstance(d, dict))
            if len(data) < _PAGE_LIMIT:
                break
            offset += _PAGE_LIMIT
            if offset > 200000:
                break
        self._cache[key] = out
        return out

    def count(self, area: str, path: str, scope: tuple | None = None, **extra) -> int:
        """How many items a list endpoint holds: the `total` of a one-item
        page (the discovery's counts), the page's length when the answer
        carries no total."""
        url = f"{SCM_API_BASE}/{area}/v1{path}"
        params: dict = {"limit": 1, "offset": 0}
        if scope:
            params[scope[0]] = scope[1]
        params.update(extra)
        body = self._page(url, params)
        if isinstance(body, dict):
            if body.get("total") is not None:
                return int(body["total"])
            data = body.get("data")
            return len(data) if isinstance(data, list) else 0
        return len(body) if isinstance(body, list) else 0


def _flatten_folders(items: list, parent: str | None = None, out: list | None = None) -> list:
    """The folder list as the API answers it, flat or nested (`children`),
    into one flat list with `parent` filled."""
    out = out if out is not None else []
    for f in items or []:
        if not isinstance(f, dict) or not f.get("name"):
            continue
        row = {k: v for k, v in f.items() if k != "children"}
        if not row.get("parent") and parent:
            row["parent"] = parent
        out.append(row)
        if f.get("children"):
            _flatten_folders(f["children"], f["name"], out)
    return out


def _is_prisma_root(folder: dict) -> bool:
    return ((folder.get("name") or "").strip().lower() in PRISMA_ACCESS_ROOTS
            or (folder.get("type") or "").lower() == "cloud")


def read_tenant(client: ScmClient) -> dict:
    """The tenant's structure: NGFW folders (tree order, root first) with
    their parent and snippet associations, snippets, devices with their
    folder, and what was skipped. Device containers (folders of type
    on-prem that stand for one device) are not folders here, the device
    list carries them."""
    raw = _flatten_folders(client.get_all("setup", "/folders"))
    by_name = {f["name"]: f for f in raw}

    # subtree membership: walk parents up to the root
    def root_of(f: dict) -> dict:
        seen = set()
        cur = f
        while cur.get("parent") and cur["parent"] in by_name and cur["name"] not in seen:
            seen.add(cur["name"])
            cur = by_name[cur["parent"]]
        return cur

    skipped_prisma: list[str] = []
    folders: list[dict] = []
    device_containers: dict[str, dict] = {}
    for f in raw:
        if _is_prisma_root(root_of(f)):
            skipped_prisma.append(f["name"])
            continue
        if (f.get("type") or "").lower() == "on-prem" and (f.get("device_only") or f.get("serial_number")):
            device_containers[f["name"]] = f
            continue
        folders.append(f)
    # tree order: roots first, then children by level
    ordered: list[dict] = []
    level = [f for f in folders if not f.get("parent") or f["parent"] not in {x["name"] for x in folders}]
    seen_names: set = set()
    while level:
        nxt: list[dict] = []
        for f in sorted(level, key=lambda x: x["name"]):
            if f["name"] in seen_names:
                continue
            seen_names.add(f["name"])
            ordered.append(f)
            nxt.extend(c for c in folders if c.get("parent") == f["name"])
        level = nxt
    roots = [f["name"] for f in ordered if not f.get("parent") or f["parent"] not in seen_names]
    snippets = [s for s in client.get_all("setup", "/snippets") if isinstance(s, dict) and s.get("name")]
    devices = []
    for d in client.get_all("setup", "/devices"):
        if not isinstance(d, dict) or not (d.get("name") or d.get("id")):
            continue
        name = d.get("name") or d.get("id")
        folder = d.get("folder") or (device_containers.get(name) or {}).get("parent")
        if folder and folder in by_name and _is_prisma_root(by_name[folder]):
            continue
        devices.append({"name": name, "serial": d.get("id") or d.get("serial_number") or "",
                        "folder": folder, "ip": d.get("ip_address") or "",
                        "hostname": d.get("hostname") or "", "model": d.get("model") or "",
                        "software": d.get("software_version") or "",
                        "connected": bool(d.get("is_connected")),
                        "ha_state": d.get("ha_state") or "", "ha_peer": d.get("ha_peer_serial") or "",
                        "snippets": [s for s in (d.get("snippets") or []) if isinstance(s, str)]})
    return {"folders": ordered, "roots": roots, "snippets": snippets, "devices": devices,
            "skipped_prisma_folders": skipped_prisma, "device_containers": sorted(device_containers)}


def tenant_summary(client: ScmClient) -> dict:
    """What the Enterprise add dialog's connection test reports."""
    t = read_tenant(client)
    return {"folders": [f["name"] for f in t["folders"]], "roots": t["roots"],
            "snippets": len(t["snippets"]), "devices": len(t["devices"]),
            "prisma_access_folders": len(t["skipped_prisma_folders"])}


def discover_scm(tsg_id: str, client_id: str, client_secret: str, *, client=None) -> dict:
    """The NGFW folder tree, the snippets and the devices of a tenant with
    rule, object and device counts (folders and snippets bounded)."""
    if client is None:
        if not (tsg_id and client_id and client_secret):
            raise DiscoveryError("Strata Cloud Manager needs the TSG id, the client id and the client secret")
        client = ScmClient(ScmAuth(tsg_id, client_id, client_secret))
    try:
        t = read_tenant(client)
    except RuntimeError as exc:
        raise DiscoveryError(str(exc))
    manager = _manager("scm", f"tenant {tsg_id}" if tsg_id else "tenant", "", "")
    nodes: list = []
    truncated: list = []
    devices_in = {}
    for d in t["devices"]:
        devices_in[d.get("folder") or ""] = devices_in.get(d.get("folder") or "", 0) + 1

    def _rules(scope: tuple) -> int:
        return sum(client.count("security", "/security-rules", scope, position=pos) for pos in ("pre", "post"))

    folders = t["folders"]
    if len(folders) > MAX_FOLDERS:
        truncated.append(f"{len(folders) - MAX_FOLDERS} more folders")
    for f in folders[:MAX_FOLDERS]:
        scope = ("folder", f["name"])
        nodes.append(_node("folder", f["name"], f.get("parent"),
                           [s for s in (f.get("snippets") or []) if isinstance(s, str)],
                           rules=_rules(scope), objects=client.count("objects", "/addresses", scope),
                           devices=devices_in.get(f["name"], 0)))
    snippets = t["snippets"]
    if len(snippets) > MAX_SNIPPETS:
        truncated.append(f"{len(snippets) - MAX_SNIPPETS} more snippets")
    for s in snippets[:MAX_SNIPPETS]:
        scope = ("snippet", s["name"])
        nodes.append(_node("snippet", s["name"], None, None,
                           rules=_rules(scope), objects=client.count("objects", "/addresses", scope)))
    firewalls = [_firewall(d["name"], d.get("serial") or "", d.get("model") or "", d.get("software") or "",
                           "connected" if d.get("connected") else "disconnected", d.get("folder") or "")
                 for d in t["devices"]]
    skipped = []
    if t["skipped_prisma_folders"]:
        skipped.append(f"{len(t['skipped_prisma_folders'])} Prisma Access folders (not firewalls)")
    return _result(manager, nodes, firewalls, skipped=skipped, truncated=truncated)


# ── the dispatch the route uses ───────────────────────────────────────────

def discover(kind: str, form: dict) -> dict:
    """The add dialog's request: `kind` names the manager, `form` carries
    the fields of its block. Raises DiscoveryError with the sentence to
    show; never echoes a credential."""
    g = lambda k: str(form.get(k) or "").strip()   # noqa: E731
    if kind == "panorama":
        return discover_panorama(g("host"), g("api_key"))
    if kind == "fortimanager":
        return discover_fortimanager(g("host"), g("api_key"))
    if kind == "fmgcloud":
        return discover_fmg_cloud(g("host"), g("api_id"), g("password"))
    if kind == "checkpoint":
        return discover_checkpoint(g("host"), g("api_key"))
    if kind == "scm":
        return discover_scm(g("tsg_id"), g("client_id"), g("client_secret"))
    raise DiscoveryError(f"no such manager kind: {kind}")
