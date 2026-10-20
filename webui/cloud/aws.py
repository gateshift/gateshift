# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""Amazon Web Services as a SOURCE: security groups and network ACLs and
the VPC network they attach to, read from an account (EC2 Query API with
SigV4 signing, no SDK) or from an uploaded bundle of the same JSON,
parsed into the shapes the Gateshift import and collect handlers store.

Model (docs/CLOUD_SOURCES_PLAN.md, D2/D3): one device row = one account
with a region list (optionally filtered to VPC ids). Zones are
topological: every subnet is a zone and a pseudo-interface without an
address. Security groups and managed prefix lists are address groups
whose members are resolved at import time (the private addresses of the
network interfaces that carry the group, the entries of the list); they
are never zones.

The ruleset is ONE ordered rulebase, in three blocks:

1. Network ACL entries, per ACL by rule number. An ACL is stateless and
   evaluated at the subnet boundary before (inbound) or after (outbound)
   the security groups, and both layers must allow. A first-match
   rulebase can express the ACL's denies faithfully (a deny there wins
   regardless of the groups), so explicit deny entries are imported as
   active rules at the top. Its allow entries are only a necessary
   condition, so they are imported DISABLED with the reason, and the
   ephemeral-range allows a stateless ruleset needs for return traffic
   are flagged as such. The closing '*' deny of each ACL is marked as a
   default rule and imported disabled as well (the implicit deny at the
   end of the rulebase carries that meaning for the whole account).
2. Security-group rules, group by group (sorted by name), inbound then
   outbound. Groups allow only and the groups of one interface form a
   union, so their order does not matter and ONE implicit deny closes
   the rulebase instead of one per group (a per-group deny would shadow
   the allows of a second group on the same interface).
3. The implicit deny, marked `aws-sg-implicit-deny`.

The bundle is a dict keyed like the AWS CLI output of the describe
commands: Vpcs, Subnets, RouteTables, SecurityGroups, NetworkAcls,
NetworkInterfaces, PrefixLists, plus PrefixListEntries (prefix list id to
its entries). The fetcher produces it from the EC2 XML answers; an upload
carries the same keys.

Nothing here talks to the database or to main.py; `register()` in the
package wires the two entry points into the import/collect registries.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

from ._common import literal_ref, member_objects, port_literal, service_ref

API_VERSION = "2016-11-15"      # EC2
STS_VERSION = "2011-06-15"

# Resource lists the bundle carries, in the order the fetcher reads them.
# The Network Firewall lists (P4b) are optional in an upload and hold the
# describe outputs as the CLI prints them: NetworkFirewalls = describe-
# firewall, NetworkFirewallPolicies = describe-firewall-policy,
# NetworkFirewallRuleGroups = describe-rule-group.
BUNDLE_KEYS = ("Vpcs", "Subnets", "RouteTables", "SecurityGroups", "NetworkAcls",
               "NetworkInterfaces", "PrefixLists", "NetworkFirewalls", "NetworkFirewallPolicies",
               "NetworkFirewallRuleGroups")
NFW_TARGET = "NetworkFirewall_20201112"

# EC2 Query API verbs that read each list (and the XML element that holds it).
_DESCRIBE = {
    "Vpcs": "DescribeVpcs", "Subnets": "DescribeSubnets", "RouteTables": "DescribeRouteTables",
    "SecurityGroups": "DescribeSecurityGroups", "NetworkAcls": "DescribeNetworkAcls",
    "NetworkInterfaces": "DescribeNetworkInterfaces", "PrefixLists": "DescribeManagedPrefixLists",
}

# IP protocol numbers with a service-literal name on the targets.
_PROTO_NUM = {"6": "tcp", "17": "udp", "1": "icmp", "50": "esp", "51": "ah", "47": "gre", "132": "sctp"}
_PROTO_NAMES = {"tcp", "udp", "icmp", "esp", "ah", "gre", "sctp"}

_AUTH_CODES = {"AuthFailure", "InvalidClientTokenId", "SignatureDoesNotMatch", "UnauthorizedOperation",
               "AccessDenied", "AccessDeniedException", "ExpiredToken", "IncompleteSignature",
               "InvalidAccessKeyId", "MissingAuthenticationToken", "InvalidSignatureException"}

_NACL_DEFAULT_RULE = 32767


class AwsAuthError(Exception):
    """Keys refused or the account is not readable with them."""


class AwsApiError(RuntimeError):
    """An EC2/STS call answered with an error document."""

    def __init__(self, code: str, message: str, action: str):
        super().__init__(f"AWS {action} failed ({code}): {message}")
        self.code = code
        self.action = action


# ── SigV4 ──────────────────────────────────────────────────────────────

def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sign_request(method: str, host: str, path: str, query: str, headers: dict, payload: bytes,
                 access_key_id: str, secret_access_key: str, region: str, service: str,
                 amz_date: str, session_token: str | None = None) -> dict:
    """AWS Signature Version 4: the request headers with Authorization
    added. `query` is the already canonical query string (empty for the
    Query API, which posts its parameters in the body)."""
    hdrs = {k.lower(): " ".join(str(v).strip().split()) for k, v in (headers or {}).items()}
    hdrs["host"] = host
    hdrs["x-amz-date"] = amz_date
    if session_token:
        hdrs["x-amz-security-token"] = session_token
    signed = ";".join(sorted(hdrs))
    canonical_headers = "".join(f"{k}:{hdrs[k]}\n" for k in sorted(hdrs))
    canonical = "\n".join([method.upper(), path or "/", query or "", canonical_headers, signed,
                           _sha256_hex(payload or b"")])
    date = amz_date[:8]
    scope = f"{date}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, _sha256_hex(canonical.encode("utf-8"))])
    key = _hmac(("AWS4" + secret_access_key).encode("utf-8"), date)
    for part in (region, service, "aws4_request"):
        key = _hmac(key, part)
    signature = hmac.new(key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    hdrs["authorization"] = (f"AWS4-HMAC-SHA256 Credential={access_key_id}/{scope}, "
                             f"SignedHeaders={signed}, Signature={signature}")
    return hdrs


# ── Query API plumbing ─────────────────────────────────────────────────

def flatten_params(params: dict, prefix: str = "") -> dict:
    """Nested dicts/lists to the Query API's dotted, 1-based member names:
    {"Filter": [{"Name": "vpc-id", "Value": ["vpc-1"]}]} becomes
    Filter.1.Name=vpc-id, Filter.1.Value.1=vpc-1."""
    out: dict[str, str] = {}
    for k, v in (params or {}).items():
        key = f"{prefix}{k}"
        if v is None:
            continue
        if isinstance(v, dict):
            out.update(flatten_params(v, key + "."))
        elif isinstance(v, (list, tuple)):
            for i, item in enumerate(v, 1):
                if isinstance(item, dict):
                    out.update(flatten_params(item, f"{key}.{i}."))
                elif item is not None:
                    out[f"{key}.{i}"] = _qstr(item)
        else:
            out[key] = _qstr(v)
    return out


def _qstr(v) -> str:
    if v is True:
        return "true"
    if v is False:
        return "false"
    return str(v)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


# XML element names whose CLI spelling is not just a capitalised first letter.
_RENAME = {
    "securityGroupInfo": "SecurityGroups", "networkAclSet": "NetworkAcls",
    "networkInterfaceSet": "NetworkInterfaces", "vpcSet": "Vpcs", "subnetSet": "Subnets",
    "routeTableSet": "RouteTables", "prefixListSet": "PrefixLists", "entrySet": "Entries",
    "associationSet": "Associations", "routeSet": "Routes", "tagSet": "Tags",
    "groupSet": "Groups", "privateIpAddressesSet": "PrivateIpAddresses",
    "groups": "UserIdGroupPairs", "cidrBlockAssociationSet": "CidrBlockAssociationSet",
    "ipv6CidrBlockAssociationSet": "Ipv6CidrBlockAssociationSet",
    "propagatingVgwSet": "PropagatingVgws", "ipv6AddressesSet": "Ipv6Addresses",
    "securityGroupRuleSet": "SecurityGroupRules",
    # a network ACL's <default> and a security group's <groupDescription>
    # print as IsDefault and Description in the CLI
    "default": "IsDefault", "groupDescription": "Description",
}
# Empty elements that mean an empty list rather than an empty string.
_LIST_TAGS = set(_RENAME) | {"ipPermissions", "ipPermissionsEgress", "ipRanges", "ipv6Ranges",
                             "prefixListIds", "item"}
_INT_TAGS = {"fromPort", "toPort", "ruleNumber", "from", "to", "code", "type", "maxEntries",
             "deviceIndex", "version"}


def xml_to_py(el) -> object:
    """An EC2/STS XML element to the dict/list shape the AWS CLI prints
    (first letter capitalised, `<item>` sequences as lists, true/false and
    the numeric fields typed)."""
    children = list(el)
    tag = _local(el.tag)
    if not children:
        txt = (el.text or "").strip()
        if not txt and (tag in _LIST_TAGS or tag.endswith("Set")):
            return []
        if txt in ("true", "false"):
            return txt == "true"
        if tag in _INT_TAGS and re.fullmatch(r"-?\d+", txt):
            return int(txt)
        return txt
    if all(_local(c.tag) == "item" for c in children):
        return [xml_to_py(c) for c in children]
    out: dict = {}
    for c in children:
        ctag = _local(c.tag)
        key = _RENAME.get(ctag) or (ctag[:1].upper() + ctag[1:])
        out[key] = xml_to_py(c)
    return out


def _error_of(raw: bytes) -> tuple[str, str]:
    try:
        root = ET.fromstring(raw)
        code = root.find(".//{*}Code")
        msg = root.find(".//{*}Message")
        return ((code.text or "").strip() if code is not None else "",
                (msg.text or "").strip() if msg is not None else raw.decode("utf-8", "replace")[:200])
    except ET.ParseError:
        return "", raw.decode("utf-8", "replace")[:200]


def api_call(creds: dict, region: str, action: str, params: dict | None = None,
             service: str = "ec2", version: str = API_VERSION, retries: int = 5) -> dict:
    """One signed Query API call; the answer as a CLI-shaped dict.
    Throttling is retried with backoff, authentication failures raise
    AwsAuthError, every other error document raises AwsApiError."""
    host = f"{service}.{region}.amazonaws.com"
    body_params = {"Action": action, "Version": version}
    body_params.update(flatten_params(params or {}))
    body = urllib.parse.urlencode(sorted(body_params.items()), quote_via=urllib.parse.quote,
                                  safe="-_.~").encode("utf-8")
    raw = b""
    for attempt in range(retries):
        amz_date = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        headers = sign_request("POST", host, "/", "",
                               {"content-type": "application/x-www-form-urlencoded; charset=utf-8"},
                               body, creds["access_key_id"], creds["secret_access_key"], region, service,
                               amz_date, creds.get("session_token"))
        req = urllib.request.Request(f"https://{host}/", data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                raw = resp.read()
            break
        except urllib.error.HTTPError as exc:
            code, msg = _error_of(exc.read())
            if code in _AUTH_CODES:
                raise AwsAuthError(f"AWS refused {action} in {region} ({code}): check the access key id and "
                                   f"secret access key, and that the key may read EC2 (Describe*). {msg}")
            if code in ("RequestLimitExceeded", "Throttling", "ThrottlingException") and attempt < retries - 1:
                time.sleep(1.5 * (2 ** attempt))
                continue
            raise AwsApiError(code or f"HTTP {exc.code}", msg, action)
        except urllib.error.URLError as exc:
            raise RuntimeError(f"AWS endpoint {host} unreachable: {exc.reason}")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        raise RuntimeError(f"AWS {action}: answer is not XML ({exc})")
    out = xml_to_py(root)
    return out if isinstance(out, dict) else {"Value": out}


def nfw_call(creds: dict, region: str, action: str, body: dict | None = None, retries: int = 4) -> dict:
    """One Network Firewall call (JSON protocol, SigV4 service network-firewall)."""
    host = f"network-firewall.{region}.amazonaws.com"
    payload = json.dumps(body or {}).encode("utf-8")
    for attempt in range(retries):
        amz_date = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        headers = sign_request("POST", host, "/", "",
                               {"content-type": "application/x-amz-json-1.0", "x-amz-target": f"{NFW_TARGET}.{action}"},
                               payload, creds["access_key_id"], creds["secret_access_key"], region, "network-firewall",
                               amz_date, creds.get("session_token"))
        req = urllib.request.Request(f"https://{host}/", data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                raw = resp.read()
            return json.loads(raw) if raw.strip() else {}
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")
            try:
                err = json.loads(detail)
                code = str(err.get("__type") or err.get("code") or "").rsplit("#", 1)[-1]
                msg = str(err.get("message") or err.get("Message") or detail)[:300]
            except Exception:
                code, msg = f"HTTP {exc.code}", detail[:300]
            if exc.code == 403 or code in ("AccessDeniedException", "UnrecognizedClientException",
                                           "InvalidSignatureException", "IncompleteSignatureException"):
                raise AwsAuthError(f"AWS refused Network Firewall {action} in {region} ({code}): the key lacks "
                                   f"the network-firewall permission for this call. {msg}")
            if code in ("ThrottlingException", "TooManyRequestsException") and attempt < retries - 1:
                time.sleep(1.5 * (2 ** attempt))
                continue
            raise AwsApiError(code, msg, action)
        except urllib.error.URLError as exc:
            raise RuntimeError(f"AWS endpoint {host} unreachable: {exc.reason}")
    return {}


def nfw_list(creds: dict, region: str, action: str, result_key: str, body: dict | None = None) -> list[dict]:
    items: list[dict] = []
    token = None
    while True:
        b = dict(body or {})
        if token:
            b["NextToken"] = token
        resp = nfw_call(creds, region, action, b)
        items.extend(x for x in (resp.get(result_key) or []) if isinstance(x, dict))
        token = resp.get("NextToken")
        if not token:
            break
    return items


def describe(creds: dict, region: str, action: str, result_key: str, params: dict | None = None) -> list[dict]:
    """A paginated Describe*/Get* call, every page's `result_key` list."""
    items: list[dict] = []
    token = None
    while True:
        p = dict(params or {})
        if token:
            p["NextToken"] = token
        resp = api_call(creds, region, action, p)
        items.extend(x for x in (resp.get(result_key) or []) if isinstance(x, dict))
        token = resp.get("NextToken")
        if not token:
            break
    return items


def caller_identity(creds: dict, region: str) -> dict:
    """STS GetCallerIdentity: the account id and the principal's ARN. The
    first call of a fetch, so bad keys fail here with a clear message."""
    resp = api_call(creds, region, "GetCallerIdentity", service="sts", version=STS_VERSION)
    return resp.get("GetCallerIdentityResult") or {}


# ── Fetch ──────────────────────────────────────────────────────────────

def fetch_bundle(access_key_id: str, secret_access_key: str, regions: list[str],
                 vpc_ids: list[str] | None = None, session_token: str | None = None) -> dict:
    """Read the account's regions (or the given VPCs) into a bundle."""
    creds = {"access_key_id": access_key_id, "secret_access_key": secret_access_key,
             "session_token": session_token or None}
    regions = [r.strip() for r in regions if r and r.strip()]
    if not regions:
        raise AwsAuthError("no region configured for this account")
    ident = caller_identity(creds, regions[0])
    bundle: dict = {"accountId": str(ident.get("Account") or ""), "principal": ident.get("Arn") or "",
                    "regions": regions, "apiVersion": API_VERSION,
                    "fetchedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "warnings": []}
    for key in BUNDLE_KEYS:
        bundle[key] = []
    bundle["PrefixListEntries"] = {}
    vpc_filter = {"Filter": [{"Name": "vpc-id", "Value": list(vpc_ids)}]} if vpc_ids else {}
    for region in regions:
        try:
            vpcs = describe(creds, region, "DescribeVpcs", "Vpcs", {"VpcId": list(vpc_ids)} if vpc_ids else {})
        except AwsApiError as exc:
            if exc.code in ("OptInRequired", "UnsupportedOperation"):
                bundle["warnings"].append(f"region {region} is not enabled for this account, skipped")
                continue
            raise
        for v in vpcs:
            v["Region"] = region
        bundle["Vpcs"].extend(vpcs)
        for key in ("Subnets", "RouteTables", "SecurityGroups", "NetworkAcls", "NetworkInterfaces"):
            items = describe(creds, region, _DESCRIBE[key], key, vpc_filter)
            for it in items:
                it["Region"] = region
            bundle[key].extend(items)
        referenced: set[str] = set()
        for sg in bundle["SecurityGroups"]:
            if sg.get("Region") != region:
                continue
            for perm in (sg.get("IpPermissions") or []) + (sg.get("IpPermissionsEgress") or []):
                for p in perm.get("PrefixListIds") or []:
                    if p.get("PrefixListId"):
                        referenced.add(p["PrefixListId"])
        for rt in bundle["RouteTables"]:
            if rt.get("Region") == region:
                for r in rt.get("Routes") or []:
                    if r.get("DestinationPrefixListId"):
                        referenced.add(r["DestinationPrefixListId"])
        for pl in describe(creds, region, _DESCRIBE["PrefixLists"], "PrefixLists"):
            plid = pl.get("PrefixListId") or ""
            if str(pl.get("OwnerId") or "") == "AWS" and plid not in referenced:
                continue        # the account-wide AWS catalogue (S3, DynamoDB ...), unused here
            pl["Region"] = region
            bundle["PrefixLists"].append(pl)
            try:
                bundle["PrefixListEntries"][plid] = describe(creds, region, "GetManagedPrefixListEntries",
                                                             "Entries", {"PrefixListId": plid})
            except AwsApiError as exc:
                bundle["warnings"].append(f"prefix list {plid}: entries not readable ({exc.code})")
                bundle["PrefixListEntries"][plid] = []
        # Network Firewall: the firewalls of the region, their policies and rule groups
        try:
            fws = nfw_list(creds, region, "ListFirewalls", "Firewalls")
        except (AwsApiError, AwsAuthError) as exc:
            bundle["warnings"].append(f"network firewalls in {region} not readable: {str(exc)[:120]}")
            fws = []
        pol_arns: set[str] = set()
        for f in fws:
            try:
                d = nfw_call(creds, region, "DescribeFirewall", {"FirewallArn": f.get("FirewallArn")})
            except AwsApiError as exc:
                bundle["warnings"].append(f"firewall {f.get('FirewallName')}: {exc.code}")
                continue
            fw = d.get("Firewall") or {}
            if vpc_ids and fw.get("VpcId") not in set(vpc_ids):
                continue
            d["Region"] = region
            bundle["NetworkFirewalls"].append(d)
            if fw.get("FirewallPolicyArn"):
                pol_arns.add(fw["FirewallPolicyArn"])
        rg_arns: set[str] = set()
        for arn in sorted(pol_arns):
            try:
                d = nfw_call(creds, region, "DescribeFirewallPolicy", {"FirewallPolicyArn": arn})
            except AwsApiError as exc:
                bundle["warnings"].append(f"firewall policy {arn.rsplit('/', 1)[-1]}: {exc.code}")
                continue
            d["Region"] = region
            bundle["NetworkFirewallPolicies"].append(d)
            pol = d.get("FirewallPolicy") or {}
            for ref in (pol.get("StatelessRuleGroupReferences") or []) + (pol.get("StatefulRuleGroupReferences") or []):
                if ref.get("ResourceArn"):
                    rg_arns.add(ref["ResourceArn"])
        for arn in sorted(rg_arns):
            try:
                d = nfw_call(creds, region, "DescribeRuleGroup", {"RuleGroupArn": arn})
            except AwsApiError as exc:
                bundle["warnings"].append(f"rule group {arn.rsplit('/', 1)[-1]}: {exc.code}")
                continue
            d["Region"] = region
            bundle["NetworkFirewallRuleGroups"].append(d)
    return bundle


def device_settings(device: dict) -> dict:
    """The aws block of the device's config JSON."""
    try:
        return (json.loads(device.get("config") or "{}") or {}).get("aws") or {}
    except Exception:
        return {}


def _csv(value) -> list[str]:
    if isinstance(value, (list, tuple)):
        return [str(x).strip() for x in value if str(x).strip()]
    return [x.strip() for x in str(value or "").replace(";", ",").split(",") if x.strip()]


def bundle_for_device(device: dict) -> dict:
    """Live fetch when keys are on the row, else the stored upload."""
    cfg = device_settings(device)
    secret = device.get("api_key") or ""
    if secret and cfg.get("access_key_id"):
        if not _csv(cfg.get("regions")):
            raise AwsAuthError("the account has an access key but no region: enter at least one "
                               "region (for example eu-central-1) in the device's settings, or "
                               "upload a bundle instead")
        return fetch_bundle(cfg["access_key_id"], secret, _csv(cfg.get("regions")),
                            _csv(cfg.get("vpc_ids")) or None)
    raw = cfg.get("bundle")
    if raw:
        return json.loads(raw) if isinstance(raw, str) else raw
    raise AwsAuthError("no AWS access key and no uploaded bundle on this device")


# ── Parse helpers ──────────────────────────────────────────────────────

def _int(v) -> int | None:
    if v is None or v == "":
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _bool(v) -> bool:
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() == "true"


def _tag(item: dict, key: str = "Name") -> str:
    for t in item.get("Tags") or []:
        if isinstance(t, dict) and t.get("Key") == key:
            return str(t.get("Value") or "").strip()
    return ""


def _cidr(value):
    """A prefix of either family (docs/IPV6_PLAN.md, phase 4), or None."""
    try:
        return ipaddress.ip_network(str(value).strip(), strict=False)
    except Exception:
        return None


def _host_cidr(value: str) -> str:
    """A bare address as a host prefix of its family, a prefix as is."""
    v = str(value).strip()
    return v if "/" in v else f"{v}/{128 if ':' in v else 32}"


def _any_token(cidr: str) -> list[str] | None:
    """The D5 token a catch-all prefix stands for, None for the rest."""
    c = str(cidr or "").strip()
    return ["any4"] if c == "0.0.0.0/0" else (["any6"] if c == "::/0" else None)


def _side_with_tokens(out: list[str], zones: list[str], toks: set) -> tuple[list[str], list[str]]:
    """A rule side and its zones once the catch-alls are known: both
    families whole is `any`, one family's whole is its token beside the
    names, and a catch-all makes the zones `any`."""
    if {"any4", "any6"} <= toks:
        return ["any"], ["any"]
    if toks:
        return [t for t in ("any4", "any6") if t in toks] + [o for o in out if o not in ("any4", "any6")], ["any"]
    return out, (zones or ["any"])


def _proto_of(raw) -> str | None:
    """'-1', 'tcp', '6', '50' ... to a canonical protocol token: 'any', a
    literal name, or None for what no target literal can hold."""
    p = str(raw if raw is not None else "-1").strip().lower()
    if p in ("-1", "all", ""):
        return "any"
    if p in _PROTO_NAMES:
        return p
    return _PROTO_NUM.get(p)


def _port_literals(proto: str, lo: int | None, hi: int | None) -> list[str]:
    if proto in ("any",):
        return ["any"]
    if proto not in ("tcp", "udp", "sctp"):
        return [proto]
    if lo is None or lo < 1:
        lo = 1
    if hi is None or hi < 1 or hi > 65535:
        hi = 65535
    if lo == 1 and hi == 65535:
        return [f"{proto}/1-65535"]
    return [f"{proto}/{lo}"] if lo == hi else [f"{proto}/{lo}-{hi}"]


def _is_return_range(proto: str, lo: int | None, hi: int | None) -> bool:
    """The ephemeral ranges a stateless ruleset opens for return traffic."""
    return proto in ("tcp", "udp") and lo in (1024, 32768, 49152) and hi == 65535


class _Net:
    """Everything the parse needs to know about the account's network."""

    def __init__(self, bundle: dict):
        self.bundle = bundle
        self.drops: dict[str, list[str]] = {}
        self.vpc_name: dict[str, str] = {}
        self.subnets: dict[str, dict] = {}         # subnet id -> info (zone, cidr, vpc, rt, nacl)
        self.rts: dict[str, dict] = {}             # route table id -> info
        self.nacls: dict[str, dict] = {}
        self.sgs: dict[str, dict] = {}             # group id -> info (name, members, member_subnets)
        self.pls: dict[str, dict] = {}             # prefix list id -> info (name, cidrs)
        self.enis: dict[str, dict] = {}
        self.extra_groups: dict[str, dict] = {}    # placeholders for unresolved references
        self.var_groups: dict[str, dict] = {}      # Network Firewall IP set variables -> {cidrs, owner}
        self.fqdns: dict[str, str] = {}            # FQDN object name -> host (domain lists)
        self.synth: dict[str, dict] = {}           # address objects made from literals (members, rule sides)
        self.synth_svc: dict[str, dict] = {}       # service objects made from the rules' protocol/port literals
        self.vpc_cidrs: dict[str, list[str]] = {}  # vpc id -> its CIDR blocks (the default HOME_NET)
        self.home_net: list[str] = ["any"]
        self.ref_sets: dict[str, str] = {}         # reference set name -> prefix list id (per rule group)
        self._index()

    def drop(self, key: str, what: str) -> None:
        self.drops.setdefault(key, []).append(what)

    # -- naming -----------------------------------------------------------
    @staticmethod
    def _dedupe(items: list[tuple[str, str, str]]) -> dict[str, str]:
        """[(id, preferred name, fallback suffix)] -> id -> unique name.
        A repeated name gets the suffix, a still repeated one the id."""
        counts: dict[str, int] = {}
        for _, name, _ in items:
            counts[name] = counts.get(name, 0) + 1
        out: dict[str, str] = {}
        taken: set[str] = set()
        for rid, name, suffix in items:
            cand = name if counts[name] == 1 else f"{name}-{suffix}"
            if cand in taken:
                cand = f"{name}-{rid}"
            taken.add(cand)
            out[rid] = cand
        return out

    def _index(self) -> None:
        b = self.bundle
        for v in b.get("Vpcs") or []:
            vid = v.get("VpcId") or ""
            self.vpc_name[vid] = _tag(v) or vid
            cidrs = [a.get("CidrBlock") for a in v.get("CidrBlockAssociationSet") or [] if a.get("CidrBlock")]
            self.vpc_cidrs[vid] = cidrs or ([v["CidrBlock"]] if v.get("CidrBlock") else [])
        # subnets -> zones
        rows = []
        for s in b.get("Subnets") or []:
            sid = s.get("SubnetId") or ""
            if not sid:
                continue
            rows.append((sid, _tag(s) or sid, self.vpc_name.get(s.get("VpcId") or "", s.get("VpcId") or "")))
        zone_of = self._dedupe(rows)
        for s in b.get("Subnets") or []:
            sid = s.get("SubnetId") or ""
            if not sid:
                continue
            net = _cidr(s.get("CidrBlock") or "")
            if net is None:
                self.drop("subnet_no_ipv4", sid)
                continue
            # a dual-stack subnet (docs/IPV6_PLAN.md, phase 6) carries its IPv6
            # block in the association set: it joins the zone's ranges
            nets6 = [_cidr(a.get("Ipv6CidrBlock") or "") for a in s.get("Ipv6CidrBlockAssociationSet") or []
                     if ((a.get("Ipv6CidrBlockState") or {}).get("State") or "associated") == "associated"]
            nets6 = [n for n in nets6 if n is not None]
            self.subnets[sid] = {
                "id": sid, "zone": zone_of[sid], "vpc": s.get("VpcId") or "",
                "vpc_name": self.vpc_name.get(s.get("VpcId") or "", s.get("VpcId") or ""),
                "cidr": str(net), "net": net, "nets": [net] + nets6,
                "cidr6": str(nets6[0]) if nets6 else "", "az": s.get("AvailabilityZone") or "",
                "rt": "", "nacl": "",
            }
        # route tables: explicit associations, then the VPC main table
        rows = [(rt.get("RouteTableId") or "", _tag(rt) or (rt.get("RouteTableId") or ""),
                 self.vpc_name.get(rt.get("VpcId") or "", "")) for rt in b.get("RouteTables") or []]
        rt_name = self._dedupe([r for r in rows if r[0]])
        main_of_vpc: dict[str, str] = {}
        for rt in b.get("RouteTables") or []:
            rid = rt.get("RouteTableId") or ""
            if not rid:
                continue
            self.rts[rid] = {"id": rid, "name": rt_name[rid], "vpc": rt.get("VpcId") or "",
                             "routes": rt.get("Routes") or [], "subnets": [], "main": False}
            for a in rt.get("Associations") or []:
                if _bool(a.get("Main")):
                    self.rts[rid]["main"] = True
                    main_of_vpc[rt.get("VpcId") or ""] = rid
                sid = a.get("SubnetId")
                if sid and sid in self.subnets:
                    self.subnets[sid]["rt"] = rid
        for s in self.subnets.values():
            if not s["rt"]:
                s["rt"] = main_of_vpc.get(s["vpc"], "")
            if s["rt"]:
                self.rts[s["rt"]]["subnets"].append(s["id"])
        # network ACLs
        rows = [(n.get("NetworkAclId") or "", _tag(n) or (n.get("NetworkAclId") or ""),
                 self.vpc_name.get(n.get("VpcId") or "", "")) for n in b.get("NetworkAcls") or []]
        nacl_name = self._dedupe([r for r in rows if r[0]])
        for n in b.get("NetworkAcls") or []:
            nid = n.get("NetworkAclId") or ""
            if not nid:
                continue
            subnets = [a.get("SubnetId") for a in n.get("Associations") or []
                       if a.get("SubnetId") in self.subnets]
            for sid in subnets:
                self.subnets[sid]["nacl"] = nid
            self.nacls[nid] = {"id": nid, "name": nacl_name[nid], "vpc": n.get("VpcId") or "",
                               "default": _bool(n.get("IsDefault")), "entries": n.get("Entries") or [],
                               "subnets": subnets}
        # network interfaces -> group membership
        for e in b.get("NetworkInterfaces") or []:
            eid = e.get("NetworkInterfaceId") or ""
            ips = [str(p.get("PrivateIpAddress")).strip() for p in e.get("PrivateIpAddresses") or []
                   if p.get("PrivateIpAddress")]
            if not ips and e.get("PrivateIpAddress"):
                ips = [str(e["PrivateIpAddress"]).strip()]
            primary = str(e.get("PrivateIpAddress") or (ips[0] if ips else "")).strip()
            att = e.get("Attachment") or {}
            self.enis[eid] = {"id": eid, "ips": ips, "primary": primary, "subnet": e.get("SubnetId") or "",
                              "instance": att.get("InstanceId") or "", "device_index": _int(att.get("DeviceIndex")),
                              "groups": [g.get("GroupId") for g in e.get("Groups") or [] if g.get("GroupId")]}
        # security groups
        rows = [(sg.get("GroupId") or "", sg.get("GroupName") or (sg.get("GroupId") or ""),
                 self.vpc_name.get(sg.get("VpcId") or "", "")) for sg in b.get("SecurityGroups") or []]
        sg_name = self._dedupe([r for r in rows if r[0]])
        for sg in b.get("SecurityGroups") or []:
            gid = sg.get("GroupId") or ""
            if not gid:
                continue
            self.sgs[gid] = {"id": gid, "name": sg_name[gid], "group_name": sg.get("GroupName") or gid,
                             "vpc": sg.get("VpcId") or "",
                             "vpc_name": self.vpc_name.get(sg.get("VpcId") or "", sg.get("VpcId") or ""),
                             "description": (sg.get("Description") or "").strip(),
                             "ingress": sg.get("IpPermissions") or [], "egress": sg.get("IpPermissionsEgress") or [],
                             "members": [], "member_subnets": []}
        for e in self.enis.values():
            for gid in e["groups"]:
                sg = self.sgs.get(gid)
                if sg is None:
                    continue
                for ip in e["ips"]:
                    if ip not in sg["members"]:
                        sg["members"].append(ip)
                if e["subnet"] and e["subnet"] not in sg["member_subnets"]:
                    sg["member_subnets"].append(e["subnet"])
        # managed prefix lists -> address groups (names beside the groups)
        taken = set(sg["name"] for sg in self.sgs.values())
        entries = b.get("PrefixListEntries") or {}
        for pl in b.get("PrefixLists") or []:
            plid = pl.get("PrefixListId") or ""
            if not plid:
                continue
            name = (pl.get("PrefixListName") or plid).strip()
            if name in taken:
                name = f"{name}-{plid}"
            taken.add(name)
            cidrs: list[str] = []
            for en in entries.get(plid) or []:
                c = (en.get("Cidr") or "").strip() if isinstance(en, dict) else str(en).strip()
                if _cidr(c) is not None and c not in cidrs:
                    cidrs.append(c)
            self.pls[plid] = {"id": plid, "name": name, "cidrs": cidrs, "owner": str(pl.get("OwnerId") or ""),
                              "fetched": plid in entries}

    # -- lookups ----------------------------------------------------------
    def subnet_for_ip(self, ip: str, vpc: str | None = None) -> dict | None:
        try:
            addr = ipaddress.IPv4Address(ip)
        except Exception:
            return None
        for s in self.subnets.values():
            if vpc and s["vpc"] != vpc:
                continue
            if addr in s["net"]:
                return s
        return None

    def zones_for_prefix(self, prefix: str) -> list[str]:
        """The zone a prefix lies in. A prefix that is not inside one subnet
        (a supernet, or outside the VPCs) may come from anywhere: 'any'."""
        net = _cidr(prefix)
        if net is None:
            return ["any"]
        for s in self.subnets.values():
            if any(net.version == n.version and net.subnet_of(n) for n in s["nets"]):
                return [s["zone"]]
        return ["any"]

    def zones_of_subnets(self, subnet_ids: list[str]) -> list[str]:
        zones: list[str] = []
        for sid in subnet_ids:
            s = self.subnets.get(sid)
            if s and s["zone"] not in zones:
                zones.append(s["zone"])
        return zones or ["any"]

    def placeholder_group(self, name: str, reason: str, what: str) -> str:
        if name not in self.extra_groups:
            self.extra_groups[name] = {"name": name, "reason": reason}
            self.drop(reason, what)
        return name

    def var_group(self, var: str, cidrs: list[str], owner: str) -> str:
        """A Network Firewall IP set variable as an address group; the same
        name with other members in another group gets the group as suffix."""
        v4 = [c for c in cidrs if _cidr(c) is not None]
        name = var
        if name in self.var_groups and self.var_groups[name]["cidrs"] != v4:
            name = f"{var}-{owner.rsplit('-', 1)[0]}"
        self.var_groups.setdefault(name, {"cidrs": v4})
        return name


def _merge_zones(acc: list[str], more: list[str]) -> list[str]:
    if "any" in acc or "any" in more:
        return ["any"]
    for z in more:
        if z not in acc:
            acc.append(z)
    return acc


def _resolve_remote(net: _Net, perm: dict, owner: str) -> tuple[list[str], list[str], list[str]]:
    """The far side of a security-group rule: (address literals and group
    names, zones, descriptions). Ranges of both families are read, a whole
    family's catch-all becomes its D5 token."""
    out: list[str] = []
    zones: list[str] = []
    descs: list[str] = []
    toks: set[str] = set()
    for key, r in ([("CidrIp", r) for r in perm.get("IpRanges") or []]
                   + [("CidrIpv6", r) for r in perm.get("Ipv6Ranges") or []]):
        c = str(r.get(key) or "").strip()
        if not c:
            continue
        if r.get("Description"):
            descs.append(str(r["Description"]).strip())
        tok = _any_token(c)
        if tok:
            toks.add(tok[0])
            continue
        net_ = _cidr(c)
        if net_ is None:
            net.drop("address_unresolved", f"{owner}:{c}")
            continue
        lit = str(net_) if "/" in c else _host_cidr(c)
        name = literal_ref(lit, owner, net.synth)
        if name not in out:
            out.append(name)
        zones = _merge_zones(zones, net.zones_for_prefix(lit))
    for p in perm.get("UserIdGroupPairs") or []:
        gid = str(p.get("GroupId") or "").strip()
        if not gid:
            continue
        if p.get("Description"):
            descs.append(str(p["Description"]).strip())
        sg = net.sgs.get(gid)
        if sg is None:
            name = net.placeholder_group(gid, "group_reference_unresolved", f"{owner}:{gid}")
            zones = _merge_zones(zones, ["any"])
        else:
            name = sg["name"]
            zones = _merge_zones(zones, net.zones_of_subnets(sg["member_subnets"]))
        if name not in out:
            out.append(name)
    for p in perm.get("PrefixListIds") or []:
        plid = str(p.get("PrefixListId") or "").strip()
        if not plid:
            continue
        if p.get("Description"):
            descs.append(str(p["Description"]).strip())
        pl = net.pls.get(plid)
        if pl is None:
            name = net.placeholder_group(plid, "prefix_list_unresolved", f"{owner}:{plid}")
            zones = _merge_zones(zones, ["any"])
        else:
            name = pl["name"]
            for c in pl["cidrs"]:
                zones = _merge_zones(zones, net.zones_for_prefix(c))
        if name not in out:
            out.append(name)
    out, zones = _side_with_tokens(out, zones, toks)
    return out, zones, descs


def _sg_services(net: _Net, perm: dict, owner: str, raw_extras: dict) -> list[str] | None:
    proto = _proto_of(perm.get("IpProtocol"))
    if proto is None:
        net.drop("protocol_unsupported", f"{owner}:{perm.get('IpProtocol')}")
        return None
    lo, hi = _int(perm.get("FromPort")), _int(perm.get("ToPort"))
    if proto == "icmp":
        if lo is not None and lo >= 0:
            raw_extras["aws_icmp_type"] = lo
            raw_extras["aws_icmp_code"] = hi
        return ["icmp"]
    if lo is not None and lo < 0:
        lo = None
    if hi is not None and hi < 0:
        hi = None
    return _port_literals(proto, lo, hi)


def _rule(name: str, seq: int, action: str, src: list[str], src_zones: list[str], dst: list[str],
          dst_zones: list[str], services: list[str], description: str, disabled: int,
          raw_extras: dict, dropped: list[str]) -> dict:
    return {
        "rule_name":      name,
        "seq_num":        seq,
        "action":         action,
        "src_zones":      src_zones,
        "dst_zones":      dst_zones,
        "sources":        src,
        "destinations":   dst,
        "services":       services,
        "applications":   [],
        "description":    description,
        "disabled":       disabled,
        "tags":           [],
        "negate_source":      0,
        "negate_destination": 0,
        "negate_service":     0,
        "schedule":       None,
        "source_identities": None,
        "raw_extras":     raw_extras,
        "dropped_inputs": dropped,
    }


def _parse_nacl_rules(net: _Net, seq: int, rules: list[dict]) -> int:
    for nacl in sorted(net.nacls.values(), key=lambda n: n["name"]):
        zones = net.zones_of_subnets(nacl["subnets"])
        scope4 = [literal_ref(net.subnets[s]["cidr"], nacl["name"], net.synth) for s in nacl["subnets"]] or ["any"]
        # an IPv6 entry guards the subnets' IPv6 blocks (phase 6); subnets
        # without one keep the IPv4 prefixes as the near side, so the target
        # declares the mixed-family rule instead of a widened any6 deny
        scope6 = [literal_ref(net.subnets[s]["cidr6"], nacl["name"], net.synth)
                  for s in nacl["subnets"] if net.subnets[s]["cidr6"]] or scope4
        if not nacl["subnets"]:
            net.drop("nacl_unassociated", nacl["name"])
        for egress in (False, True):
            entries = sorted((e for e in nacl["entries"] if _bool(e.get("Egress")) == egress),
                             key=lambda e: _int(e.get("RuleNumber")) or 0)
            for e in entries:
                num = _int(e.get("RuleNumber")) or 0
                is_default = num >= _NACL_DEFAULT_RULE
                label = "default" if is_default else str(num)
                name = f"{nacl['name']}-{'out' if egress else 'in'}-{label}"
                cidr = str(e.get("CidrBlock") or e.get("Ipv6CidrBlock") or "").strip()
                if not cidr:
                    net.drop("address_unresolved", name)
                    continue
                proto = _proto_of(e.get("Protocol"))
                if proto is None:
                    net.drop("protocol_unsupported", f"{name}:{e.get('Protocol')}")
                    continue
                pr = e.get("PortRange") or {}
                lo, hi = _int(pr.get("From")), _int(pr.get("To"))
                raw_extras = {"aws_nacl": nacl["id"], "aws_rule_number": num, "aws_egress": egress,
                              "aws_stateless": True}
                if proto == "icmp":
                    itc = e.get("IcmpTypeCode") or {}
                    if _int(itc.get("Type")) is not None and _int(itc.get("Type")) >= 0:
                        raw_extras["aws_icmp_type"] = _int(itc.get("Type"))
                        raw_extras["aws_icmp_code"] = _int(itc.get("Code"))
                    services = ["icmp"]
                else:
                    services = _port_literals(proto, lo, hi)
                remote = _any_token(cidr) or [literal_ref(cidr, name, net.synth)]
                remote_zones = ["any"] if _any_token(cidr) else net.zones_for_prefix(cidr)
                scope = scope6 if ":" in cidr else scope4
                allow = str(e.get("RuleAction") or "").lower() == "allow"
                disabled, dropped, note = 0, [], ""
                if is_default:
                    disabled = 1
                    note = "[default deny of the network ACL, see the implicit deny at the end of the ruleset]"
                # per-rule declarations go into dropped_inputs ONLY: the import
                # route aggregates those by rule name and adds the object-level
                # drops dict on top, so a field in both would count twice
                elif allow and _is_return_range(proto, lo, hi):
                    disabled = 1
                    dropped = ["stateless_return"]
                    note = "[stateless return-traffic rule, not needed on a stateful target]"
                elif allow:
                    disabled = 1
                    dropped = ["stateless_allow"]
                    note = "[stateless subnet rule imported disabled, the security group rules carry the policy]"
                else:
                    note = "[stateless network ACL deny, evaluated at the subnet boundary]"
                if egress:
                    rule = _rule(name, seq, "allow" if allow else "deny", scope, zones, remote, remote_zones,
                                 services, note, disabled, raw_extras, dropped)
                else:
                    rule = _rule(name, seq, "allow" if allow else "deny", remote, remote_zones, scope, zones,
                                 services, note, disabled, raw_extras, dropped)
                if is_default:
                    rule["default_rule_kind"] = "aws-nacl-default"
                rules.append(rule)
                seq += 1
    return seq


def _parse_sg_rules(net: _Net, seq: int, rules: list[dict]) -> int:
    for sg in sorted(net.sgs.values(), key=lambda g: g["name"]):
        member_zones = net.zones_of_subnets(sg["member_subnets"])
        if not sg["members"]:
            net.drop("membership_empty", sg["name"])
        for direction, perms in (("in", sg["ingress"]), ("out", sg["egress"])):
            for i, perm in enumerate(perms, 1):
                name = f"{sg['name']}-{direction}-{i}"
                raw_extras = {"aws_group_id": sg["id"], "aws_group_name": sg["group_name"],
                              "aws_vpc": sg["vpc"], "aws_direction": "ingress" if direction == "in" else "egress",
                              "aws_rule_index": i}
                services = _sg_services(net, perm, name, raw_extras)
                if services is None:
                    continue
                remote, remote_zones, descs = _resolve_remote(net, perm, name)
                if not remote:
                    net.drop("rule_remote_empty", name)
                    continue
                description = ", ".join(dict.fromkeys(d for d in descs if d))
                if direction == "in":
                    rule = _rule(name, seq, "allow", remote, remote_zones, [sg["name"]], member_zones,
                                 services, description, 0, raw_extras, [])
                else:
                    rule = _rule(name, seq, "allow", [sg["name"]], member_zones, remote, remote_zones,
                                 services, description, 0, raw_extras, [])
                rules.append(rule)
                seq += 1
    return seq


# ── Network Firewall (P4b) ─────────────────────────────────────────────

_NFW_PROTO = {"6": "tcp", "17": "udp", "1": "icmp", "50": "esp", "51": "ah", "47": "gre", "132": "sctp",
              "tcp": "tcp", "udp": "udp", "icmp": "icmp", "ip": "any"}
_APP_LAYER = {"http", "tls", "dns", "ftp", "smb", "smtp", "ssh", "tftp", "dcerpc", "ikev2", "krb5", "ntp",
              "imap", "msn", "dhcp", "nfs", "http2", "quic"}


def _nfw_ports(spec, portsets: dict, owner: str, net: _Net) -> list[str]:
    """A stateful rule's port field ('ANY', '443', '1000:2000', '[80,443]',
    '$WEB_PORTS') -> ['443', '1000-2000', ...] ('*' for any)."""
    s = str(spec or "ANY").strip()
    if s.upper() == "ANY":
        return ["*"]
    if s.startswith("$"):
        vals = portsets.get(s[1:]) or []
        if not vals:
            net.drop("port_variable_unresolved", f"{owner}:{s}")
            return ["*"]
        out: list[str] = []
        for v in vals:
            out.extend(_nfw_ports(v, portsets, owner, net))
        return [x for x in out if x != "*"] or ["*"]
    s = s.strip("[]")
    out = []
    for part in s.split(","):
        part = part.strip().replace(":", "-")
        if part:
            out.append(part)
    return out or ["*"]


def _nfw_side(spec, ipsets: dict, net: _Net, owner: str) -> tuple[list[str], list[str], int]:
    """A stateful rule's address field -> (literals or group names, zones,
    negated). 'ANY', a CIDR, '[a,b]', '$VAR' (IP set variable), '@ref'
    (reference set, a prefix list), with an optional '!' in front."""
    s = str(spec or "ANY").strip()
    negate = 0
    if s.startswith("!"):
        negate = 1
        s = s[1:].strip()
    if s.upper() == "ANY":
        return ["any"], ["any"], negate
    out: list[str] = []
    zones: list[str] = []
    toks: set[str] = set()
    for part in [p.strip() for p in s.strip("[]").split(",") if p.strip()]:
        if part.startswith("$"):
            var = part[1:]
            if var in ipsets:
                name = net.var_group(var, ipsets[var], owner)
                out.append(name)
                for c in ipsets[var]:
                    zones = _merge_zones(zones, net.zones_for_prefix(c))
            elif var == "HOME_NET":
                # the default HOME_NET is the VPC CIDR of the firewall's VPC
                cidrs = net.home_net
                name = net.var_group("HOME_NET", cidrs, owner)
                out.append(name)
                for c in cidrs:
                    zones = _merge_zones(zones, net.zones_for_prefix(c))
            elif var == "EXTERNAL_NET":
                return ["any"], ["any"], negate      # everything outside, read as any
            else:
                net.drop("ip_variable_unresolved", f"{owner}:{part}")
                return ["any"], ["any"], negate
        elif part.startswith("@"):
            ref = net.ref_sets.get(part[1:])
            pl = net.pls.get(ref or "") if ref else None
            if pl is None:
                name = net.placeholder_group(part[1:], "prefix_list_unresolved", f"{owner}:{part}")
                zones = _merge_zones(zones, ["any"])
            else:
                name = pl["name"]
                for c in pl["cidrs"]:
                    zones = _merge_zones(zones, net.zones_for_prefix(c))
            out.append(name)
        elif _cidr(part) is not None:
            lit = _host_cidr(part)
            if _any_token(lit):
                toks.add(_any_token(lit)[0])
                continue
            name = literal_ref(lit, owner, net.synth)
            if name not in out:
                out.append(name)
            zones = _merge_zones(zones, net.zones_for_prefix(lit))
        else:
            net.drop("address_unresolved", f"{owner}:{part}")
    out, zones = _side_with_tokens(out, zones, toks)
    if not out:
        return ["any"], ["any"], negate
    return out, zones, negate


def _parse_nfw_rules(net: _Net, seq: int, rules: list[dict]) -> int:
    """The Network Firewall block(s), in front of the network ACLs: per
    firewall its policy's stateless rules by priority, then the stateful
    groups (strict order as listed, default action order sorted pass,
    drop, alert), then the default actions marked as defaults."""
    b = net.bundle
    policies = {((d.get("FirewallPolicyResponse") or {}).get("FirewallPolicyArn") or ""): d
                for d in b.get("NetworkFirewallPolicies") or []}
    groups = {((d.get("RuleGroupResponse") or {}).get("RuleGroupArn") or ""): d
              for d in b.get("NetworkFirewallRuleGroups") or []}
    for d in sorted(b.get("NetworkFirewalls") or [], key=lambda x: (x.get("Firewall") or {}).get("FirewallName") or ""):
        fw = d.get("Firewall") or {}
        fw_name = fw.get("FirewallName") or "firewall"
        vpc = fw.get("VpcId") or ""
        net.home_net = [c for c in net.vpc_cidrs.get(vpc, [])] or ["any"]
        pol_d = policies.get(fw.get("FirewallPolicyArn") or "")
        if pol_d is None:
            net.drop("firewall_policy_unread", fw_name)
            continue
        pol = pol_d.get("FirewallPolicy") or {}
        pol_name = (pol_d.get("FirewallPolicyResponse") or {}).get("FirewallPolicyName") or "policy"
        base_extras = {"aws_network_firewall": fw_name, "aws_firewall_policy": pol_name, "aws_vpc": vpc}

        def emit(name, action, src, src_zones, dst, dst_zones, services, description, disabled, extras, dropped,
                 negate_source=0, negate_destination=0, default_kind=None):
            nonlocal seq
            rule = _rule(name, seq, action, src, src_zones, dst, dst_zones, services, description, disabled,
                         dict(base_extras, **extras), dropped)
            rule["negate_source"] = negate_source
            rule["negate_destination"] = negate_destination
            if default_kind:
                rule["default_rule_kind"] = default_kind
            rules.append(rule)
            seq += 1

        # stateless: rule groups by reference priority, rules by priority
        refs = sorted(pol.get("StatelessRuleGroupReferences") or [], key=lambda r: int(r.get("Priority") or 0))
        for ref in refs:
            g = groups.get(ref.get("ResourceArn") or "")
            if g is None:
                net.drop("rule_group_unread", f"{fw_name}:{(ref.get('ResourceArn') or '').rsplit('/', 1)[-1]}")
                continue
            g_name = (g.get("RuleGroupResponse") or {}).get("RuleGroupName") or "stateless"
            src_ = ((g.get("RuleGroup") or {}).get("RulesSource") or {}).get("StatelessRulesAndCustomActions") or {}
            for r in sorted(src_.get("StatelessRules") or [], key=lambda x: int(x.get("Priority") or 0)):
                name = f"{g_name}-{r.get('Priority')}"
                rd = r.get("RuleDefinition") or {}
                m = rd.get("MatchAttributes") or {}
                actions = [str(a) for a in rd.get("Actions") or []]
                aws_action = next((a for a in actions if a.startswith("aws:")), "aws:forward_to_sfe")
                dropped: list[str] = []
                extras = {"aws_rule_group": g_name, "aws_stateless": True, "aws_priority": r.get("Priority"),
                          "aws_actions": actions}
                srcs = [a.get("AddressDefinition") for a in m.get("Sources") or [] if a.get("AddressDefinition")]
                dsts = [a.get("AddressDefinition") for a in m.get("Destinations") or [] if a.get("AddressDefinition")]
                src, src_zones, _ = _nfw_side("[" + ",".join(srcs) + "]" if srcs else "ANY", {}, net, name)
                dst, dst_zones, _ = _nfw_side("[" + ",".join(dsts) + "]" if dsts else "ANY", {}, net, name)
                protos = [_NFW_PROTO.get(str(p)) for p in m.get("Protocols") or []]
                protos = [p for p in protos if p] or ["any"]
                if len(protos) != len(m.get("Protocols") or []) and m.get("Protocols"):
                    net.drop("protocol_unsupported", f"{name}:{m.get('Protocols')}")
                services: list[str] = []
                dports = [f"{_int(p.get('FromPort'))}-{_int(p.get('ToPort'))}" if _int(p.get("FromPort")) != _int(p.get("ToPort"))
                          else str(_int(p.get("FromPort"))) for p in m.get("DestinationPorts") or []]
                for proto in protos:
                    if proto == "any":
                        services = ["any"]
                        break
                    if proto in ("tcp", "udp", "sctp"):
                        lits = [x for x in (port_literal(proto, p) for p in (dports or ["*"])) if x]
                    else:
                        lits = [proto]
                    services.extend(x for x in lits if x not in services)
                if m.get("SourcePorts"):
                    dropped.append("source_ports")
                    extras["aws_source_ports"] = m["SourcePorts"]
                if m.get("TCPFlags"):
                    dropped.append("tcp_flags")
                    extras["aws_tcp_flags"] = m["TCPFlags"]
                disabled, note = 0, ""
                if aws_action == "aws:pass":
                    action = "allow"
                elif aws_action == "aws:drop":
                    action = "deny"
                else:
                    action, disabled = "allow", 1
                    dropped.append("forward_to_sfe")
                    note = "[forwards to the stateful engine, decides nothing itself, imported disabled]"
                emit(name, action, src, src_zones, dst, dst_zones, services or ["any"], note, disabled, extras, dropped)
        default = [str(a) for a in pol.get("StatelessDefaultActions") or []]
        if default:
            aws_default = next((a for a in default if a.startswith("aws:")), "aws:forward_to_sfe")
            action = "allow" if aws_default == "aws:pass" else "deny"
            disabled = 0 if aws_default in ("aws:pass", "aws:drop") else 1
            emit(f"{pol_name}-stateless-default", action, ["any"], ["any"], ["any"], ["any"], ["any"],
                 f"Stateless default action {aws_default}" + (" (continues to the stateful rules)" if disabled else ""),
                 disabled, {"aws_stateless": True, "aws_actions": default}, ["forward_to_sfe"] if disabled else [],
                 default_kind="aws-nfw-stateless-default")

        # stateful: groups in policy order, rules in their order; with the
        # default action order the engine sorts pass, drop and reject, alert
        strict = str(((pol.get("StatefulEngineOptions") or {}).get("RuleOrder")) or "DEFAULT_ACTION_ORDER").upper() == "STRICT_ORDER"
        srefs = pol.get("StatefulRuleGroupReferences") or []
        if strict:
            srefs = sorted(srefs, key=lambda r: int(r.get("Priority") or 0))
        pending: list[tuple[int, dict]] = []      # (action rank, rule) for default action order

        def stateful_emit(rank, args):
            if strict:
                emit(*args[0], **args[1])
            else:
                pending.append((rank, args))

        for ref in srefs:
            g = groups.get(ref.get("ResourceArn") or "")
            if g is None:
                net.drop("rule_group_unread", f"{fw_name}:{(ref.get('ResourceArn') or '').rsplit('/', 1)[-1]}")
                continue
            g_name = (g.get("RuleGroupResponse") or {}).get("RuleGroupName") or "stateful"
            rg = g.get("RuleGroup") or {}
            ipsets = {k: list((v or {}).get("Definition") or []) for k, v in ((rg.get("RuleVariables") or {}).get("IPSets") or {}).items()}
            portsets = {k: list((v or {}).get("Definition") or []) for k, v in ((rg.get("RuleVariables") or {}).get("PortSets") or {}).items()}
            net.ref_sets = {k: str((v or {}).get("ReferenceArn") or "").rsplit("/", 1)[-1]
                            for k, v in ((rg.get("ReferenceSets") or {}).get("IPSetReferences") or {}).items()}
            rs = rg.get("RulesSource") or {}
            for i, r in enumerate(rs.get("StatefulRules") or [], 1):
                h = r.get("Header") or {}
                opts = {str(o.get("Keyword")).lower(): o.get("Settings") or [] for o in r.get("RuleOptions") or []}
                sid = (opts.get("sid") or [None])[0]
                name = f"{g_name}-{sid}" if sid else f"{g_name}-{i}"
                dropped = []
                extras = {"aws_rule_group": g_name, "aws_sid": sid, "aws_header": h, "aws_action": r.get("Action")}
                src, src_zones, nsrc = _nfw_side(h.get("Source"), ipsets, net, name)
                dst, dst_zones, ndst = _nfw_side(h.get("Destination"), ipsets, net, name)
                proto = str(h.get("Protocol") or "IP").lower()
                dports = _nfw_ports(h.get("DestinationPort"), portsets, name, net)
                if proto in _APP_LAYER:
                    services = ["any"]
                    dropped.append("app_layer_protocol")
                    extras["aws_app_protocol"] = proto
                elif _NFW_PROTO.get(proto, proto) in ("tcp", "udp", "sctp"):
                    p = _NFW_PROTO.get(proto, proto)
                    services = [x for x in (port_literal(p, d) for d in dports) if x] or [f"{p}/1-65535"]
                elif _NFW_PROTO.get(proto) == "any":
                    services = ["any"]
                elif _NFW_PROTO.get(proto):
                    services = [_NFW_PROTO[proto]]
                else:
                    net.drop("protocol_unsupported", f"{name}:{proto}")
                    continue
                if str(h.get("SourcePort") or "ANY").upper() != "ANY":
                    dropped.append("source_ports")
                    extras["aws_source_port"] = h.get("SourcePort")
                if str(h.get("Direction") or "FORWARD").upper() == "ANY":
                    dropped.append("direction_any")
                extra_opts = [k for k in opts if k not in ("sid", "msg", "rev", "flow", "classtype", "gid", "metadata")]
                if extra_opts:
                    dropped.append("rule_options")
                    extras["aws_rule_options"] = extra_opts
                act = str(r.get("Action") or "PASS").upper()
                disabled, note = 0, (opts.get("msg") or [""])[0].strip('"')
                if act == "PASS":
                    action, rank = "allow", 0
                elif act == "DROP":
                    action, rank = "deny", 1
                elif act == "REJECT":
                    action, rank = "deny", 1
                    dropped.append("reject")
                else:
                    action, rank, disabled = "allow", 2, 1
                    dropped.append("alert_only")
                    note = (note + " " if note else "") + "[alert only, imported disabled]"
                stateful_emit(rank, ((name, action, src, src_zones, dst, dst_zones, services, note, disabled, extras, dropped),
                                     {"negate_source": nsrc, "negate_destination": ndst}))
            dl = rs.get("RulesSourceList") or {}
            if dl.get("Targets"):
                kind = str(dl.get("GeneratedRulesType") or "ALLOWLIST").upper()
                types = [str(t).upper() for t in dl.get("TargetTypes") or ["TLS_SNI", "HTTP_HOST"]]
                services = [s for s, t in (("tcp/443", "TLS_SNI"), ("tcp/80", "HTTP_HOST")) if t in types] or ["any"]
                for t in dl["Targets"]:
                    host = str(t).strip()
                    wild = host.startswith(".")
                    obj = "fqdn-" + ("wildcard" + host if wild else host)
                    net.fqdns[obj] = ("*" + host) if wild else host
                    stateful_emit(0 if kind == "ALLOWLIST" else 1,
                                  ((f"{g_name}-{host.lstrip('.')}", "allow" if kind == "ALLOWLIST" else "deny",
                                    ["any"], ["any"], [obj], ["any"], services,
                                    f"domain list {kind.lower()} ({', '.join(types)})", 0,
                                    {"aws_rule_group": g_name, "aws_domain_list": kind, "aws_target_types": types},
                                    ["fqdn_wildcard"] if wild else []), {}))
                if kind == "ALLOWLIST":
                    stateful_emit(1, ((f"{g_name}-other-domains", "deny", ["any"], ["any"], ["any"], ["any"], services,
                                       "[the allowlist drops every other HTTP host and TLS server name, imported disabled]",
                                       1, {"aws_rule_group": g_name, "aws_domain_list": kind}, ["domain_allowlist_deny"]), {}))
            if rs.get("RulesString"):
                lines = [ln for ln in str(rs["RulesString"]).splitlines()
                         if ln.strip().split(" ")[0].lower() in ("alert", "pass", "drop", "reject")]
                net.drop("suricata_rules", f"{g_name}:{len(lines)} rule(s)")
                stateful_emit(2, ((f"{g_name}-suricata", "allow", ["any"], ["any"], ["any"], ["any"], ["any"],
                                   f"[{len(lines)} Suricata rule(s) of this group are not translated, imported disabled]",
                                   1, {"aws_rule_group": g_name, "aws_suricata_rules": len(lines)}, ["suricata_rules"]), {}))
        if not strict:
            for _, (args, kw) in sorted(pending, key=lambda x: x[0]):
                emit(*args, **kw)
        sdefault = [str(a) for a in pol.get("StatefulDefaultActions") or []]
        if sdefault:
            drop_ = any("drop" in a for a in sdefault)
            emit(f"{pol_name}-stateful-default", "deny" if drop_ else "allow", ["any"], ["any"], ["any"], ["any"], ["any"],
                 f"Stateful default action {', '.join(sdefault)}", 0 if drop_ else 1,
                 {"aws_actions": sdefault}, [] if drop_ else ["alert_only"], default_kind="aws-nfw-stateful-default")
    return seq


def _parse_rules(net: _Net) -> list[dict]:
    rules: list[dict] = []
    seq = _parse_nfw_rules(net, 0, rules)
    seq = _parse_nacl_rules(net, seq, rules)
    seq = _parse_sg_rules(net, seq, rules)
    deny = _rule("implicit-deny", seq, "deny", ["any"], ["any"], ["any"], ["any"], ["any"],
                 "Security groups allow only, everything they do not allow is denied", 0,
                 {"aws_implicit": True}, [])
    deny["default_rule_kind"] = "aws-sg-implicit-deny"
    rules.append(deny)
    return rules


def _parse_objects(net: _Net) -> list[dict]:
    """Containers as address groups whose members are address objects
    synthesised from the resolved addresses (see _common.member_objects)."""
    objects: list[dict] = []
    synth = net.synth        # one registry: rule literals and members share objects
    for sg in sorted(net.sgs.values(), key=lambda g: g["name"]):
        members = sorted(set(sg["members"]), key=lambda ip: ipaddress.IPv4Address(ip)
                         if _cidr(ip) else ipaddress.IPv4Address("0.0.0.0"))
        cidrs = [m if "/" in m else f"{m}/32" for m in members]
        objects.append({"obj_type": "address_group", "name": sg["name"], "value": {
            "type": "static", "members": member_objects(cidrs, sg["name"], synth),
            "description": f"AWS security group {sg['id']} ({sg['vpc_name']}), "
                           f"{len(members)} member(s) resolved at import",
        }})
    for pl in sorted(net.pls.values(), key=lambda p: p["name"]):
        if not pl["cidrs"]:
            net.drop("membership_empty" if pl["fetched"] else "prefix_list_unresolved", pl["name"])
        objects.append({"obj_type": "address_group", "name": pl["name"], "value": {
            "type": "static", "members": member_objects(list(pl["cidrs"]), pl["name"], synth),
            "description": f"AWS managed prefix list {pl['id']}, {len(pl['cidrs'])} entries resolved at import",
        }})
    for name, g in sorted(net.extra_groups.items()):
        objects.append({"obj_type": "address_group", "name": name, "value": {
            "type": "static", "members": [],
            "description": "referenced by a security group rule but not part of this read "
                           "(another account, a peered VPC or an unread region)",
        }})
    for name in sorted(net.var_groups):
        cidrs = net.var_groups[name]["cidrs"]
        objects.append({"obj_type": "address_group", "name": name, "value": {
            "type": "static", "members": member_objects(list(cidrs), name, synth),
            "description": f"AWS Network Firewall IP set variable, {len(cidrs)} address(es)",
        }})
    for name in sorted(net.fqdns):
        objects.append({"obj_type": "address", "name": name,
                        "value": {"type": "fqdn", "value": net.fqdns[name], "description": "AWS Network Firewall domain list entry"}})
    return objects + list(synth.values()) + list(net.synth_svc.values())


def _parse_network(net: _Net) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    """(interfaces, zones, routes, vrfs). Every route table with subnets is a
    virtual router named after it (each subnet follows exactly one table)."""
    interfaces: list[dict] = []
    zones: list[dict] = []
    vrfs: list[dict] = []
    routes: list[dict] = []
    members_by_vr: dict[str, list[str]] = {}
    for s in sorted(net.subnets.values(), key=lambda x: (x["vpc_name"], x["zone"])):
        vr = net.rts[s["rt"]]["name"] if s["rt"] in net.rts else "default"
        s["vr"] = vr
        interfaces.append({
            "name":         s["zone"],
            "zone":         s["zone"],
            "description":  f"{s['vpc_name']} {s['cidr']} {s['az']}".strip(),
            "ips":          [],
            "type":         "physical",
            "vr_name":      vr,
            "role":         None,
            "dhcp_enabled": False,
            "enabled":      True,
        })
        zones.append({"name": s["zone"], "members": [s["zone"]],
                      "properties": {"aws_vpc": s["vpc"], "aws_subnet_id": s["id"],
                                     "aws_cidr": s["cidr"], "aws_cidr6": s["cidr6"], "aws_az": s["az"]}})
        members_by_vr.setdefault(vr, []).append(s["zone"])
    for rt in sorted(net.rts.values(), key=lambda r: r["name"]):
        if not rt["subnets"]:
            net.drop("route_table_unassociated", rt["name"])
            continue
        if rt["name"] != "default":
            vrfs.append({"name": rt["name"], "interface_members": members_by_vr.get(rt["name"], []),
                         "properties": {"interface_members": members_by_vr.get(rt["name"], []),
                                        "aws_route_table_id": rt["id"], "aws_vpc": rt["vpc"],
                                        "aws_main": rt["main"]}})
        for r in rt["routes"]:
            dest = str(r.get("DestinationCidrBlock") or r.get("DestinationIpv6CidrBlock") or "").strip()
            if not dest:
                if r.get("DestinationPrefixListId"):
                    net.drop("route_prefix_list", f"{rt['name']}:{r.get('DestinationPrefixListId')}")
                continue
            if str(r.get("GatewayId") or "") == "local":
                continue        # the connected route, implied by the subnet
            net_ = _cidr(dest)
            if net_ is None:
                net.drop("route_unresolved", f"{rt['name']}:{dest}")
                continue
            hop_ip = ""
            if r.get("NetworkInterfaceId"):
                hop_ip = (net.enis.get(r["NetworkInterfaceId"]) or {}).get("primary") or ""
            elif r.get("InstanceId"):
                for e in net.enis.values():
                    if e["instance"] == r["InstanceId"] and (e["device_index"] in (0, None)):
                        hop_ip = e["primary"]
                        break
            if not hop_ip:
                hop = (r.get("NetworkInterfaceId") or r.get("InstanceId") or r.get("GatewayId")
                       or r.get("NatGatewayId") or r.get("TransitGatewayId") or r.get("VpcPeeringConnectionId")
                       or r.get("EgressOnlyInternetGatewayId") or r.get("LocalGatewayId")
                       or r.get("CarrierGatewayId") or r.get("CoreNetworkArn") or "?")
                net.drop("route_hop_type", f"{rt['name']}/{dest} via {hop}")
                continue
            egress = net.subnet_for_ip(hop_ip, rt["vpc"])
            routes.append({
                "prefix":   str(net_.network_address),
                "plen":     net_.prefixlen,
                "iface":    egress["zone"] if egress else None,
                "next_hop": hop_ip,
                "vr":       rt["name"],
            })
    return interfaces, zones, routes, vrfs


def parse_bundle(bundle: dict) -> dict:
    """The whole account in one pass: rules, objects, drops and the network
    strand. Import and collect each take their half."""
    net = _Net(bundle)
    rules = _parse_rules(net)
    for r in rules:
        # a rule side holds service names, never literals (see _common.service_ref)
        r["services"] = [service_ref(s, net.synth_svc) for s in (r.get("services") or ["any"])]
    objects = _parse_objects(net)
    interfaces, zones, routes, vrfs = _parse_network(net)
    warnings: list[str] = list(bundle.get("warnings") or [])
    if net.drops:
        warnings.append("drops: " + ", ".join(f"{k}({len(v)})" for k, v in net.drops.items()))
    account = str(bundle.get("accountId") or "")
    if not account:
        for sg in bundle.get("SecurityGroups") or []:
            if sg.get("OwnerId"):
                account = str(sg["OwnerId"])
                break
    return {
        "rules": rules, "nat_rules": [], "objects": objects, "drops": net.drops,
        "errors": [], "hostname": f"aws-{account}" if account else "aws",
        "interfaces": interfaces, "zones": zones, "routes": routes, "vrfs": vrfs,
        "warnings": warnings,
    }


# ── Entry points (registered into main by the package) ─────────────────

def run_import(device: dict) -> dict:
    parsed = parse_bundle(bundle_for_device(device))
    out = {k: parsed[k] for k in ("rules", "nat_rules", "objects", "drops", "errors", "hostname")}
    # The operator names the account row (D2); an import never renames it.
    if device.get("host_name"):
        out["hostname"] = device["host_name"]
    return out


def collect_network(device: dict) -> dict:
    parsed = parse_bundle(bundle_for_device(device))
    return {k: parsed[k] for k in ("interfaces", "routes", "vrfs", "zones", "errors", "warnings")}


def validate_bundle(raw: str) -> tuple[dict | None, str | None]:
    """An uploaded bundle: JSON with at least the VPC, subnet and security
    group lists, keyed like the AWS CLI prints them."""
    try:
        data = json.loads(raw)
    except Exception as exc:
        return None, f"not JSON: {exc}"
    if not isinstance(data, dict):
        return None, "the bundle must be a JSON object keyed by resource type"
    missing = [t for t in ("Vpcs", "Subnets", "SecurityGroups") if t not in data]
    if missing:
        return None, "bundle lacks " + ", ".join(missing)
    for t in BUNDLE_KEYS:
        if t in data and not isinstance(data[t], list):
            return None, f"{t} must be a list"
    if "PrefixListEntries" in data and not isinstance(data["PrefixListEntries"], dict):
        return None, "PrefixListEntries must be an object keyed by prefix list id"
    return data, None
