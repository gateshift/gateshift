# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1
"""Cisco Secure Firewall Management Center: the REST transport.

One client for the on-premises Management Center and for the
cloud-delivered one in Security Cloud Control (docs/FMC_SOURCE_PLAN.md,
D3). The two differ in authentication and in the path prefix, nothing
else: the configuration API is the same.

- On-premises: `POST /api/fmc_platform/v1/auth/generatetoken` with HTTP
  basic auth answers the access and refresh tokens and the user's domains
  in headers. The access token lives 30 minutes and can be refreshed three
  times; the client refreshes at 25 minutes and logs in again after the
  third refresh or on a 401.
- Cloud-delivered: a bearer API token of the tenant on the regional
  gateway, paths under `/firewall/v1/cdfmc/api`, one domain whose UUID the
  inventory call names (the Global UUID is the fallback).

Lists are read with `expanded=true` and the API's page cap of 1000,
following `offset` until `paging.count` is reached. HTTP 429 (120
requests per minute, 10 connections) backs off and retries. Errors are
sentences that never carry a credential.
"""
from __future__ import annotations

import json
import time

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_CONNECT_TIMEOUT = 5
_READ_TIMEOUT = 120
PAGE_LIMIT = 1000
TOKEN_REFRESH_AT = 25 * 60       # seconds, the token lives 30 minutes
MAX_REFRESH = 3
_RETRY_429 = 6

GLOBAL_DOMAIN = "e276abec-e0f2-11e3-8169-6d9ed49b625f"   # the Global domain, the same on every FMC
CDFMC_REGIONS = {
    "us": "api.us.security.cisco.com",
    "eu": "api.eu.security.cisco.com",
    "apj": "api.apj.security.cisco.com",
    "au": "api.au.security.cisco.com",
    "in": "api.in.security.cisco.com",
    "uae": "api.uae.security.cisco.com",
}


class FmcError(RuntimeError):
    """A transport failure, worded for the operator, without the credential."""


class FmcAuthError(FmcError):
    """The Management Center refused the credentials."""


def _request(method: str, url: str, *, headers: dict, params: dict | None = None,
             auth: tuple | None = None, timeout=(_CONNECT_TIMEOUT, _READ_TIMEOUT)):
    """The one HTTP call of this module: (status, json body or None, headers).
    Injectable in the clients for the tests."""
    try:
        r = requests.request(method, url, headers=headers, params=params, auth=auth,
                             verify=False, timeout=timeout)
    except requests.RequestException as exc:
        raise FmcError(f"the Management Center did not answer: {exc.__class__.__name__}")
    body = None
    if r.text:
        try:
            body = r.json()
        except ValueError:
            body = None
    return r.status_code, body, dict(r.headers)


class FmcAuth:
    """On-premises Management Center: token login with basic auth."""

    kind = "fmc"
    prefix = "/api"

    def __init__(self, host: str, username: str, password: str, port: int = 443, *,
                 _request=_request, _clock=time.monotonic):
        self.host, self.port = host, int(port or 443)
        self.base = f"https://{host}:{self.port}"
        self._user, self._password = username, password
        self._req, self._clock = _request, _clock
        self._access: str | None = None
        self._refresh: str | None = None
        self._issued = 0.0
        self._refreshes = 0
        self.domains: list[dict] = []       # [{name, uuid}] from the login headers
        self.default_domain: str = GLOBAL_DOMAIN

    def __repr__(self) -> str:   # never the password
        return f"FmcAuth({self.host})"

    def login(self) -> None:
        status, _body, hdr = self._req("POST", f"{self.base}/api/fmc_platform/v1/auth/generatetoken",
                                       headers={}, auth=(self._user, self._password))
        if status in (401, 403):
            raise FmcAuthError("the Management Center refused the login: check the user, the password "
                               "and that the role allows the REST API")
        if status != 204 and status != 200:
            raise FmcError(f"the Management Center answered the login with HTTP {status}")
        access = hdr.get("X-auth-access-token") or hdr.get("x-auth-access-token")
        if not access:
            raise FmcError("the Management Center answered the login without an access token")
        self._access = access
        self._refresh = hdr.get("X-auth-refresh-token") or hdr.get("x-auth-refresh-token")
        self._issued = self._clock()
        self._refreshes = 0
        self.default_domain = (hdr.get("DOMAIN_UUID") or hdr.get("domain_uuid") or GLOBAL_DOMAIN)
        raw = hdr.get("DOMAINS") or hdr.get("domains") or "[]"
        try:
            doms = json.loads(raw)
        except ValueError:
            doms = []
        self.domains = [{"name": d.get("name"), "uuid": d.get("uuid")} for d in doms
                        if isinstance(d, dict) and d.get("uuid")]
        if not self.domains:
            self.domains = [{"name": "Global", "uuid": self.default_domain}]

    def _refresh_token(self) -> None:
        status, _body, hdr = self._req("POST", f"{self.base}/api/fmc_platform/v1/auth/refreshtoken",
                                       headers={"X-auth-access-token": self._access or "",
                                                "X-auth-refresh-token": self._refresh or ""})
        access = hdr.get("X-auth-access-token") or hdr.get("x-auth-access-token")
        if status not in (200, 204) or not access:
            self.login()
            return
        self._access = access
        self._refresh = hdr.get("X-auth-refresh-token") or hdr.get("x-auth-refresh-token") or self._refresh
        self._issued = self._clock()
        self._refreshes += 1

    def headers(self) -> dict:
        if not self._access:
            self.login()
        elif self._clock() - self._issued >= TOKEN_REFRESH_AT:
            if self._refreshes < MAX_REFRESH:
                self._refresh_token()
            else:
                self.login()
        return {"X-auth-access-token": self._access or "", "Accept": "application/json"}

    def relogin(self) -> None:
        """After a 401 on a call: one fresh login."""
        self._access = None
        self.login()

    def domain_list(self) -> list[dict]:
        if not self._access:
            self.login()
        return list(self.domains)


class CdfmcAuth:
    """Cloud-delivered Management Center in Security Cloud Control: a bearer
    API token on the regional gateway."""

    kind = "cdfmc"
    prefix = "/v1/cdfmc/api"

    def __init__(self, region: str, token: str, *, _request=_request):
        region = (region or "").strip().lower()
        if region not in CDFMC_REGIONS:
            raise FmcError("Security Cloud Control region must be one of " + ", ".join(CDFMC_REGIONS))
        self.region = region
        self.host = CDFMC_REGIONS[region]
        self.base = f"https://{self.host}/firewall"
        self._token = token
        self._req = _request
        self.domains: list[dict] = []
        self.default_domain: str = GLOBAL_DOMAIN

    def __repr__(self) -> str:   # never the token
        return f"CdfmcAuth({self.region})"

    def login(self) -> None:
        """The inventory call names the tenant's cdFMC and its domain UUID
        (DevNet "Getting Started"); the Global UUID stands in when the call
        does not answer the field."""
        status, body, _hdr = self._req("GET", f"{self.base}/v1/inventory/managers",
                                       headers=self.headers(), params={"q": "deviceType:CDFMC"})
        if status in (401, 403):
            raise FmcAuthError("Security Cloud Control refused the API token")
        items = (body or {}).get("items") if isinstance(body, dict) else None
        first = items[0] if items else {}
        uid = (first or {}).get("fmcDomainUid") or GLOBAL_DOMAIN
        self.default_domain = uid
        self.domains = [{"name": "Global", "uuid": uid, "manager": first or {}}]

    def headers(self) -> dict:
        return {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}

    def relogin(self) -> None:
        raise FmcAuthError("Security Cloud Control refused the API token")

    def domain_list(self) -> list[dict]:
        if not self.domains:
            self.login()
        return list(self.domains)


class FmcClient:
    """GETs against the configuration and platform APIs through either auth."""

    def __init__(self, auth, *, _request=_request, _sleep=time.sleep):
        self.auth = auth
        self._req, self._sleep = _request, _sleep
        self.calls = 0

    @property
    def kind(self) -> str:
        return self.auth.kind

    def url(self, path: str) -> str:
        return f"{self.auth.base}{self.auth.prefix}{path}"

    @staticmethod
    def cfg(domain: str, path: str) -> str:
        return f"/fmc_config/v1/domain/{domain}{path}"

    def get(self, path: str, params: dict | None = None, *, tolerate: tuple = ()) -> dict | None:
        """One GET with the 429 backoff and one re-login on 401. `tolerate`
        lists the statuses that answer None instead of raising (a 404 on a
        resource the FMC version does not have)."""
        relogged = False
        for attempt in range(_RETRY_429 + 1):
            self.calls += 1
            status, body, hdr = self._req("GET", self.url(path), headers=self.auth.headers(), params=params)
            if status == 429 and attempt < _RETRY_429:
                try:
                    wait = float(hdr.get("Retry-After") or 0)
                except ValueError:
                    wait = 0.0
                self._sleep(wait if wait > 0 else 2.0 * (attempt + 1))
                continue
            if status == 401 and not relogged:
                relogged = True
                self.auth.relogin()
                continue
            if status in tolerate:
                return None
            if status == 401 or status == 403:
                raise FmcAuthError(f"the Management Center refused {path.rsplit('/', 1)[-1]} (HTTP {status})")
            if status >= 400:
                msg = ""
                if isinstance(body, dict):
                    err = body.get("error") or {}
                    msgs = err.get("messages") if isinstance(err, dict) else None
                    if msgs and isinstance(msgs, list) and isinstance(msgs[0], dict):
                        msg = str(msgs[0].get("description") or "")[:160]
                raise FmcError(f"the Management Center answered {path.rsplit('/', 1)[-1]} with HTTP {status}"
                               + (f": {msg}" if msg else ""))
            return body if isinstance(body, dict) else {}
        raise FmcError("the Management Center keeps answering 429 (rate limit), try again in a minute")

    def get_all(self, path: str, *, expanded: bool = True, limit: int = PAGE_LIMIT,
                tolerate: tuple = (), params: dict | None = None) -> list[dict]:
        """Every item of a list resource, page by page."""
        items: list[dict] = []
        offset = 0
        while True:
            q = {"offset": offset, "limit": min(limit, PAGE_LIMIT), **(params or {})}
            if expanded:
                q["expanded"] = "true"
            body = self.get(path, q, tolerate=tolerate)
            if body is None:
                return items
            page = body.get("items") or []
            items.extend(i for i in page if isinstance(i, dict))
            count = (body.get("paging") or {}).get("count")
            if not page or count is None or offset + len(page) >= int(count):
                return items
            offset += len(page)

    def count(self, path: str, *, tolerate: tuple = (404,), params: dict | None = None) -> int:
        """The item count of a list resource from one one-item page."""
        body = self.get(path, {"offset": 0, "limit": 1, **(params or {})}, tolerate=tolerate)
        if body is None:
            return 0
        count = (body.get("paging") or {}).get("count")
        return int(count) if count is not None else len(body.get("items") or [])

    def server_version(self) -> str:
        """`serverVersion` of the platform API, "" when the deployment does
        not answer it (the cloud-delivered gateway may not)."""
        try:
            body = self.get("/fmc_platform/v1/info/serverversion", tolerate=(404, 403, 400))
        except FmcAuthError:
            raise
        except FmcError:
            return ""
        items = (body or {}).get("items") or []
        return str((items[0] if items else {}).get("serverVersion") or "")


def fmc_client_for(device: dict) -> FmcClient:
    """The client of a registered Management Center row: `config.fmc`
    carries the username (on-premises) or the cloud region, the secret
    sits in api_key, the address in mgmt_ip (docs/FMC_SOURCE_PLAN.md D2)."""
    from deploy.base import management_host
    try:
        cfg = json.loads(device.get("config") or "{}").get("fmc") or {}
    except Exception:
        cfg = {}
    secret = device.get("api_key") or ""
    cloud = cfg.get("cloud") or {}
    if cloud:
        return FmcClient(CdfmcAuth(cloud.get("region") or "", secret))
    host = management_host(device.get("mgmt_ip") or device.get("host_name"), "Management Center")
    return FmcClient(FmcAuth(host, cfg.get("username") or "admin", secret, device.get("mgmt_port") or 443))
