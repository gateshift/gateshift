# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""Device-add glue for the cloud sources: the config builder the CE add
route consults, and the bundle upload route."""
from __future__ import annotations

import json
import pathlib

from fastapi import Request
from fastapi.responses import FileResponse, RedirectResponse
from sqlalchemy import text

from . import PLATFORMS, SECRET_LABELS

# The collector scripts the upload dialog offers: run where the provider's
# CLI is signed in (its Cloud Shell), they write the bundle to upload.
COLLECTORS = {key: pathlib.Path(__file__).parent / "collectors" / f"gateshift-collect-{key}.sh" for key in PLATFORMS}


async def cloud_collector(platform: str):
    """GET /devices/add/cloud/collector/{platform}: the collector script
    for the platform, as a download."""
    path = COLLECTORS.get(platform)
    if path is None or not path.is_file():
        return RedirectResponse("/projects?form_error=no+collector+for+this+platform", status_code=303)
    return FileResponse(str(path), media_type="text/x-shellscript", filename=path.name)

# The non-secret ids each platform keeps in config.<platform>, as posted by
# the add and edit forms (cloud_<key>).
ID_FIELDS = {
    "aws": ("access_key_id", "regions", "vpc_ids"),
    "azure": ("tenant_id", "client_id", "subscription_id", "resource_groups"),
    "gcp": ("project_id", "client_email", "networks"),
}


def _first(form, key: str) -> str:
    """The first non-empty value of a form field. The add form renders one
    block per platform and the secret field repeats across blocks, so a
    plain get() would return the last (empty) one."""
    values = form.getlist(key) if hasattr(form, "getlist") else [form.get(key)]
    return next((str(v).strip() for v in values if v is not None and str(v).strip()), "")


def build_cloud_config(platform: str, form) -> tuple[str, None, str | None] | None:
    """(config_json, mgmt_ip, api_key) for the CE add route, or None when
    the form carries no ids for this platform (the upload path)."""
    keys = ID_FIELDS.get(platform)
    if not keys:
        return None
    block = {k: _first(form, f"cloud_{k}") for k in keys}
    block = {k: v for k, v in block.items() if v}
    secret = _first(form, "cloud_secret") or None
    if platform == "gcp" and secret:
        # the service-account key names the project and the principal
        key = PLATFORMS["gcp"][1].parse_key(secret)
        if not key:
            # say what the key is, not "Project ID is required" (2026-10-18:
            # a pasted private key alone, without the JSON around it)
            raise ValueError("Google Cloud: the service account key is not the JSON file Google Cloud "
                             "created (type service_account with project_id, client_email and "
                             "private_key), the account was not added")
        block.setdefault("project_id", str(key.get("project_id") or "").strip())
        block["client_email"] = str(key.get("client_email") or "").strip()
        block = {k: v for k, v in block.items() if v}
    # The add route registers nothing from an incomplete form: every id the
    # reader needs and the secret must be there, the sentence names what is
    # missing (found 2026-10-18: an AWS account without a region, and a
    # form without ids, were accepted and could never import).
    required = {"aws": (("access_key_id", "Access key ID"), ("regions", "Regions")),
                "azure": (("tenant_id", "Tenant ID"), ("client_id", "Client ID"), ("subscription_id", "Subscription ID")),
                "gcp": (("project_id", "Project ID"),)}
    missing = [label for key, label in required.get(platform, ()) if not block.get(key)]
    if not secret:
        missing.append(SECRET_LABELS.get(platform, "secret"))
    if missing:
        raise ValueError(f"{PLATFORMS[platform][0]}: {', '.join(missing)} "
                         f"{'is' if len(missing) == 1 else 'are'} required, the account was not added")
    return json.dumps({platform: block}), None, secret


async def cloud_upload(request: Request):
    """POST /devices/add/cloud/upload: register a cloud account from an
    exported bundle (no credentials in Gateshift)."""
    import main as _main
    form = await request.form()
    platform = str(form.get("platform") or "").strip()
    name = str(form.get("cloud_name") or "").strip()
    entry = PLATFORMS.get(platform)
    if not entry or not name:
        return RedirectResponse("/projects?form_error=cloud+upload+needs+a+platform+and+a+name", status_code=303)
    upload = form.get("bundle")
    raw = ""
    if upload is not None and hasattr(upload, "read"):
        raw = (await upload.read()).decode("utf-8", "replace")
    data, err = entry[1].validate_bundle(raw)
    if err:
        return RedirectResponse(f"/projects?form_error={err.replace(' ', '+')}", status_code=303)
    config_json = json.dumps({platform: {"bundle": json.dumps(data)}})
    engine = _main.get_engine()
    with engine.begin() as conn:
        _main._ensure_devices_table(conn)
        conn.execute(text("""
            INSERT INTO fw_devices (host_name, platform, role, notes, config, tenant_id)
            VALUES (:hn, :pl, 'source', :notes, :config, :tn)
            ON DUPLICATE KEY UPDATE platform=:pl, notes=:notes, config=:config
        """), {"hn": name, "pl": platform, "notes": str(form.get("notes") or "").strip() or None,
               "config": config_json, "tn": _main._form_tenant(request, form, conn)})
    return RedirectResponse(f"/projects?added={name.replace(' ', '+')}", status_code=303)
