# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""Manager-deploy backend registry (Community-Edition side).

A target may be pushed DIRECTLY (its own device API) or THROUGH a manager
(Panorama / FortiManager). The manager-push logic is an ENTERPRISE feature - its
code is NOT shipped in the Community Edition. An enterprise module registers its
driver subclasses here at startup (when a valid licence loads it, see the lifespan
`import enterprise` hook). The CE keeps only this thin registry + push-time
resolution + a gate for manager configs whose handler isn't loaded.

Design: config-driven, mirroring the CP manager-vs-gateway split. See
[[manager-deploy-scope]] + [[ce-ee-split-plan]].
"""
from __future__ import annotations

import json

# (platform, config_key) -> enterprise driver subclass (registered by the EE module)
_MANAGER_DRIVERS: dict[tuple[str, str], type] = {}

# Manager config-keys whose logic has been EXTRACTED to the enterprise module. A
# device carrying one of these but with no registered handler (EE absent /
# unlicensed) is GATED - we never silently mis-push it as a direct device. This
# set grows as each manager is extracted (P2: fortimanager, P3: panorama); while a
# manager's code still lives in the CE driver, its key is NOT here, so it keeps
# working via the CE class.
GATED_MANAGER_KEYS: set[str] = {"fortimanager", "panorama"}  # P2 FMG + P3 Panorama in the EE module

# The config-key names the CE recognises as "manager-managed" (just strings - no
# enterprise logic). Used for the presence check only.
_KNOWN_MANAGER_KEYS = ("panorama", "fortimanager")


def register_manager_driver(platform: str, config_key: str, cls: type) -> None:
    """Called by the enterprise module at load time."""
    _MANAGER_DRIVERS[(platform, config_key)] = cls


def device_manager_key(device: dict) -> str | None:
    """The manager config-key present in the device config (panorama /
    fortimanager), or None. Pure key-presence check - carries no enterprise
    logic, so it's safe in the CE."""
    try:
        cfg = json.loads(device.get("config") or "{}")
    except Exception:
        return None
    for key in _KNOWN_MANAGER_KEYS:
        if isinstance(cfg.get(key), dict) and cfg.get(key):
            return key
    return None


class _EnterpriseGateDriver:
    """Stand-in for a manager target when the enterprise module isn't loaded:
    every push yields a clear 'Enterprise licence required' instead of a wrong
    direct push."""

    _LABELS = {"panorama": "Panorama", "fortimanager": "FortiManager"}

    def __init__(self, config_key: str):
        self._key = config_key

    def push(self, *, device, config, strand="policy", **_kw):
        from .base import StepResult
        label = self._LABELS.get(self._key, self._key)
        yield StepResult(
            step="Enterprise required", success=False,
            detail=(f"This target is managed via {label} - an Enterprise feature. "
                    f"Install the Enterprise module + a valid licence, or point the "
                    f"target at the device directly."))


def resolve_push_driver(platform: str, device: dict, ce_cls: type):
    """Pick the driver CLASS/factory for a push. Returns:
    - the enterprise manager driver, if the device is manager-managed AND its
      handler is registered (EE loaded);
    - a gate driver, if the manager-key is extracted-but-unregistered (unlicensed);
    - else the CE class (direct push, or a manager still handled inside the CE
      driver during the transition).
    The caller instantiates the result with `()`.
    """
    key = device_manager_key(device)
    if key is not None:
        cls = _MANAGER_DRIVERS.get((platform, key))
        if cls is not None:
            return cls
        if key in GATED_MANAGER_KEYS:
            return lambda: _EnterpriseGateDriver(key)
    return ce_cls


# ── device-add UI (enterprise-contributed) ───────────────────────
# The manager device-add UI (Panorama/FMG fieldsets + discover routes + the
# config building) is an enterprise feature. The EE module registers a config
# builder per platform; /devices/add + the devices template consult these so the
# CE ships no manager-UI logic.

_MANAGER_CONFIG_BUILDERS: dict[str, object] = {}


def register_manager_config_builder(platform: str, fn) -> None:
    _MANAGER_CONFIG_BUILDERS[platform] = fn


def build_manager_config(platform: str, form):
    """EE hook for /devices/add: from the add-device form, build
    (config_json, mgmt_ip, api_key) for a manager-managed target, or None.
    Returns None in the CE (no builder registered)."""
    fn = _MANAGER_CONFIG_BUILDERS.get(platform)
    return fn(form) if fn else None


def manager_ui_available() -> bool:
    """True when an enterprise module has contributed the manager device-add UI -
    the devices template gates the manager fieldsets on this."""
    return bool(_MANAGER_CONFIG_BUILDERS)
