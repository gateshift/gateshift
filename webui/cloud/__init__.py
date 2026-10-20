# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""Cloud sources: hyperscaler firewalls read as SOURCES (Microsoft Azure,
Amazon Web Services, Google Cloud).

Each provider module is a pure parser plus a thin fetcher; `register()`
wires its import/collect entry points into the registries of main and adds
the platform to the lists the UI consults (labels, zone-native platforms,
the source kinds the Overview counts); `init_app()` adds the add-form
builder and the upload and collector routes. Part of the Community Edition
since 0.9.4 (docs/CLOUD_SOURCES_PLAN.md, D1): an account, a subscription or
a project is one source, not a manager.
"""
from . import aws, azure, gcp

# platform key -> (label, module, kinds the Overview counts for the source)
PLATFORMS = {
    "aws": ("Amazon Web Services", aws,
            {"interfaces", "zones", "vrfs", "routes", "rules", "objects", "groups"}),
    "azure": ("Microsoft Azure", azure,
              {"interfaces", "zones", "vrfs", "routes", "rules", "objects", "groups"}),
    "gcp": ("Google Cloud", gcp,
            {"interfaces", "zones", "vrfs", "routes", "rules", "objects", "groups"}),
}

# what the secret field of each platform holds (the CE templates label it)
SECRET_LABELS = {"aws": "Secret access key", "azure": "Client secret", "gcp": "Service account key (JSON)"}


def _guarded(label, fn, error_cls):
    """The import route knows one failure class (`_ImportAuthError`, shown
    as a clean message with a device-log entry); a provider's refusal, a
    disabled API or an unreachable endpoint must arrive as that, not as a
    500. The modules stay free of main, so the translation lives here."""
    def run(device):
        try:
            return fn(device)
        except (RuntimeError, ValueError, OSError) as exc:
            raise error_cls(f"{label}: {exc}") from exc
        except Exception as exc:
            if type(exc).__name__.endswith("AuthError"):
                raise error_cls(f"{label}: {exc}") from exc
            raise
    return run


def register(main) -> None:
    for key, (label, module, kinds) in PLATFORMS.items():
        main._IMPORT_HANDLERS[key] = _guarded(label, module.run_import, main._ImportAuthError)
        main._COLLECT_HANDLERS[key] = module.collect_network
        main.PLATFORM_LABELS[key] = label
        main._OV_EXPECTED_KINDS[key] = set(kinds)
        main.CLOUD_SOURCE_PLATFORMS.add(key)
    main.CLOUD_SECRET_LABELS.update(SECRET_LABELS)
    main._ZONE_NATIVE_PLATFORMS = frozenset(main._ZONE_NATIVE_PLATFORMS | set(PLATFORMS))


def init_app(app, main) -> None:
    """Wire the cloud sources into the running app (called from the
    lifespan): the registries, the add-form config builder per platform,
    the bundle upload and the collector download."""
    from deploy.manager_backends import register_manager_config_builder
    from . import ui as cloud_ui
    register(main)
    for key in PLATFORMS:
        # an account builder, not a manager one: it must not switch the
        # enterprise manager UI on (2026-10-18)
        register_manager_config_builder(key, lambda form, _k=key: cloud_ui.build_cloud_config(_k, form),
                                        manager=False)
    app.add_api_route("/devices/add/cloud/upload", cloud_ui.cloud_upload, methods=["POST"])
    app.add_api_route("/devices/add/cloud/collector/{platform}", cloud_ui.cloud_collector, methods=["GET"])
