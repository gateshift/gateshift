# Copyright (c) 2026 Timo Duttine
# SPDX-License-Identifier: BUSL-1.1

"""
Freshness of the target configuration artefact (docs/DEPLOY_PAGE_DESIGN.md, E4).

One project holds one artefact: the sections a build rendered, the Review
report and the summary the page shows. The push sends that stored artefact and
never renders anew, so the one question this module answers is whether the
stored build is still the build the operator may push.

Two things make it outdated, and they are not the same kind of event:

  E4a  the project changed - a curation edit, a re-import, a target setting.
       Writers stamp stale_<strand>_at, and a stamp younger than the moment
       the build started reading its inputs (built_from_at) stales that
       strand. The stamp carries the time, so the page can name it.

  E4b  Gateshift changed - a renderer fix, a new validation, a Review change
       between versions. Nothing in the project moved, so there is no stamp
       and no time to show: the artefact simply came out of another version of
       the code. It stales BOTH strands, because which renderer ran is not a
       per-strand question.

The functions are pure (no SQL, no clock, no app imports) so the decision can
be tested on its own. main.py reads the row and hands it in; the DB clock
stamps both sides of the timestamp comparison, so app and DB time zones never
meet.
"""

STRANDS = ("policy", "network")


def version_stale(built_version, app_version) -> bool:
    """True when another Gateshift version rendered the artefact (E4b).

    An empty built_version - a row written before the column existed - counts
    as another version, so the first read after the upgrade rebuilds it once.
    """
    return (str(built_version or "")) != (str(app_version or ""))


def staleness(built_from_at, stale_at_by_strand, built_version, app_version) -> dict:
    """The artefact's staleness, per strand and by cause.

    built_from_at         when the build started reading its inputs
    stale_at_by_strand    {"policy": stamp|None, "network": stamp|None}
    built_version         the version stored on the artefact
    app_version           the version running now

    Returns {"stale": {strand: bool}, "stale_at": {strand: stamp|None},
             "stale_version": bool}. stale_at holds only the EDIT stamps: a
    version change has no edit behind it, and a reader that showed the stamp
    for it would claim an edit that never happened.
    """
    vstale = version_stale(built_version, app_version)
    stale, stale_at = {}, {}
    for s in STRANDS:
        st = (stale_at_by_strand or {}).get(s)
        edited = bool(st and (built_from_at is None or st > built_from_at))
        stale[s] = edited or vstale
        stale_at[s] = st if edited else None
    return {"stale": stale, "stale_at": stale_at, "stale_version": vstale}


def stale_reason(stale_at_for_strand, version_is_stale, built_version, app_version) -> str:
    """Why a strand is outdated, in the operator's terms - the one wording the
    push refusal, the state line and the Review finding all read from."""
    # a row from before the column has no version to name, and inventing one
    # would be worse than saying it is older
    who = f"Gateshift {built_version}" if built_version else "an earlier Gateshift version"
    if stale_at_for_strand and version_is_stale:
        return f"edits since it was built, and {who} built it"
    if version_is_stale:
        return f"{who} built it, this is {app_version}"
    return "edits since it was built"
