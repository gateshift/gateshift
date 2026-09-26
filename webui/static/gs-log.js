// Copyright (c) 2026 Timo Duttine
// SPDX-License-Identifier: BUSL-1.1

/* Shared activity-log widget over fw_deploy_jobs/_events.
   Used by the Deploy tab (rules.html) and the Device Registry
   (devices.html). Rows render into #push-history-list; the filter
   context comes from window._deviceId/_targetId when the page defines
   them (deploy tab: source OR target), otherwise the log is global.
   The attach button appears only where the page provides
   attachPushJob (deploy tab reattach path). */
(function () {
  /* Literal signal colors: since the reskin the legacy tokens are
     aliases (--green -> accent blue, --red/--amber -> muted grey), so
     failure rows silently lost their red. Status words are SIGNALS, not
     chips - they keep real colors. */
  var TONE = {done: 'var(--accent)',
              failed: '#e05c5c', refused: '#e05c5c',
              running: 'var(--accent)',
              staged: '#d4a017',
              interrupted: 'var(--tx3)'};

  function esc(s) {
    var d = document.createElement('div');
    d.textContent = String(s == null ? '' : s);
    return d.innerHTML;
  }

  function jsonRes(r) {
    return r.json().then(function (d) { return {ok: r.ok, data: d}; });
  }

  /* Step renderer - also used by the push/publish overlay streams in
     rules.html, hence the global name. */
  window._logStep = function (logEl, data) {
    var p = document.createElement('p');
    if (data.success) {
      p.className = 'text-green-400';
      p.textContent = '[OK] ' + data.step + (data.detail ? ' — ' + data.detail : '');
    } else {
      p.className = 'text-red-400';
      p.textContent = '[FAIL] ' + data.step + ' — ' + data.detail;
    }
    logEl.appendChild(p);
    logEl.scrollTop = logEl.scrollHeight;
    // Re-arm the overlay watchdog on every progress event so a long push
    // with frequent updates doesn't get falsely cleared at the 150 s mark.
    // Silence > 150 s still trips the watchdog (real hang signal).
    if (typeof window._armOverlayWatchdog === 'function') window._armOverlayWatchdog();
  };

  // A log row that stems from a different source than the page's context
  // names that source, so its origin is unambiguous. Without a device
  // context (registry page) every row names its source.
  function foreignSrc(j) {
    if (typeof window._deviceId !== 'number') return true;
    return !!(j.source_id && j.source_id !== window._deviceId);
  }

  function histRowHtml(j) {
    var tone = TONE[j.status] || 'var(--tx2)';
    var isPipe = (j.kind === 'pipeline');
    // import/collect rows are device-scoped (no target): "import · <device>"
    var isSrcOnly = (j.kind === 'import' || j.kind === 'collect');
    // upload rows are GLOBAL (no device at all): "upload · failed · reason"
    var isUpload = (j.kind === 'upload');
    var kindChip = (j.kind === 'generate')
      ? '<span class="pp on">generate</span>'
      : (isPipe || isSrcOnly || isUpload
          ? '<span class="pp on">' + esc(j.kind) + '</span>'
          : '<span class="pp on">' + esc(j.strand) + '</span>');
    var dur = (j.duration_s != null && j.status !== 'running')
      ? (j.duration_s + 's') : '';
    var summary = j.summary
      ? ' · <span style="color:var(--tx3);">' + esc(String(j.summary).slice(0, 120)) + '</span>'
      : '';
    var attach = (j.status === 'running' && typeof window.attachPushJob === 'function')
      ? ' <button type="button" class="btn sm" onclick="event.stopPropagation();attachPushJob(\'' + j.job_id + '\', \'' + j.strand + '\')">attach</button>'
      : '';
    var who;
    if (isUpload) {
      who = '';
    } else if (isPipe) {
      who = ' · <span>' + esc(j.target_name) + '</span>';
    } else if (isSrcOnly) {
      who = ' · <span>' + esc(j.source_name) + '</span>';
    } else {
      who = (foreignSrc(j) ? ' · <span>' + esc(j.source_name) + '</span> → ' : ' → ')
        + '<span>' + esc(j.target_name) + '</span>';
    }
    return '<div style="border-bottom:1px solid var(--line);padding:5px 0;cursor:pointer;"'
      + ' onclick="toggleHistJob(this, \'' + j.job_id + '\')">'
      + '<span style="color:var(--tx3);">' + esc(j.created_at) + '</span> · '
      + kindChip + who + ' · '
      + '<span style="color:' + tone + ';font-weight:600;">' + esc(j.status) + '</span>'
      + (dur ? ' · <span style="color:var(--tx3);">' + dur + '</span>' : '')
      + ' · <span style="color:var(--tx3);">' + j.steps + ' step(s)</span>'
      + summary + attach
      + '<div class="hist-steps hidden" style="margin-top:6px;padding-left:10px;border-left:2px solid var(--line);"></div>'
      + '</div>';
  }

  window.toggleHistJob = function (rowEl, jobId) {
    var det = rowEl.querySelector('.hist-steps');
    if (!det) return;
    if (!det.classList.contains('hidden')) { det.classList.add('hidden'); return; }
    det.classList.remove('hidden');
    if (det.dataset.loaded) return;
    det.textContent = 'loading…';
    fetch('/deploy/push/' + jobId).then(jsonRes).then(function (res) {
      if (!res.ok) { det.textContent = 'log unavailable'; return; }
      det.textContent = '';
      det.dataset.loaded = '1';
      (res.data.events || []).forEach(function (e) {
        window._logStep(det, {step: e.step, success: e.success, detail: e.detail});
      });
    }).catch(function () { det.textContent = 'log unavailable'; });
  };

  window.loadPushHistory = function () {
    var box = document.getElementById('push-history-list');
    if (!box) return;
    box.innerHTML = '<span class="mut">loading…</span>';
    var srcId = (typeof window._deviceId === 'number') ? window._deviceId : 0;
    var tgtId = (typeof window._targetId === 'number') ? window._targetId : 0;
    fetch('/deploy/history?source_id=' + srcId + '&target_id=' + tgtId + '&limit=30')
      .then(jsonRes).then(function (res) {
        if (!res.ok) { box.textContent = (res.data && res.data.error) || 'history failed'; return; }
        var jobs = (res.data && res.data.jobs) || [];
        if (!jobs.length) {
          box.innerHTML = '<span class="mut">no log entries yet</span>';
          return;
        }
        box.innerHTML = jobs.map(histRowHtml).join('');
      })
      .catch(function () { box.textContent = 'history failed'; });
  };
})();
