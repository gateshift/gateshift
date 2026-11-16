// Copyright (c) 2026 Timo Duttine
// SPDX-License-Identifier: BUSL-1.1

/* The step renderer of the push, publish and attach streams (rules.html).
   The project log itself is rendered by the Overview (_project_overview.html),
   so nothing else lives here. */
(function () {
  window._logStep = function (logEl, data) {
    var p = document.createElement('p');
    if (data.success) {
      p.className = 'text-green-400';
      p.textContent = '[OK] ' + data.step + (data.detail ? ': ' + data.detail : '');
    } else {
      p.className = 'text-red-400';
      p.textContent = '[FAIL] ' + data.step + ': ' + data.detail;
    }
    logEl.appendChild(p);
    logEl.scrollTop = logEl.scrollHeight;
    // Re-arm the overlay watchdog on every progress event so a long push
    // with frequent updates doesn't get falsely cleared at the 150 s mark.
    // Silence > 150 s still trips the watchdog (real hang signal).
    if (typeof window._armOverlayWatchdog === 'function') window._armOverlayWatchdog();
  };
})();
