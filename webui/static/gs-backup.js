// Copyright (c) 2026 Timo Duttine
// SPDX-License-Identifier: BUSL-1.1

// Device configuration backup - the one-click half of devicebackup.py,
// shared by the Devices tab (row button) and the push dialog (the reminder
// for a target without staging). Goes through fetch so an error lands as a
// toast and the server's caveat (X-Gateshift-Warning, e.g. an uncommitted
// PA candidate) can be shown; the bytes go straight into a download and
// are kept nowhere. Needs base.html's _setOverlay / showToast and, where
// present, gs-log.js's loadPushHistory.
function deviceBackup(id, host) {
  _setOverlay(true, 'Pulling the running configuration from ' + host + '…');
  return fetch('/devices/' + id + '/backup')
    .then(function (r) {
      if (!r.ok) {
        return r.json().then(function (j) { throw new Error(j.error || ('HTTP ' + r.status)); });
      }
      var warn = r.headers.get('X-Gateshift-Warning');
      var m = /filename="([^"]+)"/.exec(r.headers.get('Content-Disposition') || '');
      return r.blob().then(function (b) {
        return {blob: b, name: m ? m[1] : ('gateshift-backup-' + host + '.txt'), warn: warn};
      });
    })
    .then(function (d) {
      var url = URL.createObjectURL(d.blob);
      var a = document.createElement('a');
      a.href = url; a.download = d.name; document.body.appendChild(a); a.click();
      setTimeout(function () { URL.revokeObjectURL(url); a.remove(); }, 1000);
      showToast('Backup of ' + host + ' downloaded - ' + d.name, 'success');
      if (d.warn) showToast(d.warn, 'info', 10000);
      if (window.loadPushHistory) loadPushHistory();
      return true;
    })
    .catch(function (e) { showToast('Backup failed: ' + e.message, 'error', 9000); return false; })
    .finally(function () { _setOverlay(false); });
}
window.deviceBackup = deviceBackup;
