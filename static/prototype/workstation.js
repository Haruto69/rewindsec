/* RewindSec 2.0 — the synthetic workstation client.
 *
 * WHAT THIS IS
 * ------------
 * A renderer and an input surface. It asks the server what the world is,
 * draws it, and sends back semantic actions — "open this message", "approve
 * this request". That is the whole of its job.
 *
 * WHAT IT IS NOT
 * --------------
 * It is not authoritative for anything factual. There is no world model here,
 * no consequence engine, no timers that decide what happens, and no copy of
 * the simulation to diverge from the server's. Every consequential change is
 * a server decision, arrives as a new snapshot, and survives a refresh because
 * it was persisted before this file ever heard about it.
 *
 * THE THREE KINDS OF STATE
 * ------------------------
 *   SNAP  the server's authoritative, learner-safe projection. Replaced
 *         wholesale on every update. Never edited in place.
 *   APP   per-application view state: which folder, which row is selected,
 *         an unsent draft. Presentation. Losing it costs nothing.
 *   WIN   window geometry, z-order, open/closed. Presentation. Deliberately
 *         not persisted as simulation truth: where a window sits is not a
 *         fact about the workplace.
 *
 * WHY THE CLIENT NEVER APPLIES A CONSEQUENCE OPTIMISTICALLY
 * ---------------------------------------------------------
 * A button may show that it was pressed. Nothing beyond that changes until
 * the server has accepted the action and returned the new truth. If the
 * request fails, the screen still shows what is actually true rather than
 * what we hoped would be.
 */
(function () {
  'use strict';

  // =========================================================================
  // Small helpers
  // =========================================================================

  function qs(selector, root) { return (root || document).querySelector(selector); }
  function qsa(selector, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(selector));
  }

  function esc(value) {
    return String(value === undefined || value === null ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function icon(name, extra) {
    return '<svg aria-hidden="true"' + (extra ? ' ' + extra : '')
      + '><use href="#i-' + name + '"></use></svg>';
  }

  function clamp(value, low, high) {
    return Math.max(low, Math.min(high, value));
  }

  function param(name) {
    return new URLSearchParams(window.location.search).get(name);
  }

  function csrfToken() {
    var meta = qs('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
  }

  // =========================================================================
  // State
  // =========================================================================

  var SNAP = null;    // the server's projection. The only factual truth here.
  var WIN = {};       // window geometry / open / focus. Presentation only.
  var APP = {};       // per-application view state. Presentation only.
  var NOTICE = null;  // transient server notice (a Practice confirmation)
  var seenNotifications = {};
  var pendingRequests = 0;
  var stream = null;
  var tickTimer = null;
  var noteSaveTimer = null;
  var ended = false;

  var APPS = {
    mail: { label: 'Mail', icon: 'mail', w: 1020, h: 660 },
    browser: { label: 'Browser', icon: 'globe', w: 940, h: 640 },
    files: { label: 'Files', icon: 'folder', w: 880, h: 560 },
    messages: { label: 'Messages', icon: 'chat', w: 800, h: 560 },
    authenticator: { label: 'Authenticator', icon: 'shield', w: 700, h: 560 },
    directory: { label: 'Directory', icon: 'book', w: 800, h: 560 },
    notes: { label: 'Notes', icon: 'note', w: 720, h: 500 }
  };

  var FOLDERS = [
    { id: 'inbox', label: 'Inbox', icon: 'mail' },
    { id: 'archive', label: 'Archive', icon: 'folder' },
    { id: 'sent', label: 'Sent', icon: 'reply' },
    { id: 'reported', label: 'Reported', icon: 'flag' },
    { id: 'deleted', label: 'Deleted', icon: 'trash' }
  ];

  var FOCUS_LABELS = {
    phishing: 'Phishing', ransomware: 'Ransomware', mfa: 'MFA',
    bec: 'BEC', mixed: 'Mixed'
  };
  var MODE_LABELS = {
    practice: 'Practice', simulation: 'Simulation', assessment: 'Assessment'
  };

  function defaultAppState() {
    return {
      mail: {
        folder: 'inbox', selected: null, search: '', headers: false,
        linkShown: null, composing: null, draft: '',
        // Forward is a compose flow, not a button that fires. These three
        // are presentation state only: nothing is sent, and no world state
        // exists, until Send posts one `mail.forward` and the authoritative
        // snapshot comes back.
        forwarding: null, forwardRecipient: null, forwardDraft: '',
        mobileDetail: false
      },
      browser: { tabs: [], active: 0, accountDraft: null },
      files: { location: null, selected: null, renaming: false },
      messages: { conversation: null, draft: '', mobileDetail: false },
      authenticator: { details: {} },
      directory: { search: '', selected: null, mobileDetail: false },
      notes: { selected: null }
    };
  }

  function flags() { return (SNAP && SNAP.session.flags) || {}; }

  // =========================================================================
  // Talking to the server
  // =========================================================================
  //
  // One request shape for everything. Each carries the revision the screen was
  // built from, so a submission the world has already moved past is refused by
  // the server instead of being applied twice.

  function request(path, options) {
    var opts = options || {};
    var init = {
      method: opts.method || 'GET',
      headers: { Accept: 'application/json' },
      credentials: 'same-origin'
    };
    if (opts.body !== undefined) {
      init.headers['Content-Type'] = 'application/json';
      init.headers['X-CSRF-Token'] = csrfToken();
      init.body = JSON.stringify(opts.body);
    }
    return fetch(path, init).then(function (response) {
      return response.json().catch(function () { return {}; })
        .then(function (payload) {
          if (!response.ok) {
            var error = new Error((payload.error && payload.error.message)
              || 'The workstation could not complete that.');
            error.status = response.status;
            error.code = payload.error && payload.error.code;
            error.detail = (payload.error && payload.error.detail) || {};
            throw error;
          }
          return payload;
        });
    });
  }

  var noticeTimer = null;

  /* Adopt the server's answer as the new truth.
   *
   * The revision is the whole change-detection mechanism: it moves on every
   * accepted mutation and on nothing else, so an unchanged revision means an
   * unchanged world and there is nothing to redraw. That matters because the
   * tick runs every few seconds and most ticks change nothing — redrawing
   * anyway would throw away the caret in a note, the selection in a search
   * box and the scroll position of every list, several times a minute, for
   * no reason at all. */
  function adopt(payload) {
    if (payload && payload.snapshot) {
      var previous = SNAP;
      var changed = !previous
        || payload.snapshot.session.revision !== previous.session.revision;
      SNAP = payload.snapshot;
      syncClock();
      if (payload.notice && payload.notice.kind === 'confirmation') {
        // Practice, and only Practice, confirms a good decision. The text is
        // the server's; how long it stays on screen is presentation, so it
        // lives here and is not persisted anywhere.
        NOTICE = { text: payload.notice.text };
        if (noticeTimer) { window.clearTimeout(noticeTimer); }
        noticeTimer = window.setTimeout(function () {
          NOTICE = null;
          render();
        }, 12000);
        changed = true;
      }
      if (changed) {
        syncToasts();
        render();
      }
    }
    return payload;
  }

  function refresh() {
    return request('/api/session').then(adopt);
  }

  /* Send one semantic action. The server decides what it means.
   *
   * On a stale revision the world has moved on since this screen was drawn —
   * usually because a consequence landed while the learner was reading. The
   * response is refused, nothing is applied twice, and the recovery is to
   * take the authoritative state and, for an observational action only,
   * try once more. A consequential action is never retried automatically:
   * repeating "release the payment" on the learner's behalf is not a
   * reconciliation, it is a second decision. */
  var OBSERVATIONAL = {
    'mail.open': 1, 'mail.inspect_headers': 1, 'mail.inspect_link': 1,
    'mail.inspect_attachment': 1, 'mail.open_link': 1, 'browser.navigate': 1,
    'files.inspect': 1, 'notifications.open': 1, 'notifications.mark_read': 1,
    'notes.create': 1, 'notes.open': 1, 'notes.save': 1, 'notes.delete': 1,
    'auth.inspect_request': 1, 'auth.inspect_history': 1, 'messages.open': 1,
    'directory.open': 1, 'session.acknowledge': 1
  };

  function send(action, target, params, retried) {
    if (!SNAP || ended) { return Promise.resolve(); }
    var payload = { action: action, revision: SNAP.session.revision };
    if (target !== undefined && target !== null) { payload.target = target; }
    if (params) { payload.params = params; }

    pendingRequests += 1;
    renderBusy();
    return request('/api/actions', { method: 'POST', body: payload })
      .then(adopt)
      .catch(function (error) {
        if (error.status === 409 && !retried) {
          return refresh().then(function () {
            if (OBSERVATIONAL[action]) {
              return send(action, target, params, true);
            }
            showTransient('The workstation moved on while that was on screen. '
              + 'It is up to date now — check it and try again if you still '
              + 'want to.');
          });
        }
        if (error.status === 410) {
          ended = true;
          showTransient('This session has finished.');
          return null;
        }
        if (error.status === 404 && error.code === 'no_session') {
          showTransient('This training session is no longer open.');
          return null;
        }
        // A network failure tells us nothing about whether the action was
        // applied, so we do not guess. We re-read the authoritative state.
        return refresh().catch(function () {
          showTransient('The workstation could not reach the server. Nothing '
            + 'has been assumed; try again in a moment.');
        });
      })
      .then(function (value) {
        pendingRequests -= 1;
        renderBusy();
        return value;
      });
  }

  function renderBusy() {
    var shell = qs('#pw-ws');
    if (shell) { shell.setAttribute('data-busy', pendingRequests > 0 ? '1' : '0'); }
  }

  // =========================================================================
  // Simulation clock
  // =========================================================================
  //
  // The server owns simulation time. This interpolates between updates purely
  // so the corner of the screen does not sit frozen, and resynchronises to the
  // server on every snapshot. Nothing here is ever read back to the server and
  // no simulation decision depends on it.

  var clockAnchor = { simMs: 0, wallMs: 0, rate: 12 };

  function syncClock() {
    if (!SNAP) { return; }
    clockAnchor = {
      simMs: SNAP.session.sim_time_ms,
      wallMs: Date.now(),
      rate: SNAP.session.clock_rate || 12
    };
  }

  function nowLabel() {
    if (!SNAP) { return '09:00'; }
    if (ended || !SNAP.session.active) { return SNAP.session.clock; }
    var simMs = clockAnchor.simMs + (Date.now() - clockAnchor.wallMs);
    var total = 9 * 60 + Math.floor((simMs * clockAnchor.rate) / 60000);
    var hh = Math.floor(total / 60) % 24;
    var mm = total % 60;
    return (hh < 10 ? '0' : '') + hh + ':' + (mm < 10 ? '0' : '') + mm;
  }

  // =========================================================================
  // Lookups over the snapshot
  // =========================================================================

  function findMail(id) {
    var list = SNAP.mail.messages;
    for (var i = 0; i < list.length; i += 1) {
      if (list[i].id === id) { return list[i]; }
    }
    return null;
  }

  function findFile(fileId) {
    var files = SNAP.files.files;
    for (var i = 0; i < files.length; i += 1) {
      if (files[i].id === fileId) {
        return { file: files[i], location: findLocation(files[i].location) };
      }
    }
    return null;
  }

  function findLocation(locationId) {
    var list = SNAP.files.locations;
    for (var i = 0; i < list.length; i += 1) {
      if (list[i].id === locationId) { return list[i]; }
    }
    return list[0] || { id: null, name: '' };
  }

  function filesIn(locationId) {
    return SNAP.files.files.filter(function (file) {
      return file.location === locationId;
    });
  }

  function findConversation(id) {
    for (var i = 0; i < SNAP.messages.length; i += 1) {
      if (SNAP.messages[i].id === id) { return SNAP.messages[i]; }
    }
    return null;
  }

  function findContact(id) {
    for (var i = 0; i < SNAP.directory.length; i += 1) {
      if (SNAP.directory[i].id === id) { return SNAP.directory[i]; }
    }
    return null;
  }

  function incident(key) {
    for (var i = 0; i < SNAP.incidents.length; i += 1) {
      if (SNAP.incidents[i].key === key) { return SNAP.incidents[i]; }
    }
    return null;
  }

  // =========================================================================
  // Window management  (presentation only)
  // =========================================================================

  var zCounter = 10;

  function areaSize() {
    var area = qs('#pw-workarea');
    return { w: area.clientWidth, h: area.clientHeight };
  }

  function canDrag() { return window.innerWidth >= 1024; }

  function openApp(appId, focusTarget) {
    if (!WIN[appId]) {
      var size = areaSize();
      var spec = APPS[appId];
      var n = Object.keys(WIN).length;
      var w = Math.min(spec.w, Math.max(320, size.w - 40));
      var h = Math.min(spec.h, Math.max(240, size.h - 40));
      var step = 34;
      var baseX = Math.max(16, Math.round((size.w - w) / 2) - step);
      var baseY = Math.max(12, Math.round((size.h - h) / 2) - 26 - step);
      WIN[appId] = {
        x: clamp(baseX + n * step, 8, Math.max(8, size.w - w - 8)),
        y: clamp(baseY + n * step, 8, Math.max(8, size.h - h - 8)),
        w: w, h: h, z: (zCounter += 1), open: true, minimized: false
      };
    } else {
      WIN[appId].open = true;
      WIN[appId].minimized = false;
      WIN[appId].z = (zCounter += 1);
    }
    if (focusTarget) { applyFocusTarget(appId, focusTarget); }
    render();
  }

  function reflowWindows() {
    var size = areaSize();
    Object.keys(WIN).forEach(function (appId) {
      var win = WIN[appId];
      if (win.maximized) { fillWorkarea(win); return; }
      win.w = Math.min(win.w, Math.max(320, size.w - 24));
      win.h = Math.min(win.h, Math.max(240, size.h - 24));
      win.x = clamp(win.x, 8, Math.max(8, size.w - win.w - 8));
      win.y = clamp(win.y, 8, Math.max(8, size.h - win.h - 8));
    });
  }

  function applyFocusTarget(appId, target) {
    if (appId === 'mail' && target.mail_id) {
      openMessage(target.mail_id);
    } else if (appId === 'files' && target.location_id) {
      APP.files.location = target.location_id;
    } else if (appId === 'messages' && target.conversation_id) {
      APP.messages.conversation = target.conversation_id;
      APP.messages.mobileDetail = true;
      send('messages.open', target.conversation_id);
    }
  }

  function closeApp(appId) {
    var win = WIN[appId];
    if (win) {
      win.open = false;
      // A closed window is a fresh start, not a paused one: reopening it
      // (openApp's "already exists" branch) must not come back stuck
      // maximised from whatever this instance was doing when it closed.
      // Restoring the saved geometry here (falling back to the size/position
      // openApp itself would have chosen, if there is none) means the next
      // open is an ordinary window, same as opening it for the first time.
      if (win.maximized) {
        var prev = win.restoreGeometry;
        win.maximized = false;
        win.restoreGeometry = null;
        if (prev) { win.x = prev.x; win.y = prev.y; win.w = prev.w; win.h = prev.h; }
        else { fitDefaultGeometry(appId, win); }
      }
    }
    render();
  }

  function minimiseApp(appId) {
    if (WIN[appId]) { WIN[appId].minimized = true; }
    render();
  }

  /* Maximise/restore, entirely presentation state (see the WIN comment at the
   * top of this file). Maximising remembers the window's pre-maximise
   * geometry so restoring puts it back exactly where it was, and the toggle
   * is idempotent against a resize: reflowWindows() keeps a maximised window
   * filling the work area rather than clamping it like an ordinary window. */
  function toggleMaximiseApp(appId) {
    var win = WIN[appId];
    if (!win) { return; }
    if (win.maximized) {
      var prev = win.restoreGeometry;
      win.maximized = false;
      win.restoreGeometry = null;
      if (prev) {
        win.x = prev.x; win.y = prev.y; win.w = prev.w; win.h = prev.h;
      } else {
        fitDefaultGeometry(appId, win);
      }
      // Clamp to the *current* work area: it may have been resized while
      // maximised, and a saved geometry from before that resize must never
      // be allowed to leave the restored window partly or fully offscreen.
      var size = areaSize();
      win.w = Math.min(win.w, Math.max(320, size.w - 24));
      win.h = Math.min(win.h, Math.max(240, size.h - 24));
      win.x = clamp(win.x, 8, Math.max(8, size.w - win.w - 8));
      win.y = clamp(win.y, 8, Math.max(8, size.h - win.h - 8));
    } else {
      win.restoreGeometry = { x: win.x, y: win.y, w: win.w, h: win.h };
      win.maximized = true;
      fillWorkarea(win);
    }
    win.z = (zCounter += 1);
    render();
  }

  /* A safe, centred normal-size geometry for appId, derived from its app
   * spec and the current work area -- the same sizing openApp uses for a
   * window that has never existed, reused wherever "maximised with nothing
   * to restore to" needs a default instead of throwing. */
  function fitDefaultGeometry(appId, win) {
    var size = areaSize();
    var spec = APPS[appId];
    var w = Math.min(spec.w, Math.max(320, size.w - 40));
    var h = Math.min(spec.h, Math.max(240, size.h - 40));
    win.w = w;
    win.h = h;
    win.x = clamp(Math.round((size.w - w) / 2), 8, Math.max(8, size.w - w - 8));
    win.y = clamp(Math.round((size.h - h) / 2), 8, Math.max(8, size.h - h - 8));
  }

  function fillWorkarea(win) {
    var size = areaSize();
    win.x = 4;
    win.y = 4;
    win.w = Math.max(320, size.w - 8);
    win.h = Math.max(240, size.h - 8);
  }

  function focusApp(appId) {
    if (WIN[appId]) { WIN[appId].z = (zCounter += 1); }
  }

  function topWindow() {
    var best = null;
    Object.keys(WIN).forEach(function (appId) {
      var win = WIN[appId];
      if (!win.open || win.minimized) { return; }
      if (!best || win.z > WIN[best].z) { best = appId; }
    });
    return best;
  }

  function captureFocus() {
    var active = document.activeElement;
    if (!active || !active.id) { return null; }
    return {
      id: active.id,
      start: active.selectionStart === undefined ? null : active.selectionStart,
      end: active.selectionEnd === undefined ? null : active.selectionEnd
    };
  }

  function restoreFocus(saved) {
    if (!saved) { return; }
    var node = document.getElementById(saved.id);
    if (!node) { return; }
    node.focus();
    if (saved.start !== null && node.setSelectionRange) {
      try { node.setSelectionRange(saved.start, saved.end); }
      catch (err) { /* not a text field any more */ }
    }
  }

  var scrollPositions = {};

  function captureScroll() {
    qsa('[data-scroll-key]').forEach(function (node) {
      // Responsive master/detail panes remain in the DOM while hidden. Some
      // browsers report their scrollTop as zero in that state; recording it
      // would erase the real list position just before the learner returns.
      if (!node.getClientRects().length) { return; }
      scrollPositions[node.getAttribute('data-scroll-key')] = {
        top: node.scrollTop, left: node.scrollLeft
      };
    });
  }

  function restoreScroll() {
    qsa('[data-scroll-key]').forEach(function (node) {
      var position = scrollPositions[node.getAttribute('data-scroll-key')];
      if (!position) { return; }
      node.scrollTop = position.top;
      node.scrollLeft = position.left;
    });
  }

  // =========================================================================
  // Rendering
  // =========================================================================

  function render() {
    if (!SNAP) { return; }
    var saved = captureFocus();
    captureScroll();
    renderTopBar();
    renderRail();
    renderDesk();
    renderWindows();
    renderNotifications();
    renderComparison();
    restoreScroll();
    restoreFocus(saved);
  }

  function renderTopBar() {
    if (!SNAP) { return; }
    qs('#pw-clock').textContent = nowLabel();
    qs('#pw-mode-label').textContent = MODE_LABELS[SNAP.session.mode]
      || SNAP.session.mode;
    qs('#pw-focus-chip').textContent = FOCUS_LABELS[SNAP.session.focus]
      || SNAP.session.focus;
    qs('#pw-assessment-chip').hidden = SNAP.session.mode !== 'assessment';

    var unread = SNAP.notifications.filter(function (n) { return n.unread; }).length;
    var badge = qs('#pw-notif-badge');
    badge.hidden = unread === 0;
    badge.textContent = unread;
  }

  function renderRail() {
    var unreadMail = SNAP.mail.messages.filter(function (m) {
      return m.unread && m.folder === 'inbox';
    }).length;
    var brokenFiles = SNAP.files.files.filter(function (f) {
      return f.state === 'unavailable';
    }).length;
    var unreadChats = SNAP.messages.filter(function (c) { return c.unread; }).length;
    var pendingAuth = SNAP.authenticator.requests.length;

    var counts = { mail: unreadMail, files: brokenFiles,
                   messages: unreadChats, authenticator: pendingAuth };
    qsa('[data-count]').forEach(function (node) {
      var value = counts[node.getAttribute('data-count')] || 0;
      node.hidden = value === 0;
      node.textContent = value;
    });
    qsa('.pw-applink').forEach(function (node) {
      var appId = node.getAttribute('data-app');
      node.classList.toggle('is-open', !!(WIN[appId] && WIN[appId].open));
    });
  }

  function renderDesk() {
    var outstanding = SNAP.tasks.filter(function (task) {
      return task.state === 'outstanding' || task.state === 'interrupted';
    });
    qs('#pw-desk-tasks').hidden = outstanding.length === 0;
    qs('#pw-desk-tasklist').innerHTML = outstanding.map(function (task) {
      return '<li>' + esc(task.label)
        + (task.note ? ' <span class="pw-muted">· ' + esc(task.note) + '</span>' : '')
        + '</li>';
    }).join('');
  }

  function windowSubtitle(appId) {
    if (appId === 'mail') { return SNAP.learner.email; }
    if (appId === 'files') { return SNAP.organization.workstation_id; }
    if (appId === 'browser') {
      return SNAP.session.network_disconnected ? 'offline' : '';
    }
    return '';
  }

  function renderWindows() {
    var host = qs('#pw-workarea');
    Object.keys(APPS).forEach(function (appId) {
      var win = WIN[appId];
      var node = qs('#pw-win-' + appId);
      if (!win || !win.open || win.minimized) {
        if (node) { dismissWindow(node, appId, win && win.minimized); }
        return;
      }
      if (!node) {
        node = document.createElement('section');
        node.className = 'pw-window';
        node.id = 'pw-win-' + appId;
        node.setAttribute('role', 'dialog');
        node.setAttribute('aria-label', APPS[appId].label);
        // Notes is the one learner application where copy, cut and paste work
        // normally. A learner who needs to keep something has somewhere to
        // keep it, which is what makes the restriction everywhere else
        // reasonable rather than merely obstructive. The marker goes on the
        // window itself so integrity.js can decide from the event target.
        if (appId === 'notes') { node.setAttribute('data-clipboard', 'allow'); }
        host.insertBefore(node, qs('#pw-notifpanel'));
        bindWindow(node, appId);
        if (!prefersReducedMotion()) { node.classList.add('is-entering'); }
      }
      node.style.left = win.x + 'px';
      node.style.top = win.y + 'px';
      node.style.width = win.w + 'px';
      node.style.height = win.h + 'px';
      node.style.zIndex = win.z;
      node.classList.toggle('is-maximized', !!win.maximized);

      var subtitle = windowSubtitle(appId);
      node.innerHTML = ''
        + '<header class="pw-winbar" data-drag="' + appId + '">'
        + '  <span class="pw-winbar-title">' + icon(APPS[appId].icon)
        + '    <b>' + esc(APPS[appId].label) + '</b>'
        + (subtitle ? '<span class="pw-winbar-sub">' + esc(subtitle) + '</span>' : '')
        + '  </span>'
        + '  <span class="pw-winbar-ctl">'
        + '    <button type="button" class="pw-winctl" data-win-min="' + appId
        + '" aria-label="Minimise">' + icon('minimise') + '</button>'
        + '    <button type="button" class="pw-winctl" data-win-max="' + appId
        + '" aria-label="' + (win.maximized ? 'Restore' : 'Maximise') + '">'
        + icon(win.maximized ? 'collapse' : 'expand') + '</button>'
        + '    <button type="button" class="pw-winctl" data-win-close="' + appId
        + '" aria-label="Close">' + icon('close') + '</button>'
        + '  </span>'
        + '</header>'
        + '<div class="pw-winbody">' + renderApp(appId) + '</div>';
    });
  }

  function dismissWindow(node, appId, minimising) {
    if (node.classList.contains('is-leaving')) { return; }
    if (prefersReducedMotion()) {
      node.parentNode.removeChild(node);
      return;
    }
    node.classList.add('is-leaving');
    if (minimising) { node.classList.add('is-minimising'); }
    window.setTimeout(function () {
      if (node.parentNode) { node.parentNode.removeChild(node); }
    }, 180);
  }

  function prefersReducedMotion() {
    return window.matchMedia
      && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }

  function renderApp(appId) {
    if (appId === 'mail') { return renderMail(); }
    if (appId === 'browser') { return renderBrowser(); }
    if (appId === 'files') { return renderFiles(); }
    if (appId === 'messages') { return renderMessages(); }
    if (appId === 'authenticator') { return renderAuthenticator(); }
    if (appId === 'directory') { return renderDirectory(); }
    if (appId === 'notes') { return renderNotes(); }
    return '';
  }

  // =========================================================================
  // Mail
  // =========================================================================

  function visibleMail() {
    var state = APP.mail;
    var term = state.search.trim().toLowerCase();
    return SNAP.mail.messages.filter(function (message) {
      if (term) {
        var haystack = [message.subject, message.from_name,
                        (message.body || []).join(' ')].join(' ').toLowerCase();
        return haystack.indexOf(term) >= 0;
      }
      return message.folder === state.folder;
    }).sort(function (a, b) { return b.order - a.order; });
  }

  function renderMail() {
    var state = APP.mail;
    var messages = visibleMail();
    var selected = state.selected ? findMail(state.selected) : null;

    var folders = FOLDERS.map(function (folder) {
      var count = SNAP.mail.messages.filter(function (m) {
        return m.folder === folder.id && m.unread;
      }).length;
      // Unread only, and nothing at all at zero. It must never fall back to
      // the folder's total: a fully-read Inbox of nine messages showing "9"
      // reads as nine things still to do. This is the same quantity the Mail
      // rail badge shows, so the two can never disagree.
      return '<button type="button" class="pw-navitem'
        + (state.folder === folder.id && !state.search ? ' is-active' : '') + '"'
        + ' data-mail-folder="' + folder.id + '">'
        + icon(folder.icon) + '<span>' + esc(folder.label) + '</span>'
        + '<span class="pw-navitem-count">' + (count || '') + '</span>'
        + '</button>';
    }).join('');

    var rows = messages.map(function (message) {
      var preview = (message.body || [''])[0] || '';
      return '<button type="button" class="pw-msgrow'
        + (message.unread ? ' is-unread' : '')
        + (state.selected === message.id ? ' is-active' : '') + '"'
        + ' data-mail-open="' + esc(message.id) + '">'
        + '<span class="pw-msgrow-top">'
        + '<span class="pw-msgrow-from">' + esc(message.from_name) + '</span>'
        + '<span class="pw-msgrow-time">' + esc(message.received) + '</span>'
        + '</span>'
        + '<span class="pw-msgrow-subject">' + esc(message.subject) + '</span>'
        + '<span class="pw-msgrow-preview">' + esc(preview.slice(0, 92)) + '</span>'
        + (message.reported || message.replied || message.forwarded
            || (message.attachments || []).length
            ? '<span class="pw-msgrow-flags">'
              + ((message.attachments || []).length
                  ? '<span class="pw-chip">' + icon('paperclip', 'style="width:11px;height:11px"')
                    + ' attachment</span>' : '')
              + (message.reported ? '<span class="pw-chip is-caution">reported</span>' : '')
              + (message.replied ? '<span class="pw-chip">replied</span>' : '')
              // A real forward leaves a real mark, exactly as a reply does.
              // Neutral chip: forwarding is neither encouraged nor warned
              // against, it is just a thing that happened to this message.
              + (message.forwarded ? '<span class="pw-chip">forwarded</span>' : '')
              + '</span>'
            : '')
        + '</button>';
    }).join('');

    if (!rows) {
      rows = '<div class="pw-empty"><h3>Nothing here</h3><p>'
        + (state.search ? 'No message matches that search.' : 'This folder is empty.')
        + '</p></div>';
    }

    return ''
      + '<div class="pw-app' + (state.mobileDetail ? ' is-split-mobile' : '') + '">'
      + '  <div class="pw-pane pw-sidepane">'
      + '    <div class="pw-pane-scroll" data-scroll-key="mail-folders"><div class="pw-nav">' + folders + '</div></div>'
      + '  </div>'
      + '  <div class="pw-pane pw-listpane">'
      + '    <div class="pw-pane-head">'
      + '      <label class="pw-search">' + icon('search')
      + '        <input type="search" id="pw-mail-search" placeholder="Search mail"'
      + '          aria-label="Search mail" value="' + esc(state.search) + '">'
      + '      </label>'
      + '    </div>'
      + (SNAP.mail.rule
          ? '<div class="pw-mailbanner">' + icon('info')
            + '<span>' + esc(SNAP.mail.rule) + '</span></div>'
          : '')
      + '    <div class="pw-pane-scroll" data-scroll-key="mail-list:'
      + esc(state.folder) + ':' + esc(state.search) + '">' + rows + '</div>'
      + '  </div>'
      + '  <div class="pw-pane pw-mainpane">'
      + (selected ? renderReader(selected)
                  : '<div class="pw-empty"><h3>No message selected</h3>'
                    + '<p>Choose something from the list.</p></div>')
      + '  </div>'
      + '</div>';
  }

  /* The reader shows what a mail client shows: sender name, sender address,
   * subject, body, the visible text of each link, and each attachment's name
   * and size.
   *
   * The full header, a link's real destination, and an attachment's type and
   * provenance are *inspection-only*. They are not in the snapshot at all
   * until the learner asks for them, so this cannot render them early even by
   * mistake — pressing the button posts an observational action and the value
   * arrives with the next snapshot. That is the available-versus-observed
   * distinction, made real rather than decorative. */
  function renderReader(message) {
    var state = APP.mail;
    var confirmation = NOTICE
      ? '<div class="pw-confirmstrip">' + icon('check')
        + '<span>' + esc(NOTICE.text) + '</span></div>'
      : '';

    var headers = (state.headers && message.headers)
      ? '<div class="pw-reader-headers"><dl>'
        + '<dt>From</dt><dd>' + esc(message.headers.from_address) + '</dd>'
        + '<dt>Reply-To</dt><dd>'
        + esc(message.headers.reply_to || message.headers.from_address) + '</dd>'
        + '<dt>To</dt><dd>' + esc(message.headers.to) + '</dd>'
        + (message.headers.cc
            ? '<dt>Cc</dt><dd>' + esc(message.headers.cc) + '</dd>' : '')
        + '<dt>Received</dt><dd>' + esc(message.received) + '</dd>'
        + '</dl></div>'
      : '';

    var body = (message.body || []).map(function (paragraph) {
      if (String(paragraph).indexOf('———') === 0) {
        return '<p class="pw-reader-quote">' + esc(paragraph) + '</p>';
      }
      return '<p>' + esc(paragraph) + '</p>';
    }).join('');

    var links = (message.links || []).map(function (link) {
      var key = message.id + ':' + link.index;
      var shown = state.linkShown === key && link.href;
      return '<p><button type="button" class="pw-maillink"'
        + ' data-mail-link="' + esc(key) + '">' + esc(link.text)
        + icon('external', 'style="width:12px;height:12px"') + '</button>'
        + ' <button type="button" class="pw-linkbtn" style="margin-left:.5rem"'
        + ' data-mail-inspect-link="' + esc(key) + '">'
        + (shown ? 'Hide destination' : 'Where does this go?') + '</button>'
        + (shown ? '<span class="pw-linkinfo">' + esc(link.href) + '</span>' : '')
        + '</p>';
    }).join('');

    var attachments = (message.attachments || []).map(function (attachment) {
      var key = message.id + ':' + attachment.index;
      var shown = state.linkShown === 'att:' + key && attachment.detail;
      return '<div class="pw-attach">' + icon(attachmentIcon(attachment.name))
        + '<span class="pw-attach-main"><b>' + esc(attachment.name) + '</b>'
        + '<span>' + esc(attachment.size) + '</span>'
        + (shown
            ? '<span class="pw-linkinfo">Type: ' + esc(attachment.detail.kind_label)
              + '<br>Sender: ' + esc(attachment.detail.sender) + '</span>'
            : '')
        + '</span>'
        + '<span class="pw-attach-actions">'
        + '<button type="button" class="pw-btn is-sm" data-att-inspect="' + esc(key) + '">'
        + (shown ? 'Hide details' : 'Details') + '</button>'
        + '<button type="button" class="pw-btn is-sm" data-att-download="' + esc(key) + '">'
        + 'Download</button>'
        + '</span></div>';
    }).join('');

    var compose = state.composing === message.id
      ? '<div class="pw-compose">'
        + '<h4>Reply to ' + esc(message.from_name) + '</h4>'
        + '<textarea id="pw-compose-body" aria-label="Reply text">'
        + esc(state.draft) + '</textarea>'
        + '<div class="pw-compose-actions">'
        + '<button type="button" class="pw-btn is-primary is-sm" data-mail-send="'
        + esc(message.id) + '">Send</button>'
        + '<button type="button" class="pw-btn is-sm" data-mail-cancel="1">Cancel</button>'
        + '</div></div>'
      : '';

    var forwardCompose = state.forwarding === message.id
      ? renderForwardCompose(message)
      : '';

    var hint = flags().investigation_hints
      ? '<div class="pw-note" style="margin:.75rem 0;font-size:.8rem">'
        + 'You can open the full header, check where a link actually goes, '
        + 'search older mail from the same sender, or look someone up in the '
        + 'Directory before you act.</div>'
      : '';

    if (message.own) {
      return '<div class="pw-pane-head">'
        + '<button type="button" class="pw-btn is-sm is-quiet pw-mobile-back" data-mail-back="1">'
        + icon('back') + ' Inbox</button>'
        + '<h3>' + esc(message.subject) + '</h3></div>'
        + '<div class="pw-pane-scroll" data-scroll-key="mail-reader:' + esc(message.id) + '"><div class="pw-reader">'
        + '<h2 class="pw-reader-subject">' + esc(message.subject) + '</h2>'
        + '<div class="pw-reader-from"><span class="pw-avatar is-neutral" aria-hidden="true">'
        + esc(initialsOf(message.from_name)) + '</span>'
        + '<span class="pw-reader-from-main"><b>To ' + esc(message.to) + '</b>'
        + '<span>' + esc(message.received) + '</span></span></div>'
        + '<div class="pw-reader-body">' + body + '</div>'
        + '</div></div>';
    }

    // Deleted mail gets its own pair of actions in place of Report/Delete:
    // there is nothing to report once a message has already been removed
    // from view, and "Delete" there would be a second, different meaning of
    // the same word. Restore is reversible; "Delete permanently" is not, and
    // is never the primary (is-primary) action in the row for that reason.
    var deletedActions = ''
      + '  <button type="button" class="pw-btn is-sm" data-mail-restore="' + esc(message.id) + '">'
      + icon('reload', 'style="width:13px;height:13px"') + ' Restore</button>'
      + '  <button type="button" class="pw-btn is-sm is-alert" data-mail-delete-permanent="'
      + esc(message.id) + '">'
      + icon('trash', 'style="width:13px;height:13px"') + ' Delete permanently</button>';
    var activeActions = ''
      + '  <button type="button" class="pw-btn is-sm" data-mail-report="' + esc(message.id) + '">'
      + icon('flag', 'style="width:13px;height:13px"') + ' Report</button>'
      + '  <button type="button" class="pw-btn is-sm" data-mail-delete="' + esc(message.id) + '">'
      + icon('trash', 'style="width:13px;height:13px"') + ' Delete</button>';

    return ''
      + '<div class="pw-pane-head">'
      + '  <button type="button" class="pw-btn is-sm is-quiet pw-mobile-back" data-mail-back="1">'
      + icon('back') + ' Inbox</button>'
      // Reply is the ordinary thing to do with a message, so it carries the
      // toolbar's one emphasis. Nothing else in the row is ranked: Report must
      // never look more or less encouraged than Forward or Delete.
      + '  <button type="button" class="pw-btn is-sm is-primary" data-mail-reply="' + esc(message.id) + '">'
      + icon('reply', 'style="width:13px;height:13px"') + ' Reply</button>'
      + '  <button type="button" class="pw-btn is-sm" data-mail-forward="' + esc(message.id) + '">Forward</button>'
      + (message.folder === 'deleted' ? deletedActions : activeActions)
      + '  <span class="pw-spacer"></span>'
      + '  <button type="button" class="pw-btn is-sm" data-mail-headers="'
      + esc(message.id) + '" aria-pressed="' + (state.headers ? 'true' : 'false') + '">'
      + (state.headers ? 'Hide header' : 'Show header') + '</button>'
      + '</div>'
      + confirmation
      + '<div class="pw-pane-scroll" data-scroll-key="mail-reader:' + esc(message.id) + '"><div class="pw-reader">'
      + '  <h2 class="pw-reader-subject">' + esc(message.subject) + '</h2>'
      + '  <div class="pw-reader-from">'
      + '    <span class="pw-avatar is-neutral" aria-hidden="true">'
      + esc(initialsOf(message.from_name)) + '</span>'
      + '    <span class="pw-reader-from-main">'
      + '      <b>' + esc(message.from_name) + '</b>'
      + '      <span>' + esc(message.from_address) + '</span>'
      + '    </span>'
      + '  </div>'
      + headers
      + hint
      + '  <div class="pw-reader-body">' + body + links + '</div>'
      + attachments
      + '</div></div>'
      + compose
      + forwardCompose;
  }

  /* The forward composer. Recipient is a closed list drawn from the internal
   * Directory in the authoritative snapshot — the client never types an
   * address, and the id it posts is one the server minted. The original is
   * quoted underneath exactly as it is rendered in the reader, so nothing
   * appears here that the learner could not already see. */
  function internalContacts() {
    return (SNAP.directory || []).filter(function (contact) {
      return contact.kind === 'employee';
    });
  }

  function renderForwardCompose(message) {
    var state = APP.mail;
    var options = internalContacts().map(function (contact) {
      return '<option value="' + esc(contact.id) + '"'
        + (state.forwardRecipient === contact.id ? ' selected' : '') + '>'
        + esc(contact.name) + (contact.role ? ' — ' + esc(contact.role) : '')
        + '</option>';
    }).join('');

    var quoted = (message.body || []).map(function (paragraph) {
      return '<p>' + esc(paragraph) + '</p>';
    }).join('');

    return '<div class="pw-compose">'
      + '<h4>Forward: ' + esc(message.subject) + '</h4>'
      + '<label class="pw-field-label" for="pw-forward-to">To</label>'
      + '<select id="pw-forward-to" aria-label="Forward to">'
      + '<option value="">Choose a colleague…</option>' + options
      + '</select>'
      + '<label class="pw-field-label" for="pw-forward-note">Add a note (optional)</label>'
      + '<textarea id="pw-forward-note" aria-label="Note to add to the forward">'
      + esc(state.forwardDraft) + '</textarea>'
      + '<div class="pw-reader-quote" style="margin:.5rem 0">'
      + '<p><b>--------- Forwarded message ---------</b></p>'
      + '<p>From: ' + esc(message.from_name) + ' &lt;'
      + esc(message.from_address) + '&gt;</p>'
      + '<p>Subject: ' + esc(message.subject) + '</p>'
      + quoted + '</div>'
      + '<div class="pw-compose-actions">'
      + '<button type="button" class="pw-btn is-primary is-sm"'
      + (state.forwardRecipient ? '' : ' disabled')
      + ' data-mail-forward-send="' + esc(message.id) + '">Send</button>'
      + '<button type="button" class="pw-btn is-sm" data-mail-forward-cancel="1">Cancel</button>'
      + '</div></div>';
  }

  function attachmentIcon(name) {
    var lower = String(name || '').toLowerCase();
    if (lower.indexOf('.pdf') >= 0) { return 'pdf'; }
    if (lower.indexOf('.xls') >= 0 || lower.indexOf('.csv') >= 0) { return 'sheet'; }
    return 'doc';
  }

  function initialsOf(name) {
    return String(name || '').split(/\s+/).slice(0, 2)
      .map(function (part) { return part.charAt(0); }).join('').toUpperCase();
  }

  function defaultReply(message) {
    if (message && message.id === 'm-headcount') {
      return 'Hi Marcus,\n\nConfirmed contractor headcount for Q3 is 41.\n\nAarti';
    }
    return '';
  }

  function openMessage(messageId) {
    APP.mail.selected = messageId;
    APP.mail.headers = false;
    APP.mail.linkShown = null;
    APP.mail.composing = null;
    APP.mail.forwarding = null;
    APP.mail.forwardRecipient = null;
    APP.mail.forwardDraft = '';
    APP.mail.mobileDetail = true;
    render();
    send('mail.open', messageId);
  }

  // =========================================================================
  // Browser
  // =========================================================================
  //
  // Tabs and history are presentation and live here. Which addresses have
  // actually been reached, and what each page shows, are server state: the
  // snapshot carries only pages this session has genuinely visited, and an
  // address that is not one of the synthetic pages simply has no content.
  // Nothing in this file fetches anything from an address.

  function ensureTab() {
    if (!APP.browser.tabs.length) {
      APP.browser.tabs.push({
        url: SNAP.browser.home, history: [SNAP.browser.home], index: 0,
        urlDraft: null
      });
      APP.browser.active = 0;
    }
    return APP.browser.tabs[APP.browser.active];
  }

  function normaliseUrl(raw) {
    return String(raw || '').trim()
      .replace(/^https?:\/\//i, '').replace(/\/+$/, '').toLowerCase();
  }

  function browserNavigate(rawUrl) {
    var tab = ensureTab();
    var url = normaliseUrl(rawUrl);
    tab.history = tab.history.slice(0, tab.index + 1);
    tab.history.push(url);
    tab.index = tab.history.length - 1;
    tab.url = url;
    tab.urlDraft = null;
    openApp('browser');
    send('browser.navigate', null, { url: url });
  }

  function pageFor(url) {
    return (SNAP.browser.pages || {})[url] || null;
  }

  function renderBrowser() {
    var tab = ensureTab();
    var page = pageFor(tab.url);

    var tabs = APP.browser.tabs.map(function (entry, index) {
      var titled = pageFor(entry.url);
      return '<button type="button" class="pw-tab'
        + (index === APP.browser.active ? ' is-active' : '') + '"'
        + ' data-tab-select="' + index + '">'
        + '<span>' + esc(titled ? titled.title : entry.url) + '</span>'
        + (APP.browser.tabs.length > 1
            ? '<span class="pw-tab-close" data-tab-close="' + index + '"'
              + ' role="button" aria-label="Close tab">&times;</span>' : '')
        + '</button>';
    }).join('');

    var bookmarks = SNAP.browser.bookmarks.map(function (bookmark) {
      return '<button type="button" class="pw-bookmark" data-go="'
        + esc(bookmark.url) + '">' + esc(bookmark.label) + '</button>';
    }).join('')
      + '<button type="button" class="pw-bookmark" data-go="intranet.northbridge.example/finance/payments">Supplier payments</button>'
      + '<button type="button" class="pw-bookmark" data-go="intranet.northbridge.example/it/support">Service Desk</button>';

    var internal = page && page.chrome === 'internal';

    return ''
      + '<div class="pw-app pw-browser">'
      + '  <div class="pw-tabstrip">' + tabs
      + '    <button type="button" class="pw-tab" data-tab-new="1" aria-label="New tab">+</button>'
      + '  </div>'
      + '  <div class="pw-urlbar">'
      + '    <button type="button" class="pw-winctl" data-nav="back" aria-label="Back"'
      + (tab.index <= 0 ? ' disabled' : '') + '>' + icon('back') + '</button>'
      + '    <button type="button" class="pw-winctl" data-nav="forward" aria-label="Forward"'
      + (tab.index >= tab.history.length - 1 ? ' disabled' : '') + '>' + icon('forward') + '</button>'
      + '    <button type="button" class="pw-winctl" data-nav="reload" aria-label="Reload">'
      + icon('reload') + '</button>'
      + '    <span class="pw-urlfield">'
      + (internal ? icon('lock', 'class="is-internal"') : icon('unlock'))
      + '      <input type="text" id="pw-url-input" value="'
      + esc(tab.urlDraft === undefined || tab.urlDraft === null ? tab.url : tab.urlDraft) + '"'
      + '        aria-label="Address" spellcheck="false" autocomplete="off">'
      + '    </span>'
      + '  </div>'
      + '  <div class="pw-bookmarks">' + bookmarks + '</div>'
      + '  <div class="pw-viewport">' + renderPage(tab, page) + '</div>'
      + '</div>';
  }

  function renderPage(tab, page) {
    if (!page) {
      return '<div class="pw-blocked">' + icon('globe', 'style="width:28px;height:28px"')
        + '<h1>This address is not reachable</h1>'
        + '<p>This browser only reaches the synthetic ' + esc(SNAP.organization.name)
        + ' network. Nothing outside it can be loaded.</p></div>';
    }
    if (page.kind === 'signin') { return renderSignin(tab, page); }
    if (page.kind === 'filelist') { return renderBrowserFiles(page); }
    if (page.kind === 'payments') { return renderPayments(tab, page); }
    if (page.kind === 'support') { return renderSupport(page); }

    var sections = (page.sections || []).map(function (section) {
      return '<section class="pw-site-section"><h2>' + esc(section.title) + '</h2><ul>'
        + section.items.map(function (item) { return '<li>' + esc(item) + '</li>'; }).join('')
        + '</ul></section>';
    }).join('');

    return '<div class="pw-site">'
      + '<div class="pw-site-head"><h1>' + esc(page.heading) + '</h1>'
      + '<p>' + esc(page.subheading || '') + '</p></div>'
      + sections + renderPageDownloads(page) + '</div>';
  }

  /* Files a page offers. Every value comes from the server's projection and
   * is escaped on the way in; the button carries the *resource id* the server
   * gave us and the page address, and nothing else -- there is no filename
   * here, no path, and no URL to fetch. What lands in Downloads, and what it
   * ends up called, is the server's decision. */
  function renderPageDownloads(page) {
    var resources = page.resources || [];
    if (!resources.length) { return ''; }
    return '<section class="pw-site-section"><h2>Downloads</h2><ul>'
      + resources.map(function (resource) {
          return '<li>'
            + '<strong>' + esc(resource.name) + '</strong> '
            + '<span class="pw-hint">' + esc(resource.kind_label)
            + (resource.size ? ' \u00b7 ' + esc(resource.size) : '')
            + '</span> '
            + '<button type="button" class="pw-btn"'
            + ' data-page-download="' + esc(resource.id) + '"'
            + ' data-page-url="' + esc(page.url) + '">Download</button>'
            + '</li>';
        }).join('')
      + '</ul></section>';
  }

  /* The sign-in form never reads the password field, never serialises it and
   * never sends it. Submitting posts the *address* and nothing else; the
   * server decides what signing in on that address means. The field is
   * cleared on submit so the typed value does not even survive in the DOM. */
  function renderSignin(tab, page) {
    var signedIn = page.signed_in;

    if (signedIn === 'pending') {
      return '<div class="pw-signin"><h1>' + esc(page.heading) + '</h1>'
        + '<p class="pw-signin-sub">Waiting for you to approve the request on '
        + 'your authenticator.</p>'
        + '<p class="pw-signin-note">Open the Authenticator to approve or deny '
        + 'it.</p></div>';
    }
    if (signedIn === 'done') {
      return '<div class="pw-site"><div class="pw-site-head">'
        + '<h1>' + esc(page.heading) + '</h1>'
        + '<p>Signed in as ' + esc(SNAP.learner.email) + '</p></div>'
        + '<section class="pw-site-section"><h2>Your record</h2><ul>'
        + '<li>August payslip — published 8 September</li>'
        + '<li>July payslip — published 8 August</li>'
        + '<li>Tax summary 2025–26</li></ul></section></div>';
    }
    if (signedIn === 'submitted') {
      return '<div class="pw-site"><div class="pw-site-head">'
        + '<h1>' + esc(page.heading) + '</h1>'
        + '<p>Your record has been confirmed. You can close this page.</p>'
        + '</div></div>';
    }
    if (signedIn === 'denied') {
      return '<div class="pw-signin"><h1>' + esc(page.heading) + '</h1>'
        + '<p class="pw-signin-sub">The sign-in was not completed. You can try '
        + 'again when you are ready.</p>'
        + '<button type="button" class="pw-btn is-block" data-signin-retry="'
        + esc(page.url) + '">Sign in again</button></div>';
    }

    return '<form class="pw-signin" data-signin="' + esc(page.url) + '">'
      + '<h1>' + esc(page.heading) + '</h1>'
      + '<p class="pw-signin-sub">' + esc(page.subheading || '') + '</p>'
      + '<label class="pw-field"><span class="pw-label">Work email</span>'
      + '<input class="pw-input" type="email" id="pw-signin-user"'
      + ' value="' + esc(SNAP.learner.email) + '" autocomplete="off"></label>'
      + '<label class="pw-field"><span class="pw-label">Password</span>'
      + '<input class="pw-input" type="password" id="pw-signin-pass"'
      + ' autocomplete="off" data-synthetic-only="true"></label>'
      + '<button type="submit" class="pw-btn is-primary is-block">Sign in</button>'
      + (page.note ? '<p class="pw-signin-note">' + esc(page.note) + '</p>' : '')
      + '</form>';
  }

  function renderBrowserFiles(page) {
    var location = findLocation(page.location_id);
    if (!location) { return '<div class="pw-site"><p>Folder unavailable.</p></div>'; }
    return '<div class="pw-site">'
      + '<div class="pw-site-head"><h1>' + esc(page.heading) + '</h1>'
      + '<p>' + esc(page.subheading || '') + '</p></div>'
      + '<section class="pw-site-section"><h2>Files</h2><ul>'
      + filesIn(page.location_id).map(function (file) {
          return '<li>' + esc(file.display_name || file.name)
            + (file.owner ? ' <span class="pw-muted">· ' + esc(file.owner) + '</span>' : '')
            + (file.state === 'unavailable'
                ? ' <span class="pw-chip is-alert">will not open</span>' : '')
            + '</li>';
        }).join('')
      + '</ul></section></div>';
  }

  /* The release queue. One card per payment context the server sent -- a
   * recurring supplier request raises a second queue entry against the same
   * invoice of record, and each entry is released, and settles, on its own.
   * The client sends back the context id it was given; it never decides which
   * payment an action is about, and it holds no occurrence or decision id to
   * decide it with. */
  function renderPayments(tab, page) {
    var invoice = page.invoice || {};
    var contexts = page.payment_contexts || [];
    if (!contexts.length) {
      return '<div class="pw-site"><div class="pw-site-head">'
        + '<h1>' + esc(page.heading) + '</h1>'
        + '<p>Nothing is awaiting release.</p></div></div>';
    }
    return '<div class="pw-site">'
      + '<div class="pw-site-head"><h1>' + esc(page.heading) + '</h1>'
      + '<p>' + esc(page.subheading) + '</p></div>'
      + '<section class="pw-site-section"><h2>Release queue</h2>'
      + contexts.map(function (context) {
          return renderPaymentContext(page, context);
        }).join('')
      + '<p class="pw-hint" style="margin-top:.7rem">' + esc(page.note) + '</p>'
      + '</section></div>';
  }

  function renderPaymentContext(page, context) {
    if (context.released_account) {
      return '<div class="pw-card" style="max-width:32rem">'
        + '<h3 style="margin-bottom:.4rem">' + esc(context.queue_ref) + ' · '
        + esc(context.reference) + ' · ' + esc(context.supplier) + '</h3>'
        + '<ul class="pw-small">'
        + '<li>' + esc(context.amount) + ' — instruction accepted</li>'
        + '<li>Released to ' + esc(context.released_account) + '</li>'
        + '<li>Released by ' + esc(SNAP.learner.name) + '</li>'
        + '</ul></div>';
    }
    var draft = APP.browser.accountDraft || {};
    var account = Object.prototype.hasOwnProperty.call(draft, context.id)
      ? draft[context.id]
      : (context.account_of_record || '');
    return '<div class="pw-card" style="max-width:32rem">'
      + '<h3 style="margin-bottom:.4rem">' + esc(context.queue_ref) + ' · '
      + esc(context.reference) + ' · ' + esc(context.supplier) + '</h3>'
      + '<p class="pw-small pw-muted">Amount ' + esc(context.amount)
      + ' · approved by ' + esc(context.approved_by) + '</p>'
      + '<label class="pw-field" style="margin-top:.9rem">'
      + '<span class="pw-label">Settlement account</span>'
      + '<input class="pw-input" id="pw-pay-account-' + esc(context.id) + '"'
      + ' value="' + esc(account) + '" autocomplete="off"></label>'
      + '<div class="pw-row">'
      + '<button type="button" class="pw-btn is-primary" data-pay-release="'
      + esc(page.url) + '" data-pay-context="' + esc(context.id)
      + '">Release payment</button>'
      + '<button type="button" class="pw-btn" data-pay-reset="'
      + esc(context.id) + '">Restore account of record</button>'
      + '</div></div>';
  }

  function renderSupport(page) {
    var files = incident('inc-files');
    var offline = SNAP.session.network_disconnected;
    return '<div class="pw-site">'
      + '<div class="pw-site-head"><h1>' + esc(page.heading) + '</h1>'
      + '<p>' + esc(page.subheading) + '</p></div>'
      + (files
          ? '<div class="pw-note is-caution" style="margin-bottom:1rem">'
            + esc(files.note) + '</div>' : '')
      + '<section class="pw-site-section"><h2>Actions</h2>'
      + '<div class="pw-row">'
      + (offline
          ? '<button type="button" class="pw-btn is-primary"'
            + ' data-support="reconnect">'
            + 'Reconnect this workstation to the network</button>'
          : '<button type="button" class="pw-btn is-primary"'
            + ' data-support="isolate">'
            + 'Disconnect this workstation from the network</button>')
      + '<button type="button" class="pw-btn" data-support="raise">'
      + 'Raise an incident with the Service Desk</button>'
      + (files && files.contained && !files.recovered
          ? '<button type="button" class="pw-btn is-primary" data-support="restore">'
            + 'Restore affected files from a verified backup</button>'
          : '')
      + '</div>'
      /* Contained, but recovery is a separate, later step -- see
       * Architecture Spec v1.1 (Batch 4) S24. The button only appears once
       * containment is real, so "restore" can never be the first thing a
       * learner tries. */
      + (files && files.contained && !files.recovered
          ? '<p class="pw-note is-accent" style="margin-top:.7rem">'
            + 'The incident is contained. Affected files have not been '
            + 'restored yet.</p>'
          : '')
      + (files && files.recovered
          ? '<p class="pw-note is-good" style="margin-top:.7rem">'
            + 'Affected files were restored from a verified backup.</p>'
          : '')
      /* Says what being off the network costs, without saying whether being
       * off it was the right call. The server decides that; this only
       * describes the state the workstation is actually in. */
      + (offline
          ? '<p class="pw-note is-caution" style="margin-top:.7rem">'
            + 'This workstation is off the network. New mail, shared folders '
            + 'and remote access are unavailable until it is reconnected.</p>'
          : '')
      + '<p class="pw-hint" style="margin-top:.7rem">' + esc(page.note) + '</p>'
      + '</section>'
      + ((page.sections || []).map(function (section) {
          return '<section class="pw-site-section"><h2>' + esc(section.title) + '</h2><ul>'
            + section.items.map(function (item) { return '<li>' + esc(item) + '</li>'; }).join('')
            + '</ul></section>';
        }).join(''))
      + '</div>';
  }

  // =========================================================================
  // Files
  // =========================================================================

  function renderFiles() {
    var state = APP.files;
    if (!state.location && SNAP.files.locations.length) {
      state.location = SNAP.files.locations[0].id;
    }
    var current = findLocation(state.location);

    var nav = SNAP.files.locations.map(function (location) {
      var broken = filesIn(location.id).filter(function (f) {
        return f.state === 'unavailable';
      }).length;
      return '<button type="button" class="pw-navitem'
        + (location.id === state.location ? ' is-active' : '') + '"'
        + ' data-file-location="' + esc(location.id) + '">'
        + icon('folder') + '<span>' + esc(location.name) + '</span>'
        + (broken ? '<span class="pw-navitem-count">' + broken + '</span>' : '')
        + '</button>';
    }).join('');

    var rows = filesIn(current.id).map(function (file) {
      var unavailable = file.state === 'unavailable';
      // "New" tracks ``is_new`` -- an unseen-download flag the server clears
      // the moment ``files.open`` is attempted -- not ``state``, which is a
      // readability/security value ("normal", "unavailable", ...). Reading
      // ``state === 'downloaded'`` here would show every downloaded file as
      // new forever, since the server normalises that legacy state value to
      // "normal" on first open and never sets it again. See
      // ``rewindsec.workstation.projection._files_view``.
      return '<button type="button" class="pw-filerow'
        + (unavailable ? ' is-unavailable' : '')
        + (file.is_new ? ' is-new' : '')
        + (state.selected === file.id ? ' is-active' : '') + '"'
        + ' data-file-select="' + esc(file.id) + '">'
        + icon(unavailable ? 'filex' : fileIcon(file.kind))
        + '<span class="pw-filerow-name">' + esc(file.display_name || file.name) + '</span>'
        + '<span class="pw-filerow-meta is-optional">' + esc(file.size) + '</span>'
        + '<span class="pw-filerow-meta is-optional">' + esc(file.modified) + '</span>'
        + '<span class="pw-filerow-meta">'
        + (unavailable ? '<span class="pw-chip is-alert">error</span>'
           : file.is_new ? '<span class="pw-chip is-accent">new</span>' : '')
        + '</span>'
        + '</button>';
    }).join('');

    var header = ''
      + '<div class="pw-filehead" aria-hidden="true">'
      + '<span></span><span>Name</span>'
      + '<span class="is-optional">Size</span>'
      + '<span class="is-optional">Modified</span>'
      + '<span></span></div>';

    if (!rows) {
      header = '';
      rows = '<div class="pw-empty"><h3>Empty folder</h3>'
        + '<p>Nothing has been saved here.</p></div>';
    }

    var selected = state.selected ? findFile(state.selected) : null;
    var files = incident('inc-files');

    return ''
      + '<div class="pw-app">'
      + '  <div class="pw-pane pw-sidepane">'
      + '    <div class="pw-pane-scroll" data-scroll-key="files-folders"><div class="pw-nav">' + nav + '</div></div>'
      + '  </div>'
      + '  <div class="pw-pane pw-mainpane">'
      + '    <div class="pw-pane-head"><h3>' + esc(current.name) + '</h3>'
      + (current.path ? '<span class="pw-xsmall pw-muted">' + esc(current.path) + '</span>' : '')
      + '</div>'
      + (files
          ? '<div class="pw-mailbanner">' + icon('alert')
            + '<span>' + esc(files.note)
            + ' The Service Desk page in the Browser has the actions.</span></div>'
          : '')
      + header
      + '    <div class="pw-pane-scroll" data-scroll-key="files-list:' + esc(current.id) + '">' + rows + '</div>'
      + (selected ? renderFileInfo(selected) : '')
      + '  </div>'
      + '</div>';
  }

  function fileIcon(kind) {
    if (kind === 'pdf') { return 'pdf'; }
    if (kind === 'spreadsheet' || kind === 'spreadsheet-macro') { return 'sheet'; }
    if (kind === 'text') { return 'text'; }
    return 'doc';
  }

  function renderFileInfo(entry) {
    var file = entry.file;
    var unavailable = file.state === 'unavailable';
    return '<div class="pw-pane-foot" style="display:block">'
      + '<div class="pw-fileinfo" style="padding:0">'
      + '<div class="pw-row is-between"><b>' + esc(file.display_name || file.name) + '</b>'
      + '<span class="pw-row" style="gap:.35rem">'
      + '<button type="button" class="pw-btn is-sm" data-file-open="' + esc(file.id) + '">Open</button>'
      + '<button type="button" class="pw-btn is-sm" data-file-rename="' + esc(file.id) + '">Rename</button>'
      + '<button type="button" class="pw-btn is-sm is-alert" data-file-delete="' + esc(file.id) + '">Delete</button>'
      + '</span></div>'
      + (APP.files.renaming === file.id
          ? '<div class="pw-row" style="margin-top:.5rem">'
            + '<input class="pw-input" id="pw-file-rename" style="max-width:20rem" value="'
            + esc(file.name) + '" aria-label="New file name">'
            + '<button type="button" class="pw-btn is-sm is-primary" data-file-rename-save="'
            + esc(file.id) + '">Save</button></div>'
          : '')
      + '<dl>'
      + '<dt>Location</dt><dd>' + esc(entry.location.name) + '</dd>'
      + '<dt>Size</dt><dd>' + esc(file.size) + '</dd>'
      + '<dt>Modified</dt><dd>' + esc(file.modified) + '</dd>'
      + (file.owner ? '<dt>Owner</dt><dd>' + esc(file.owner) + '</dd>' : '')
      + (file.source ? '<dt>Source</dt><dd>' + esc(file.source) + '</dd>' : '')
      + '<dt>Status</dt><dd>'
      + (unavailable ? esc(file.note || 'Cannot be opened.') : 'Available')
      + '</dd>'
      + '</dl>'
      + ((file.preview && file.preview.length)
          ? '<div class="pw-filepreview">'
            + file.preview.map(function (line) { return '<p>' + esc(line) + '</p>'; }).join('')
            + '</div>'
          : '')
      + (file.document ? renderDocumentViewer(file.document) : '')
      + '</div></div>';
  }

  /* The read-only synthetic document viewer. Every field it renders comes
   * from a server-owned ``rewindsec.content.schema.SyntheticDocument``
   * projection whose leaf strings were already rejected by
   * ``rewindsec.content.sanitize`` if they looked like markup -- but this
   * still runs every value through ``esc()`` before it reaches the page, so
   * nothing here ever interprets a document field as HTML. No iframe, no
   * object/embed, no script, no external resource: it is plain escaped text
   * inside plain container elements. */
  function renderDocumentViewer(doc) {
    var blocks = (doc.blocks || []).map(renderDocumentBlock).join('');
    return '<div class="pw-docviewer">'
      + '<div class="pw-docviewer-head">' + icon('doc')
      + '<b>' + esc(doc.title) + '</b></div>'
      + '<div class="pw-docviewer-body">' + blocks + '</div>'
      + '</div>';
  }

  function renderDocumentBlock(block) {
    if (block.type === 'heading') {
      var tag = 'h' + Math.min(6, Math.max(4, 3 + (block.level || 2)));
      return '<' + tag + '>' + esc(block.text) + '</' + tag + '>';
    }
    if (block.type === 'paragraph') {
      return '<p>' + esc(block.text) + '</p>';
    }
    if (block.type === 'key_value') {
      return '<dl class="pw-docviewer-kv">' + (block.pairs || []).map(function (pair) {
        return '<dt>' + esc(pair[0]) + '</dt><dd>' + esc(pair[1]) + '</dd>';
      }).join('') + '</dl>';
    }
    if (block.type === 'table') {
      var head = '<tr>' + (block.headers || []).map(function (h) {
        return '<th>' + esc(h) + '</th>';
      }).join('') + '</tr>';
      var body = (block.rows || []).map(function (row) {
        return '<tr>' + row.map(function (cell) {
          return '<td>' + esc(cell) + '</td>';
        }).join('') + '</tr>';
      }).join('');
      return '<div class="pw-docviewer-table"><table>' + head + body + '</table></div>';
    }
    if (block.type === 'list') {
      return '<ul>' + (block.items || []).map(function (item) {
        return '<li>' + esc(item) + '</li>';
      }).join('') + '</ul>';
    }
    return '';
  }

  // =========================================================================
  // Messages
  // =========================================================================

  function renderMessages() {
    var state = APP.messages;
    if (!state.conversation && SNAP.messages.length) {
      state.conversation = SNAP.messages[0].id;
    }
    var current = findConversation(state.conversation) || SNAP.messages[0];
    if (!current) { return '<div class="pw-empty"><h3>No conversations</h3></div>'; }
    state.conversation = current.id;

    var list = SNAP.messages.map(function (conversation) {
      var last = conversation.entries[conversation.entries.length - 1];
      return '<button type="button" class="pw-convrow'
        + (conversation.id === state.conversation ? ' is-active' : '')
        + (conversation.unread ? ' is-unread' : '') + '"'
        + ' data-conv-open="' + esc(conversation.id) + '">'
        + '<span class="pw-avatar is-neutral" aria-hidden="true">'
        + esc(conversation.initials) + '</span>'
        + '<span class="pw-convrow-main"><b>' + esc(conversation.name) + '</b>'
        + '<span>' + esc(last ? last.text : '') + '</span></span>'
        + (conversation.unread ? '<span class="pw-dot is-accent"></span>' : '')
        + '</button>';
    }).join('');

    var bubbles = current.entries.map(function (line) {
      var mine = line.from === SNAP.learner.name;
      return '<div class="pw-bubble ' + (mine ? 'is-me' : 'is-them') + '">'
        + esc(line.text)
        + '<span class="pw-bubble-meta">' + esc(mine ? 'You' : line.from)
        + ' · ' + esc(line.when) + '</span></div>';
    }).join('');

    var verify = current.verify_prompt
      ? '<button type="button" class="pw-btn is-sm" data-conv-verify="' + esc(current.id) + '">'
        + esc(current.verify_prompt) + '</button>'
      : '';

    return ''
      + '<div class="pw-app' + (state.mobileDetail ? ' is-split-mobile' : '') + '">'
      + '  <div class="pw-pane pw-listpane" style="width:250px">'
      + '    <div class="pw-pane-head"><h3>Conversations</h3></div>'
      + '    <div class="pw-pane-scroll" data-scroll-key="messages-list">' + list + '</div>'
      + '  </div>'
      + '  <div class="pw-pane pw-mainpane">'
      + '    <div class="pw-pane-head">'
      + '      <button type="button" class="pw-btn is-sm is-quiet pw-mobile-back" data-conv-back="1">'
      + icon('back') + '</button>'
      + '      <h3>' + esc(current.name) + '</h3>'
      + '      <span class="pw-chip is-plain">' + esc(current.presence) + '</span>'
      + '      <span class="pw-spacer"></span>' + verify
      + '    </div>'
      + '    <div class="pw-pane-scroll" data-scroll-key="messages-thread:' + esc(current.id) + '"><div class="pw-thread">' + bubbles + '</div></div>'
      + '    <div class="pw-pane-foot">'
      + '      <input class="pw-input" id="pw-msg-input" placeholder="Write a message"'
      + '        aria-label="Message" value="' + esc(state.draft) + '" style="flex:1">'
      + '      <button type="button" class="pw-btn is-sm is-primary" data-msg-send="'
      + esc(current.id) + '">Send</button>'
      + '    </div>'
      + '  </div>'
      + '</div>';
  }

  // =========================================================================
  // Authenticator
  // =========================================================================

  function renderAuthenticator() {
    var prompts = SNAP.authenticator.requests.map(function (entry) {
      var open = !!APP.authenticator.details[entry.id] && entry.details;
      return '<div class="pw-authprompt">'
        + '<div class="pw-row" style="align-items:flex-start">'
        + '<div style="flex:1;min-width:0">'
        + '<h3>Approve sign-in to ' + esc(entry.app) + '?</h3>'
        + '<p class="pw-authsub">Requested ' + esc(entry.arrived) + '</p>'
        + '</div>'
        + '<span class="pw-authnum" aria-label="Number shown on the sign-in screen">'
        + esc(entry.number_match) + '</span>'
        + '</div>'
        + (open
            ? '<dl class="pw-authgrid">'
              + '<dt>Application</dt><dd>' + esc(entry.app) + '</dd>'
              + '<dt>Device</dt><dd>' + esc(entry.details.device) + '</dd>'
              + '<dt>Location</dt><dd>' + esc(entry.details.location) + '</dd>'
              + '<dt>Network</dt><dd>' + esc(entry.details.network) + '</dd>'
              + '<dt>Address</dt><dd>' + esc(entry.details.ip_class) + '</dd>'
              + '</dl>'
            : '')
        // Approve and Deny are drawn identically and neither is emphasised.
        // A primary Approve is a nudge towards approving, and the point of the
        // prompt is that the context above it — not the shape of the buttons —
        // is what a learner should be reading.
        + '<div class="pw-authactions">'
        + '<button type="button" class="pw-btn is-sm" data-mfa-approve="'
        + esc(entry.id) + '">Approve</button>'
        + '<button type="button" class="pw-btn is-sm" data-mfa-deny="' + esc(entry.id) + '">Deny</button>'
        + '<button type="button" class="pw-btn is-sm is-quiet" data-mfa-details="'
        + esc(entry.id) + '" aria-expanded="' + (open ? 'true' : 'false') + '">'
        + (open ? 'Hide details' : 'Details') + '</button>'
        + '</div></div>';
    }).join('');

    if (!prompts) {
      prompts = '<div class="pw-empty"><h3>Nothing waiting</h3>'
        + '<p>Approval requests appear here when something asks to sign in as '
        + esc(SNAP.learner.name) + '.</p></div>';
    }

    var history = SNAP.authenticator.history.map(function (entry) {
      return '<div class="pw-authrow">'
        + '<span class="pw-dot' + (String(entry.result).indexOf('Denied') === 0
            ? ' is-caution' : entry.result === 'Approved' ? ' is-good' : ' is-accent')
        + '" aria-hidden="true"></span>'
        + '<span class="pw-authrow-main"><b>' + esc(entry.app) + ' · ' + esc(entry.result) + '</b>'
        + '<span>' + esc(entry.device) + ' · ' + esc(entry.location) + '</span></span>'
        + '<span class="pw-authrow-when">' + esc(entry.when) + '</span>'
        + '</div>';
    }).join('');

    return ''
      + '<div class="pw-app">'
      + '  <div class="pw-pane pw-mainpane">'
      + '    <div class="pw-pane-head"><h3>Waiting for you</h3>'
      + '<span class="pw-spacer"></span>'
      + '<span class="pw-chip is-plain">' + esc(SNAP.learner.email) + '</span></div>'
      + '    <div class="pw-pane-scroll" data-scroll-key="authenticator-main">' + prompts
      + '      <div class="pw-pane-head" style="border-top:1px solid var(--p-line)">'
      + '        <h3>Recent activity</h3><span class="pw-spacer"></span>'
      + '        <button type="button" class="pw-btn is-sm is-quiet" data-auth-history="1"'
      + (SNAP.authenticator.history_observed ? ' aria-pressed="true"' : '') + '>'
      + 'I checked this</button>'
      + '      </div>'
      + history
      + '    </div>'
      + '  </div>'
      + '</div>';
  }

  // =========================================================================
  // Directory
  // =========================================================================

  function renderDirectory() {
    var state = APP.directory;
    var term = state.search.trim().toLowerCase();
    var contacts = SNAP.directory.filter(function (contact) {
      if (!term) { return true; }
      return [contact.name, contact.role, contact.department, contact.email]
        .join(' ').toLowerCase().indexOf(term) >= 0;
    });

    var rows = contacts.map(function (contact) {
      return '<button type="button" class="pw-dirrow'
        + (state.selected === contact.id ? ' is-active' : '') + '"'
        + ' data-dir-open="' + esc(contact.id) + '">'
        + '<span class="pw-avatar is-neutral" aria-hidden="true">'
        + esc(contact.initials) + '</span>'
        + '<span class="pw-dirrow-main"><b>' + esc(contact.name) + '</b>'
        + '<span>' + esc(contact.role) + ' · ' + esc(contact.department) + '</span></span>'
        + (contact.kind === 'vendor' ? '<span class="pw-chip">supplier</span>' : '')
        + '</button>';
    }).join('') || '<div class="pw-empty"><h3>No match</h3></div>';

    var selected = state.selected ? findContact(state.selected) : null;

    return ''
      + '<div class="pw-app' + (state.mobileDetail ? ' is-split-mobile' : '') + '">'
      + '  <div class="pw-pane pw-listpane">'
      + '    <div class="pw-pane-head">'
      + '      <label class="pw-search">' + icon('search')
      + '        <input type="search" id="pw-dir-search" placeholder="Search people and suppliers"'
      + '          aria-label="Search the directory" value="' + esc(state.search) + '">'
      + '      </label>'
      + '    </div>'
      + '    <div class="pw-pane-scroll" data-scroll-key="directory-list:' + esc(state.search) + '">' + rows + '</div>'
      + '  </div>'
      + '  <div class="pw-pane pw-mainpane">'
      + (selected ? renderContact(selected)
                  : '<div class="pw-empty"><h3>Directory</h3>'
                    + '<p>The organisation&#39;s own record of who people are and '
                    + 'how to reach them.</p></div>')
      + '  </div>'
      + '</div>';
  }

  function renderContact(contact) {
    return '<div class="pw-pane-head">'
      + '<button type="button" class="pw-btn is-sm is-quiet pw-mobile-back" data-dir-back="1">'
      + icon('back') + '</button>'
      + '<h3>' + esc(contact.name) + '</h3></div>'
      + '<div class="pw-pane-scroll" data-scroll-key="directory-contact:' + esc(contact.id) + '"><div class="pw-contact">'
      + '<div class="pw-contact-head">'
      + '<span class="pw-avatar is-lg" aria-hidden="true">' + esc(contact.initials) + '</span>'
      + '<div><h3>' + esc(contact.name) + '</h3>'
      + '<p>' + esc(contact.role) + ' · ' + esc(contact.department) + '</p></div>'
      + '</div>'
      + '<dl>'
      + '<dt>Email</dt><dd>' + esc(contact.email) + '</dd>'
      + '<dt>Telephone</dt><dd>' + esc(contact.extension) + '</dd>'
      + '<dt>Location</dt><dd>' + esc(contact.location) + '</dd>'
      + '<dt>Relationship</dt><dd>' + esc(contact.relationship) + '</dd>'
      + '<dt>Known channels</dt><dd>' + esc((contact.channels || []).join(' · ')) + '</dd>'
      + '</dl>'
      + (contact.note ? '<div class="pw-note" style="margin-top:.9rem">'
          + esc(contact.note) + '</div>' : '')
      + (contact.can_call
          ? '<div class="pw-row" style="margin-top:1rem">'
            + '<button type="button" class="pw-btn" data-dir-call="' + esc(contact.id) + '">'
            + 'Call ' + esc(contact.extension) + '</button></div>'
          : '')
      + (contact.call_result
          ? '<div class="pw-note is-accent" style="margin-top:.8rem">'
            + esc(contact.call_result) + '</div>'
          : '')
      + '</div></div>';
  }

  // =========================================================================
  // Notes
  // =========================================================================
  //
  // The only application where the clipboard is allowed, and the only place
  // learner-authored text is deliberately kept. What is stored is what the
  // learner typed into this notebook — nothing about what was copied, nothing
  // about what was pasted, and no record that a paste happened at all.

  function renderNotes() {
    var state = APP.notes;
    if (!state.selected && SNAP.notes.length) { state.selected = SNAP.notes[0].id; }
    var current = null;
    SNAP.notes.forEach(function (note) {
      if (note.id === state.selected) { current = note; }
    });

    var rows = SNAP.notes.map(function (note) {
      return '<button type="button" class="pw-noterow'
        + (note.id === state.selected ? ' is-active' : '') + '"'
        + ' data-note-open="' + esc(note.id) + '">'
        + '<b>' + esc(note.title || 'Untitled') + '</b>'
        + '<span>' + esc(note.updated) + '</span></button>';
    }).join('') || '<div class="pw-empty"><h3>No notes</h3></div>';

    return ''
      + '<div class="pw-app">'
      + '  <div class="pw-pane pw-listpane" style="width:220px">'
      + '    <div class="pw-pane-head"><h3>Notes</h3><span class="pw-spacer"></span>'
      + '      <button type="button" class="pw-btn is-sm" data-note-new="1">New</button></div>'
      + '    <div class="pw-pane-scroll" data-scroll-key="notes-list">' + rows + '</div>'
      + '  </div>'
      + '  <div class="pw-pane pw-mainpane">'
      + (current
          ? '<div class="pw-noteedit">'
            + '<input class="pw-notetitle" id="pw-note-title" value="'
            + esc(current.title) + '" aria-label="Note title">'
            + '<textarea id="pw-note-body" aria-label="Note text">' + esc(current.body)
            + '</textarea>'
            + '<div class="pw-pane-foot">'
            + '<span class="pw-xsmall pw-muted">Saved automatically</span>'
            + '<span class="pw-spacer"></span>'
            + '<button type="button" class="pw-btn is-sm is-alert" data-note-delete="'
            + esc(current.id) + '">Delete note</button>'
            + '</div></div>'
          : '<div class="pw-empty"><h3>No note selected</h3></div>')
      + '  </div>'
      + '</div>';
  }

  // =========================================================================
  // Notifications
  // =========================================================================

  function renderNotifications() {
    var list = qs('#pw-notiflist');
    if (!SNAP.notifications.length) {
      list.innerHTML = '<div class="pw-empty"><h3>Nothing new</h3></div>';
      return;
    }
    list.innerHTML = SNAP.notifications.map(function (entry) {
      return '<div class="pw-notif' + (entry.unread ? ' is-unread' : '') + '">'
        + '<span class="pw-notif-icon is-' + esc(entry.kind) + '">'
        + icon(notifIcon(entry.kind)) + '</span>'
        + '<span class="pw-notif-main"><b>' + esc(entry.title) + '</b>'
        + '<p>' + esc(entry.body) + '</p>'
        + '<span class="pw-notif-when">' + esc(entry.when) + '</span>'
        + (entry.opens
            ? '<span class="pw-notif-actions">'
              + '<button type="button" class="pw-btn is-sm" data-notif-open="'
              + esc(entry.id) + '">Open</button></span>'
            : '')
        + '</span></div>';
    }).join('');
  }

  function notifIcon(kind) {
    if (kind === 'mail') { return 'mail'; }
    if (kind === 'security') { return 'alert'; }
    if (kind === 'file') { return 'folder'; }
    if (kind === 'auth') { return 'shield'; }
    if (kind === 'message') { return 'chat'; }
    return 'info';
  }

  var TOAST_LIMIT = 3;

  /* Toasts are drawn for notifications that are new *to this client* since
   * the last snapshot. They are pure presentation: every one of them is
   * already in the notification panel, so a missed toast loses nothing.
   *
   * The first snapshot of a session never toasts. A learner who refreshes an
   * hour into a session has not just received nine things; they are looking
   * again at a mailbox that already contained them, and replaying the whole
   * backlog as if it had just landed would misrepresent the world -- loudly.
   */
  var toastsPrimed = false;

  function syncToasts() {
    var fresh = [];
    SNAP.notifications.forEach(function (entry) {
      if (!seenNotifications[entry.id]) {
        seenNotifications[entry.id] = true;
        if (entry.unread) { fresh.push(entry); }
      }
    });
    if (!toastsPrimed) {
      toastsPrimed = true;
      return;
    }
    fresh.sort(function (a, b) { return a.order - b.order; });
    fresh.slice(-TOAST_LIMIT).forEach(showToast);
  }

  function showToast(entry) {
    var host = qs('#pw-toasts');
    // Bounded on purpose. A workstation that stacks nine cards down the screen
    // is not conveying urgency, it is hiding the work.
    while (host.children.length >= TOAST_LIMIT) {
      host.removeChild(host.firstChild);
    }
    var node = document.createElement('div');
    node.className = 'pw-toast';
    node.innerHTML = '<span class="pw-notif-icon is-' + esc(entry.kind) + '">'
      + icon(notifIcon(entry.kind)) + '</span>'
      + '<span class="pw-toast-main"><b>' + esc(entry.title) + '</b>'
      + '<p>' + esc(entry.body) + '</p></span>'
      + (entry.opens
          ? '<button type="button" class="pw-btn is-sm" data-notif-open="'
            + esc(entry.id) + '">Open</button>' : '')
      + '<button type="button" class="pw-toast-close" aria-label="Dismiss">&times;</button>';
    host.appendChild(node);
    node.querySelector('.pw-toast-close').addEventListener('click', function () {
      retireToast(node);
    });
    window.setTimeout(function () { retireToast(node); }, 9000);
  }

  function retireToast(node) {
    if (!node.parentNode || node.classList.contains('is-leaving')) { return; }
    if (prefersReducedMotion()) {
      node.parentNode.removeChild(node);
      return;
    }
    node.classList.add('is-leaving');
    window.setTimeout(function () {
      if (node.parentNode) { node.parentNode.removeChild(node); }
    }, 200);
  }

  function showTransient(text) {
    showToast({ id: 'transient-' + Date.now(), kind: 'system',
                title: 'Workstation', body: text, opens: null });
  }

  // =========================================================================
  // The safer-alternative comparison  (architecture §12, provisional)
  // =========================================================================
  //
  // Entirely server-decided. In an Assessment attempt the snapshot has no
  // ``comparison`` at all — there is nothing here to hide, reveal or style
  // around. Continue posts an acknowledgement, which dismisses the
  // explanation and changes no factual state: the world the learner returns to
  // is the one their decision produced.

  var comparisonShown = null;

  function renderComparison() {
    var comparison = SNAP.comparison;
    if (!comparison) { comparisonShown = null; return; }
    if (comparisonShown === comparison.decision) { return; }
    if (!window.RewindSecComparison) {
      send('session.acknowledge');
      return;
    }
    comparisonShown = comparison.decision;
    window.RewindSecComparison.show({
      heading: comparison.heading,
      what_you_did: comparison.what_you_did,
      what_followed: comparison.what_followed,
      evidence: comparison.evidence,
      safer_process: comparison.safer_process,
      likely_outcome: comparison.likely_outcome,
      still_true: comparison.still_true
    }).then(function () {
      send('session.acknowledge');
    });
  }

  // =========================================================================
  // Input
  // =========================================================================

  function closestData(target, attribute) {
    var node = target;
    while (node && node !== document) {
      if (node.getAttribute && node.hasAttribute(attribute)) {
        return { node: node, value: node.getAttribute(attribute) };
      }
      node = node.parentNode;
    }
    return null;
  }

  function bindWindow(node, appId) {
    node.addEventListener('mousedown', function () {
      focusApp(appId);
      raiseWindow(node);
    });
    node.addEventListener('click', function (event) {
      var close = closestData(event.target, 'data-win-close');
      if (close) { closeApp(close.value); return; }
      var min = closestData(event.target, 'data-win-min');
      if (min) { minimiseApp(min.value); return; }
      var max = closestData(event.target, 'data-win-max');
      if (max) { toggleMaximiseApp(max.value); }
    });

    // Double-clicking the title bar is the ordinary desktop shortcut for
    // maximise/restore; it is purely a convenience on top of the button and
    // does not go through the click handler above (a dblclick fires two
    // click events first, and toggling on both would cancel itself out).
    node.addEventListener('dblclick', function (event) {
      var handle = closestData(event.target, 'data-drag');
      if (!handle) { return; }
      if (closestData(event.target, 'data-win-close')
          || closestData(event.target, 'data-win-min')
          || closestData(event.target, 'data-win-max')) { return; }
      toggleMaximiseApp(appId);
    });

    var drag = null;
    node.addEventListener('mousedown', function (event) {
      var handle = closestData(event.target, 'data-drag');
      if (!handle || !canDrag()) { return; }
      if (closestData(event.target, 'data-win-close')
          || closestData(event.target, 'data-win-min')
          || closestData(event.target, 'data-win-max')) { return; }
      // A maximised window has no position to drag -- it fills the work
      // area by definition, and toggling it back on a plain mousedown would
      // fight with the title bar's double-click-to-restore gesture above.
      // Restore it (with the button or a double-click) before dragging it.
      if (WIN[appId] && WIN[appId].maximized) { return; }
      var win = WIN[appId];
      drag = { x: event.clientX, y: event.clientY, ox: win.x, oy: win.y };
      event.preventDefault();
    });
    document.addEventListener('mousemove', function (event) {
      if (!drag) { return; }
      var win = WIN[appId];
      var size = areaSize();
      win.x = clamp(drag.ox + (event.clientX - drag.x), 4, Math.max(4, size.w - win.w - 4));
      win.y = clamp(drag.oy + (event.clientY - drag.y), 4, Math.max(4, size.h - win.h - 4));
      node.style.left = win.x + 'px';
      node.style.top = win.y + 'px';
    });
    document.addEventListener('mouseup', function () { drag = null; });
  }

  function raiseWindow(node) {
    var appId = node.id.replace('pw-win-', '');
    if (WIN[appId]) {
      WIN[appId].z = (zCounter += 1);
      node.style.zIndex = WIN[appId].z;
    }
  }

  function handleClick(event) {
    if (!SNAP) { return; }
    var hit;

    // -- rail ---------------------------------------------------------------
    hit = closestData(event.target, 'data-app');
    if (hit) {
      var appId = hit.value;
      if (WIN[appId] && WIN[appId].open && !WIN[appId].minimized
          && topWindow() === appId) {
        minimiseApp(appId);
      } else {
        openApp(appId);
      }
      return;
    }

    // -- mail ---------------------------------------------------------------
    hit = closestData(event.target, 'data-mail-folder');
    if (hit) { APP.mail.folder = hit.value; APP.mail.search = ''; render(); return; }

    hit = closestData(event.target, 'data-mail-open');
    if (hit) { openMessage(hit.value); return; }

    hit = closestData(event.target, 'data-mail-back');
    if (hit) { APP.mail.mobileDetail = false; render(); return; }

    hit = closestData(event.target, 'data-mail-headers');
    if (hit) {
      APP.mail.headers = !APP.mail.headers;
      render();
      if (APP.mail.headers) { send('mail.inspect_headers', hit.value); }
      return;
    }

    hit = closestData(event.target, 'data-mail-inspect-link');
    if (hit) {
      var wasShown = APP.mail.linkShown === hit.value;
      APP.mail.linkShown = wasShown ? null : hit.value;
      render();
      if (!wasShown) {
        var parts = hit.value.split(':');
        send('mail.inspect_link', parts[0], { index: Number(parts[1]) });
      }
      return;
    }

    hit = closestData(event.target, 'data-mail-link');
    if (hit) {
      // The destination is not held here unless it was inspected, so the
      // server resolves it: the client says "the second link on that message".
      var linkParts = hit.value.split(':');
      openApp('browser');
      send('mail.open_link', linkParts[0], { index: Number(linkParts[1]) })
        .then(function (payload) {
          if (payload && payload.notice && payload.notice.url) {
            var tab = ensureTab();
            tab.history = tab.history.slice(0, tab.index + 1);
            tab.history.push(payload.notice.url);
            tab.index = tab.history.length - 1;
            tab.url = payload.notice.url;
            tab.urlDraft = null;
            render();
          }
        });
      return;
    }

    hit = closestData(event.target, 'data-att-inspect');
    if (hit) {
      var attKey = 'att:' + hit.value;
      var open = APP.mail.linkShown === attKey;
      APP.mail.linkShown = open ? null : attKey;
      render();
      if (!open) {
        var attParts = hit.value.split(':');
        send('mail.inspect_attachment', attParts[0], { index: Number(attParts[1]) });
      }
      return;
    }

    hit = closestData(event.target, 'data-att-download');
    if (hit) {
      var dl = hit.value.split(':');
      send('mail.download_attachment', dl[0], { index: Number(dl[1]) });
      return;
    }

    hit = closestData(event.target, 'data-mail-reply');
    if (hit) {
      APP.mail.composing = hit.value;
      APP.mail.draft = defaultReply(findMail(hit.value));
      render();
      return;
    }

    hit = closestData(event.target, 'data-mail-cancel');
    if (hit) { APP.mail.composing = null; APP.mail.draft = ''; render(); return; }

    hit = closestData(event.target, 'data-mail-send');
    if (hit) {
      var box = qs('#pw-compose-body');
      var text = (box ? box.value : APP.mail.draft);
      APP.mail.composing = null;
      APP.mail.draft = '';
      send('mail.reply', hit.value, { text: text });
      return;
    }

    hit = closestData(event.target, 'data-mail-forward');
    if (hit) {
      APP.mail.forwarding = hit.value;
      APP.mail.forwardRecipient = null;
      APP.mail.forwardDraft = '';
      APP.mail.composing = null;
      render();
      return;
    }

    // Cancel is purely local: no request is made, so there is nothing on the
    // server to undo.
    hit = closestData(event.target, 'data-mail-forward-cancel');
    if (hit) {
      APP.mail.forwarding = null;
      APP.mail.forwardRecipient = null;
      APP.mail.forwardDraft = '';
      render();
      return;
    }

    hit = closestData(event.target, 'data-mail-forward-send');
    if (hit) {
      var recipient = APP.mail.forwardRecipient;
      if (!recipient) { return; }
      var noteBox = qs('#pw-forward-note');
      var note = noteBox ? noteBox.value : APP.mail.forwardDraft;
      var forwardParams = { recipient: recipient };
      if (note) { forwardParams.text = note; }
      var sourceId = hit.value;
      send('mail.forward', sourceId, forwardParams).then(function () {
        // Only close on the authoritative result: if the server refused, the
        // composer is still there with what was typed in it.
        if (SNAP && findMail(sourceId) && findMail(sourceId).forwarded) {
          APP.mail.forwarding = null;
          APP.mail.forwardRecipient = null;
          APP.mail.forwardDraft = '';
          render();
        }
      });
      return;
    }

    hit = closestData(event.target, 'data-mail-report');
    if (hit) { APP.mail.selected = null; send('mail.report', hit.value); return; }

    hit = closestData(event.target, 'data-mail-delete');
    if (hit) { APP.mail.selected = null; send('mail.delete', hit.value); return; }

    hit = closestData(event.target, 'data-mail-restore');
    if (hit) { APP.mail.selected = null; send('mail.restore', hit.value); return; }

    hit = closestData(event.target, 'data-mail-delete-permanent');
    if (hit) {
      var permanentId = hit.value;
      confirmDialog('Delete this message permanently?',
        'This removes it from the mailbox. It cannot be restored.',
        function () {
          APP.mail.selected = null;
          send('mail.delete_permanently', permanentId);
        });
      return;
    }

    // -- browser ------------------------------------------------------------
    hit = closestData(event.target, 'data-tab-close');
    if (hit) {
      event.stopPropagation();
      APP.browser.tabs.splice(Number(hit.value), 1);
      APP.browser.active = Math.max(0, APP.browser.active - 1);
      render();
      return;
    }

    hit = closestData(event.target, 'data-tab-select');
    if (hit) { APP.browser.active = Number(hit.value); render(); return; }

    hit = closestData(event.target, 'data-tab-new');
    if (hit) {
      APP.browser.tabs.push({
        url: SNAP.browser.home, history: [SNAP.browser.home], index: 0,
        urlDraft: null
      });
      APP.browser.active = APP.browser.tabs.length - 1;
      render();
      return;
    }

    hit = closestData(event.target, 'data-nav');
    if (hit) {
      var tab = ensureTab();
      if (hit.value === 'back' && tab.index > 0) {
        tab.index -= 1; tab.url = tab.history[tab.index]; tab.urlDraft = null;
      } else if (hit.value === 'forward' && tab.index < tab.history.length - 1) {
        tab.index += 1; tab.url = tab.history[tab.index]; tab.urlDraft = null;
      }
      render();
      return;
    }

    hit = closestData(event.target, 'data-go');
    if (hit) { browserNavigate(hit.value); return; }

    hit = closestData(event.target, 'data-signin-retry');
    if (hit) { send('browser.sign_in_retry', null, { url: hit.value }); return; }

    hit = closestData(event.target, 'data-pay-release');
    if (hit) {
      releasePayment(hit.value,
        hit.node.getAttribute('data-pay-context'));
      return;
    }

    hit = closestData(event.target, 'data-pay-reset');
    if (hit) {
      if (APP.browser.accountDraft) { delete APP.browser.accountDraft[hit.value]; }
      render();
      return;
    }

    hit = closestData(event.target, 'data-support');
    if (hit) { send('browser.support_action', null, { choice: hit.value }); return; }

    hit = closestData(event.target, 'data-page-download');
    if (hit) {
      send('browser.download', null,
           { url: hit.node.getAttribute('data-page-url'),
             resource: hit.value });
      return;
    }

    // -- files ---------------------------------------------------------------
    hit = closestData(event.target, 'data-file-location');
    if (hit) {
      APP.files.location = hit.value;
      APP.files.selected = null;
      render();
      return;
    }

    hit = closestData(event.target, 'data-file-select');
    if (hit) {
      APP.files.selected = hit.value;
      APP.files.renaming = false;
      render();
      send('files.inspect', hit.value);
      return;
    }

    hit = closestData(event.target, 'data-file-open');
    if (hit) { openFile(hit.value); return; }

    hit = closestData(event.target, 'data-file-rename');
    if (hit) { APP.files.renaming = hit.value; render(); return; }

    hit = closestData(event.target, 'data-file-rename-save');
    if (hit) {
      var input = qs('#pw-file-rename');
      var name = input ? input.value.trim() : '';
      APP.files.renaming = false;
      if (name) { send('files.rename', hit.value, { name: name }); }
      else { render(); }
      return;
    }

    hit = closestData(event.target, 'data-file-delete');
    if (hit) {
      var entry = findFile(hit.value);
      if (!entry) { return; }
      var fileId = hit.value;
      confirmDialog('Delete ' + entry.file.name + '?',
        'It will be removed from ' + entry.location.name + '.',
        function () {
          APP.files.selected = null;
          send('files.delete', fileId);
        });
      return;
    }

    // -- messages -------------------------------------------------------------
    hit = closestData(event.target, 'data-conv-open');
    if (hit) {
      APP.messages.conversation = hit.value;
      APP.messages.mobileDetail = true;
      render();
      send('messages.open', hit.value);
      return;
    }

    hit = closestData(event.target, 'data-conv-back');
    if (hit) { APP.messages.mobileDetail = false; render(); return; }

    hit = closestData(event.target, 'data-conv-verify');
    if (hit) { send('messages.verify', hit.value); return; }

    hit = closestData(event.target, 'data-msg-send');
    if (hit) {
      var msgBox = qs('#pw-msg-input');
      var msgText = msgBox ? msgBox.value.trim() : '';
      if (msgText) {
        APP.messages.draft = '';
        send('messages.send', hit.value, { text: msgText });
      }
      return;
    }

    // -- authenticator ----------------------------------------------------------
    hit = closestData(event.target, 'data-mfa-details');
    if (hit) {
      APP.authenticator.details[hit.value] = !APP.authenticator.details[hit.value];
      render();
      if (APP.authenticator.details[hit.value]) {
        send('auth.inspect_request', hit.value);
      }
      return;
    }

    hit = closestData(event.target, 'data-auth-history');
    if (hit) { send('auth.inspect_history'); return; }

    hit = closestData(event.target, 'data-mfa-approve');
    if (hit) { send('auth.approve', hit.value); return; }

    hit = closestData(event.target, 'data-mfa-deny');
    if (hit) { send('auth.deny', hit.value); return; }

    // -- directory ---------------------------------------------------------------
    hit = closestData(event.target, 'data-dir-open');
    if (hit) {
      APP.directory.selected = hit.value;
      APP.directory.mobileDetail = true;
      render();
      send('directory.open', hit.value);
      return;
    }

    hit = closestData(event.target, 'data-dir-back');
    if (hit) { APP.directory.mobileDetail = false; render(); return; }

    hit = closestData(event.target, 'data-dir-call');
    if (hit) { send('directory.call', hit.value); return; }

    // -- notes ---------------------------------------------------------------------
    hit = closestData(event.target, 'data-note-open');
    if (hit) {
      APP.notes.selected = hit.value;
      render();
      send('notes.open', hit.value);
      return;
    }

    hit = closestData(event.target, 'data-note-new');
    if (hit) {
      send('notes.create').then(function (payload) {
        if (payload && payload.notice && payload.notice.note) {
          APP.notes.selected = payload.notice.note;
          render();
        }
      });
      return;
    }

    hit = closestData(event.target, 'data-note-delete');
    if (hit) {
      var noteId = hit.value;
      APP.notes.selected = null;
      send('notes.delete', noteId);
      return;
    }

    // -- notifications ---------------------------------------------------------------
    hit = closestData(event.target, 'data-notif-open');
    if (hit) {
      var target = null;
      SNAP.notifications.forEach(function (entry) {
        if (entry.id === hit.value) { target = entry.opens; }
      });
      send('notifications.open', hit.value).then(function () {
        if (target) { openApp(target.app, target); }
      });
      return;
    }
  }

  function openFile(fileId) {
    var entry = findFile(fileId);
    if (!entry) { return; }
    var file = entry.file;
    if (file.state !== 'unavailable' && file.macro) {
      confirmDialog('Open ' + file.name + '?',
        'This workbook wants to run its own content when it opens.',
        function () { send('files.open', fileId); });
      return;
    }
    send('files.open', fileId);
  }

  function releasePayment(url, contextId) {
    var page = pageFor(url) || {};
    var contexts = page.payment_contexts || [];
    var context = null;
    for (var i = 0; i < contexts.length; i += 1) {
      if (contexts[i].id === contextId) { context = contexts[i]; break; }
    }
    if (!context) { return; }
    var field = qs('#pw-pay-account-' + cssEscape(context.id));
    var value = field ? field.value.trim() : (context.account_of_record || '');
    var changed = value !== (context.account_of_record || '');
    confirmDialog('Release ' + context.amount + ' for ' + context.reference
        + ' (' + context.queue_ref + ')?',
      changed
        ? 'The settlement account has been changed from the one held on file.'
        : 'The payment goes to the account of record.',
      function () {
        send('browser.release_payment', null,
          { url: url, account: value, context: context.id });
      });
  }

  /* Payment context ids are server-authored and match /^[a-z0-9-]+$/, but the
   * selector is built from one anyway rather than trusted. */
  function cssEscape(value) {
    return String(value).replace(/[^A-Za-z0-9_-]/g, '');
  }

  /* The password field is never read, never serialised and never sent. What is
   * submitted is the address of the page; the server decides what signing in
   * there means. The field is cleared so the typed value does not survive even
   * in the DOM. */
  function handleSubmit(event) {
    var form = event.target;
    if (!form.hasAttribute || !form.hasAttribute('data-signin')) { return; }
    event.preventDefault();
    var passwordField = qs('#pw-signin-pass', form);
    if (passwordField) { passwordField.value = ''; }
    send('browser.sign_in', null, { url: form.getAttribute('data-signin') });
  }

  // =========================================================================
  // Generic confirm dialog
  // =========================================================================

  var confirmCallback = null;
  var confirmReturnFocus = null;

  function confirmDialog(title, body, onConfirm) {
    confirmCallback = onConfirm;
    confirmReturnFocus = document.activeElement;
    qs('#pw-confirm-title').textContent = title;
    qs('#pw-confirm-body').textContent = body;
    qs('#pw-confirm-scrim').hidden = false;
    qs('#pw-confirm-ok').focus();
  }

  function closeConfirm() {
    qs('#pw-confirm-scrim').hidden = true;
    confirmCallback = null;
    if (confirmReturnFocus && document.contains(confirmReturnFocus)) {
      confirmReturnFocus.focus();
    }
    confirmReturnFocus = null;
  }

  // =========================================================================
  // End training
  // =========================================================================

  function outstandingSummary() {
    if (!SNAP) { return 'Nothing is outstanding.'; }
    var outstanding = SNAP.tasks.filter(function (task) {
      return task.state === 'outstanding';
    });
    if (!outstanding.length) { return 'Nothing is outstanding.'; }
    return outstanding.length + ' item'
      + (outstanding.length === 1 ? ' is' : 's are') + ' still outstanding: '
      + outstanding.map(function (task) { return task.label; }).join('; ') + '.';
  }

  /* Ending the attempt is a server operation. It persists the lifecycle,
   * closes the session to further consequential actions and preserves every
   * fact for the debrief — it resets nothing. The debrief that follows is
   * derived from the persisted session, not from anything this file kept. */
  function endSession() {
    ended = true;
    stopStream();
    if (tickTimer) { window.clearInterval(tickTimer); }
    request('/api/session/end', { method: 'POST', body: {} })
      .then(function () { return request('/api/session/debrief'); })
      .then(function (payload) {
        try {
          window.sessionStorage.setItem('rewindsec.prototype.run',
                                        JSON.stringify(payload.debrief));
        } catch (err) { /* private mode: the debrief falls back to its example */ }
      })
      .catch(function () { /* the results page falls back to its example */ })
      .then(function () { window.location.href = '/results'; });
  }

  // =========================================================================
  // Live updates
  // =========================================================================
  //
  // The stream carries revision numbers, not content. When the revision moves
  // we re-read the authoritative snapshot through the ordinary path, so there
  // is exactly one way state reaches this client and exactly one thing to keep
  // safe. Losing the connection changes nothing: EventSource reconnects on its
  // own, and the tick below keeps the world moving regardless.

  function startStream() {
    if (!window.EventSource) { return; }
    try {
      stream = new window.EventSource('/api/events');
    } catch (err) {
      stream = null;
      return;
    }
    stream.addEventListener('revision', function (event) {
      var revision = null;
      try { revision = JSON.parse(event.data).revision; }
      catch (err) { return; }
      if (SNAP && revision > SNAP.session.revision) { refresh().catch(function () {}); }
    });
    stream.onerror = function () {
      // EventSource reconnects by itself and replays Last-Event-ID. Nothing to
      // do here, and nothing about the simulation has changed.
    };
  }

  function stopStream() {
    if (stream) { stream.close(); stream = null; }
  }

  /* Asks the server to let simulation time move on by one step. The browser
   * decides only *whether* to ask; the size of a step is an authored constant
   * on the server, and no elapsed real time is measured anywhere. A slow
   * machine, a throttled background tab and a fast one all buy exactly the
   * same amount of simulation time per request. If this never fires — a
   * suspended tab, a closed laptop — nothing is lost and nothing is skipped;
   * the schedule simply waits. This timer does not own consequence timing. */
  function startTicking() {
    tickTimer = window.setInterval(function () {
      if (ended || !SNAP || !SNAP.session.active) { return; }
      if (document.hidden) { return; }
      request('/api/session/tick', { method: 'POST', body: {} })
        .then(adopt)
        .catch(function () { /* transient; the next tick tries again */ });
    }, 4000);

    window.setInterval(function () {
      if (SNAP) { qs('#pw-clock').textContent = nowLabel(); }
    }, 2000);
  }

  // =========================================================================
  // Shell wiring
  // =========================================================================

  function bindShell() {
    document.addEventListener('click', handleClick);
    document.addEventListener('submit', handleSubmit);

    // A <select> fires "input" in current browsers but "change" is the
    // event it has always fired, so the recipient picker listens for both.
    document.addEventListener('change', function (event) {
      if (event.target.id === 'pw-forward-to') {
        APP.mail.forwardRecipient = event.target.value || null;
        render();
      }
    });

    document.addEventListener('input', function (event) {
      var node = event.target;
      if (node.id === 'pw-mail-search') { APP.mail.search = node.value; render(); }
      else if (node.id === 'pw-compose-body') { APP.mail.draft = node.value; }
      else if (node.id === 'pw-forward-note') { APP.mail.forwardDraft = node.value; }
      else if (node.id === 'pw-forward-to') {
        APP.mail.forwardRecipient = node.value || null;
        APP.mail.forwardDraft = (qs('#pw-forward-note') || {}).value
          || APP.mail.forwardDraft;
        render();
      }
      else if (node.id === 'pw-url-input') { ensureTab().urlDraft = node.value; }
      else if (node.id === 'pw-dir-search') { APP.directory.search = node.value; render(); }
      else if (node.id === 'pw-msg-input') { APP.messages.draft = node.value; }
      else if (node.id && node.id.indexOf('pw-pay-account-') === 0) {
        if (!APP.browser.accountDraft) { APP.browser.accountDraft = {}; }
        APP.browser.accountDraft[node.id.slice('pw-pay-account-'.length)] =
          node.value;
      }
      else if (node.id === 'pw-note-title' || node.id === 'pw-note-body') {
        queueNoteSave();
      }
    });

    document.addEventListener('keydown', function (event) {
      if (event.key !== 'Enter') { return; }
      if (event.target.id === 'pw-url-input') {
        event.preventDefault();
        browserNavigate(event.target.value);
      } else if (event.target.id === 'pw-msg-input') {
        event.preventDefault();
        var text = event.target.value.trim();
        if (text) {
          APP.messages.draft = '';
          send('messages.send', APP.messages.conversation, { text: text });
        }
      }
    });

    // Escape closes non-blocking surfaces only. The comparison screen owns its
    // own key handling and deliberately does not close on Escape.
    document.addEventListener('keydown', function (event) {
      if (event.key !== 'Escape') { return; }
      if (!qs('#pw-confirm-scrim').hidden) { closeConfirm(); return; }
      if (!qs('#pw-end-scrim').hidden) { closeEndDialog(); return; }
      if (!qs('#pw-notifpanel').hidden) { toggleNotifications(false); return; }
    });

    qs('#pw-notif-btn').addEventListener('click', function () {
      toggleNotifications(qs('#pw-notifpanel').hidden);
    });
    qs('#pw-notif-close').addEventListener('click', function () {
      toggleNotifications(false);
    });
    qs('#pw-notif-clear').addEventListener('click', function () {
      send('notifications.mark_read');
    });

    qs('#pw-end-btn').addEventListener('click', function () {
      qs('#pw-end-detail').textContent = outstandingSummary();
      qs('#pw-end-scrim').hidden = false;
      qs('#pw-end-confirm').focus();
    });
    qs('#pw-end-cancel').addEventListener('click', closeEndDialog);
    qs('#pw-end-confirm').addEventListener('click', endSession);

    qs('#pw-confirm-cancel').addEventListener('click', closeConfirm);
    qs('#pw-confirm-ok').addEventListener('click', function () {
      var callback = confirmCallback;
      closeConfirm();
      if (callback) { callback(); }
    });

    window.addEventListener('resize', function () { reflowWindows(); render(); });
    window.addEventListener('beforeunload', stopStream);
  }

  /* Notes save on a short debounce rather than on every keystroke: one POST
   * per keypress would be a write amplifier for no benefit, and the note is
   * the learner's own working document, not a stream of events. */
  function queueNoteSave() {
    if (noteSaveTimer) { window.clearTimeout(noteSaveTimer); }
    noteSaveTimer = window.setTimeout(function () {
      var titleField = qs('#pw-note-title');
      var bodyField = qs('#pw-note-body');
      if (!APP.notes.selected || !titleField || !bodyField) { return; }
      send('notes.save', APP.notes.selected,
           { title: titleField.value, body: bodyField.value });
    }, 700);
  }

  function closeEndDialog() {
    qs('#pw-end-scrim').hidden = true;
    qs('#pw-end-btn').focus();
  }

  function toggleNotifications(open) {
    qs('#pw-notifpanel').hidden = !open;
    qs('#pw-notif-btn').setAttribute('aria-expanded', open ? 'true' : 'false');
    if (open) {
      send('notifications.mark_read');
      qs('#pw-notif-close').focus();
    } else {
      renderTopBar();
    }
  }

  // =========================================================================
  // Boot
  // =========================================================================
  //
  // Resume first, start second, and never the other way round. Loading this
  // page is a read: it finds the session that is already there and rebuilds
  // the workstation from the server's persisted world. Only when there is no
  // live session at all does the entry screen's focus and mode create one,
  // and that creation is an explicit POST.
  //
  // The query string is not authority over a session that exists. A stale
  // link, a bookmark or a second tab carrying ?focus=…&mode=… different from
  // the running attempt does not end it, replace it or change it — the server
  // would refuse anyway. The mismatch is reconciled in the address bar, which
  // is presentation, and nowhere else.

  function boot() {
    APP = defaultAppState();
    bindShell();

    // The server told the shell whether this browser already has a session.
    // A hint, not a fact: if it is wrong, both paths below recover. What it
    // buys is not asking a question whose answer is a 404 every single time
    // somebody starts training.
    var shell = qs('#pw-ws');
    if (shell && shell.getAttribute('data-has-session') === '0') {
      startNew().then(ready).catch(fail);
      return;
    }

    refresh()
      .then(function () {
        if (!SNAP.session.active) { return startNew(); }
        reconcileUrl();
        return null;
      })
      .catch(function (error) {
        if (error && error.status === 404) { return startNew(); }
        throw error;
      })
      .then(ready)
      .catch(fail);
  }

  /* Makes the address bar agree with the session that is actually running.
   * Cosmetic and deliberately so: it rewrites history, never state. Nothing
   * here posts, and the factual session is untouched whatever the URL said. */
  function reconcileUrl() {
    if (!window.history || !window.history.replaceState) { return; }
    var wantedFocus = param('focus');
    var wantedMode = param('mode');
    if (!wantedFocus && !wantedMode) { return; }
    if (wantedFocus === SNAP.session.focus && wantedMode === SNAP.session.mode) {
      return;
    }
    try {
      window.history.replaceState(null, '', window.location.pathname
        + '?focus=' + encodeURIComponent(SNAP.session.focus)
        + '&mode=' + encodeURIComponent(SNAP.session.mode));
    } catch (err) { /* history is unavailable; the URL is only decoration */ }
  }

  /* Two ways in, and they are not interchangeable.
   *
   * ?assessment=<id> starts (or resumes) an Assessment *attempt*: the server
   * resolves who this browser is from the signed cookie, checks that the
   * assessment has actually been assigned to them, applies the retry policy
   * and derives the focus and the mode from the definition. The id in the
   * query string is a request to be checked, never an authorisation — a
   * learner who edits it is asking for an assessment they were not given,
   * and is refused.
   *
   * Everything else is a self-directed run, where focus and mode are the
   * learner's own choices. For `mode=assessment` the same generic endpoint
   * delegates to the server-owned self-directed Attempt policy; it never
   * directly constructs a bare Assessment session. */
  function startNew() {
    var assessmentId = param('assessment');
    if (assessmentId) {
      return request('/api/session/assessment/start', {
        method: 'POST',
        body: { assessment_id: assessmentId }
      }).then(adopt).catch(function (error) {
        if (error && error.status === 409
            && error.code === 'session_active') {
          return refresh();
        }
        throw error;
      });
    }
    return request('/api/session/start', {
      method: 'POST',
      body: { focus: param('focus') || 'mixed', mode: param('mode') || 'simulation' }
    }).then(adopt).catch(function (error) {
      // 409 means this browser turned out to have a live session after all —
      // a duplicated boot, or a stale "no session" hint. Read it; never
      // replace it.
      if (error && error.status === 409) {
        return refresh().then(reconcileUrl);
      }
      throw error;
    });
  }

  function ready() {
    if (!SNAP) { throw new Error('no snapshot'); }
    syncClock();
    render();
    openApp('mail');
    startStream();
    startTicking();
    if (window.RewindSecDevPanel) {
      window.RewindSecDevPanel.attach({
        snapshot: function () { return SNAP; },
        request: request,
        adopt: adopt,
        refresh: refresh
      });
    }
  }

  function fail(error) {
    var area = qs('#pw-workarea');
    if (area) {
      area.innerHTML = '<div class="pw-empty" style="padding-top:4rem">'
        + '<h3>The workstation could not start</h3>'
        + '<p>The server did not return a session. Reload the page to try '
        + 'again.</p></div>';
    }
    if (window.console) { window.console.error(error); }
  }

  boot();
}());
