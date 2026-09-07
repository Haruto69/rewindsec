/* Prototype developer panel — visibility and generic wiring.
 *
 * Explicitly not a learner feature. This file owns showing and hiding the
 * panel and the buttons that are the same on every prototype screen. The
 * workstation binds its own session controls to the same panel when it loads;
 * on screens where those controls make no sense, they are hidden rather than
 * left as dead buttons.
 *
 * Nothing here participates in the simulated experience.
 */
(function () {
  'use strict';

  var STORAGE_KEY = 'rewindsec.prototype.devpanel';
  var panel = document.getElementById('pw-dev');
  var toggle = document.getElementById('pw-dev-toggle');
  var hide = document.getElementById('pw-dev-hide');
  if (!panel || !toggle) { return; }

  function readStored() {
    try { return window.localStorage.getItem(STORAGE_KEY); }
    catch (err) { return null; }
  }

  function store(value) {
    try { window.localStorage.setItem(STORAGE_KEY, value); }
    catch (err) { /* private mode: the panel simply forgets between loads */ }
  }

  function setVisible(visible, remember) {
    panel.hidden = !visible;
    toggle.hidden = visible;
    // Only a deliberate toggle changes the stored preference. Applying
    // ?dev=0 for one screenshot must not silently hide the panel forever.
    if (remember) { store(visible ? 'open' : 'closed'); }
    if (visible) {
      var first = panel.querySelector('button, select, input, a');
      if (first) { first.focus(); }
    }
  }

  // ?dev=0 wins over the stored preference, so a screenshot run is one URL
  // away and does not have to be undone afterwards.
  var params = new URLSearchParams(window.location.search);
  var initial = params.get('dev') === '0' ? false
    : (readStored() === 'closed' ? false : true);
  setVisible(initial, false);

  toggle.addEventListener('click', function () { setVisible(true, true); });
  if (hide) { hide.addEventListener('click', function () { setVisible(false, true); }); }

  document.addEventListener('keydown', function (event) {
    if (event.ctrlKey && event.altKey && (event.key === 'p' || event.key === 'P')) {
      event.preventDefault();
      setVisible(panel.hidden, true);
    }
  });

  // Screens that are not the workstation have no session to drive. Hide the
  // session-scoped groups there rather than leaving buttons that do nothing.
  if (!document.getElementById('pw-workarea')) {
    var scoped = panel.querySelectorAll('[data-dev-scope="workstation"]');
    for (var i = 0; i < scoped.length; i += 1) { scoped[i].hidden = true; }
  }

  // The integrity controls exist only on learner surfaces, so the group that
  // demonstrates them is hidden on the trainer console rather than offering a
  // button that could not do anything.
  var isLearner = document.body.getAttribute('data-integrity') === 'learner';
  if (!isLearner) {
    var learnerOnly = panel.querySelectorAll('[data-dev-scope="learner"]');
    for (var j = 0; j < learnerOnly.length; j += 1) {
      learnerOnly[j].hidden = true;
    }
  }

  var shot = document.getElementById('pw-dev-screenshot');
  if (shot) {
    shot.addEventListener('click', function () {
      if (window.RewindSecIntegrity) {
        window.RewindSecIntegrity.showScreenshotNotice();
      }
    });
  }

  /* Session controls.
   *
   * Every one of these is a POST to a development-only server operation under
   * /prototype/api/dev/. None of them mutates client state, none of them can
   * produce a world a learner action could not have produced, and none of
   * them bypasses persistence: they go through the same service, the same
   * repository and the same projection. What they buy is time, not truth.
   *
   * The prototype's old "inject an event" and "force a consequence chain"
   * controls are gone on purpose. Those worked by writing consequences
   * straight into the browser's copy of the world, which is exactly the thing
   * this batch removed. To see a chain now, take the decision that causes it.
   */
  function bindSession(host) {
    var focusSelect = document.getElementById('pw-dev-focus');
    var modeSelect = document.getElementById('pw-dev-mode');
    var snapshot = host.snapshot();
    if (snapshot) {
      if (focusSelect) { focusSelect.value = snapshot.session.focus; }
      if (modeSelect) { modeSelect.value = snapshot.session.mode; }
    }

    /* Starting a different session is a POST, not a link.
     *
     * Navigating to /prototype/workstation?focus=…&mode=… does not and must
     * not replace a live session — a URL is not authority over a factual
     * record, and the server refuses it. So the dev panel asks for the thing
     * it actually means: the explicit new-session operation, which completes
     * the current attempt on the record and then opens the next one. */
    function go(focus, mode) {
      return host.request('/api/session/new', {
        method: 'POST',
        body: { focus: focus, mode: mode }
      }).then(function () {
        window.location.href = '/workstation?focus='
          + encodeURIComponent(focus) + '&mode=' + encodeURIComponent(mode);
      });
    }

    var restart = document.getElementById('pw-dev-restart');
    if (restart) {
      restart.addEventListener('click', function () {
        go(focusSelect.value, modeSelect.value);
      });
    }

    var reset = document.getElementById('pw-dev-reset');
    if (reset) {
      reset.addEventListener('click', function () {
        // Completes the server session and opens a fresh one with the same
        // focus and mode. The old session stays persisted and auditable:
        // nothing is deleted, and nothing is rewound.
        try { window.sessionStorage.removeItem('rewindsec.prototype.run'); }
        catch (err) { /* nothing to clear */ }
        var current = host.snapshot();
        go(current ? current.session.focus : 'mixed',
           current ? current.session.mode : 'simulation');
      });
    }

    var next = document.getElementById('pw-dev-next');
    if (next) {
      next.addEventListener('click', function () {
        host.request('/api/dev/deliver-next',
                     { method: 'POST', body: {} }).then(host.adopt);
      });
    }

    var all = document.getElementById('pw-dev-all');
    if (all) {
      all.addEventListener('click', function () {
        var remaining = 12;
        function step() {
          if (remaining <= 0) { return; }
          remaining -= 1;
          host.request('/api/dev/deliver-next',
                       { method: 'POST', body: {} }).then(host.adopt).then(step);
        }
        step();
      });
    }

    var advances = panel.querySelectorAll('[data-dev-advance]');
    for (var i = 0; i < advances.length; i += 1) {
      (function (button) {
        button.addEventListener('click', function () {
          host.request('/api/dev/advance', {
            method: 'POST',
            body: { milliseconds: Number(button.getAttribute('data-dev-advance')) }
          }).then(host.adopt);
        });
      }(advances[i]));
    }
  }

  window.RewindSecDevPanel = {
    element: panel,
    show: function () { setVisible(true, true); },
    hide: function () { setVisible(false, true); },
    attach: bindSession
  };
}());
