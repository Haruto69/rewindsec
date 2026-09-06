/* RewindSec 2.0 trainer console — the write operations.
 *
 * Batch 5 made every one of these real. Creating a student, a group, a
 * membership or an assessment, and assigning an assessment, are POSTs to
 * /prototype/api/trainer/*, applied to persisted records by
 * rewindsec.management.service and reloaded from the server afterwards.
 * Nothing on this page invents a row, and nothing survives only in the DOM.
 *
 * The duplicate-assignment interaction is the one worth reading closely.
 * Architecture §27 requires that a trainer assigning an assessment somebody
 * already receives is told *where it already comes from*, is asked whether to
 * assign again, and — if they confirm — gets a second assignment that keeps
 * its own provenance rather than replacing the first.
 *
 * The confirmation is enforced on the server, not here. This dialog is a
 * courtesy: the first POST carries no confirmation, the server answers 409
 * with the full provenance of every affected learner and writes nothing, and
 * only a second POST carrying an explicit confirm_duplicate:true creates the
 * row. A client that skipped this dialog entirely would still be refused.
 *
 * Every POST carries an idempotency token, so a retried submission — a
 * double-click, a lost response, a flaky connection — resolves to the
 * assignment already made instead of manufacturing a second one.
 */
(function () {
  'use strict';

  function qs(selector) { return document.querySelector(selector); }

  function esc(value) {
    return String(value === undefined || value === null ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function csrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute('content') : '';
  }

  /* A per-operation idempotency token. Random rather than derived from the
   * form contents: two *deliberate* duplicate assignments are the same form
   * contents and must be allowed to produce two rows. */
  function newRequestId() {
    if (window.crypto && window.crypto.randomUUID) {
      return window.crypto.randomUUID();
    }
    var bytes = new Uint8Array(16);
    if (window.crypto && window.crypto.getRandomValues) {
      window.crypto.getRandomValues(bytes);
    } else {
      for (var i = 0; i < bytes.length; i += 1) {
        bytes[i] = Math.floor(Math.random() * 256);
      }
    }
    return Array.prototype.map.call(bytes, function (b) {
      return ('0' + b.toString(16)).slice(-2);
    }).join('');
  }

  function post(url, payload) {
    return fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'X-CSRF-Token': csrfToken()
      },
      body: JSON.stringify(payload || {})
    }).then(function (response) {
      return response.json().catch(function () { return {}; })
        .then(function (data) {
          return { status: response.status, ok: response.ok, data: data };
        });
    });
  }

  function get(url) {
    return fetch(url, { headers: { Accept: 'application/json' } })
      .then(function (response) {
        return response.json().catch(function () { return {}; })
          .then(function (data) {
            return { status: response.status, ok: response.ok, data: data };
          });
      });
  }

  function errorText(result, fallback) {
    var error = result && result.data && result.data.error;
    if (error && error.message) { return error.message; }
    return fallback;
  }

  function say(element, message) {
    if (element) { element.textContent = message; }
  }

  // =======================================================================
  // Students
  // =======================================================================

  var newStudentButton = qs('#pw-new-student-btn');
  if (newStudentButton) {
    newStudentButton.addEventListener('click', function () {
      var status = qs('#pw-new-student-status');
      var name = qs('#pw-new-student-name').value.trim();
      if (!name) {
        say(status, 'Give the student a display name first.');
        qs('#pw-new-student-name').focus();
        return;
      }
      newStudentButton.disabled = true;
      say(status, 'Saving…');
      post('/prototype/api/trainer/students', {
        display_name: name,
        reference: qs('#pw-new-student-ref').value.trim() || null,
        cohort: qs('#pw-new-student-cohort').value.trim() || null
      }).then(function (result) {
        newStudentButton.disabled = false;
        if (!result.ok) {
          say(status, errorText(result, 'That student could not be saved.'));
          return;
        }
        window.location.reload();
      }).catch(function () {
        newStudentButton.disabled = false;
        say(status, 'Could not reach the server.');
      });
    });
  }

  // =======================================================================
  // Groups and membership
  // =======================================================================

  var newGroupButton = qs('#pw-new-group-btn');
  if (newGroupButton) {
    newGroupButton.addEventListener('click', function () {
      var status = qs('#pw-new-group-status');
      var name = qs('#pw-new-group-name').value.trim();
      if (!name) {
        say(status, 'Give the group a name first.');
        qs('#pw-new-group-name').focus();
        return;
      }
      newGroupButton.disabled = true;
      say(status, 'Saving…');
      post('/prototype/api/trainer/groups', {
        name: name,
        description: qs('#pw-new-group-desc').value.trim() || null
      }).then(function (result) {
        newGroupButton.disabled = false;
        if (!result.ok) {
          say(status, errorText(result, 'That group could not be saved.'));
          return;
        }
        window.location.reload();
      }).catch(function () {
        newGroupButton.disabled = false;
        say(status, 'Could not reach the server.');
      });
    });
  }

  var membership = qs('#pw-membership');
  if (membership) {
    var groupId = membership.getAttribute('data-group-id');
    var memberStatus = qs('#pw-member-status');

    var addButton = qs('#pw-member-add');
    if (addButton) {
      addButton.addEventListener('click', function () {
        var select = qs('#pw-member-student');
        if (!select || !select.value) { return; }
        addButton.disabled = true;
        say(memberStatus, 'Adding…');
        post('/prototype/api/trainer/groups/' + encodeURIComponent(groupId)
             + '/members', { student_id: select.value })
          .then(function (result) {
            addButton.disabled = false;
            if (!result.ok) {
              say(memberStatus,
                  errorText(result, 'That student could not be added.'));
              return;
            }
            window.location.reload();
          }).catch(function () {
            addButton.disabled = false;
            say(memberStatus, 'Could not reach the server.');
          });
      });
    }

    Array.prototype.forEach.call(
      document.querySelectorAll('.pw-member-remove'), function (button) {
        button.addEventListener('click', function () {
          button.disabled = true;
          post('/prototype/api/trainer/groups/' + encodeURIComponent(groupId)
               + '/members/remove',
               { student_id: button.getAttribute('data-student-id') })
            .then(function (result) {
              button.disabled = false;
              if (!result.ok) {
                say(memberStatus,
                    errorText(result, 'That membership could not be removed.'));
                return;
              }
              window.location.reload();
            }).catch(function () {
              button.disabled = false;
              say(memberStatus, 'Could not reach the server.');
            });
        });
      });
  }

  // =======================================================================
  // Assessments: create and assign
  // =======================================================================

  var kindSelect = qs('#pw-assign-kind');
  if (!kindSelect) { return; }

  var assessmentSelect = qs('#pw-assign-assessment');
  var studentSelect = qs('#pw-assign-student');
  var groupSelect = qs('#pw-assign-group');
  var studentField = qs('#pw-assign-student-field');
  var groupField = qs('#pw-assign-group-field');
  var status = qs('#pw-assign-status');
  var assignButton = qs('#pw-assign-btn');

  var scrim = qs('#pw-dup-scrim');
  var dupLead = qs('#pw-dup-lead');
  var dupSources = qs('#pw-dup-sources');
  var dupCancel = qs('#pw-dup-cancel');
  var dupConfirm = qs('#pw-dup-confirm');

  var log = qs('#pw-assign-log');
  var logList = qs('#pw-assign-loglist');

  var pending = null;
  var returnFocus = null;

  function selectedText(select) {
    return select.options[select.selectedIndex].textContent.trim();
  }

  function updateKind() {
    var group = kindSelect.value === 'group';
    studentField.hidden = group;
    groupField.hidden = !group;
  }

  kindSelect.addEventListener('change', updateKind);
  updateKind();

  function appendLog(text) {
    log.hidden = false;
    var item = document.createElement('li');
    item.textContent = text;
    logList.appendChild(item);
  }

  function currentTarget() {
    if (kindSelect.value === 'group') {
      return { type: 'group', id: groupSelect.value,
               label: selectedText(groupSelect) };
    }
    return { type: 'student', id: studentSelect.value,
             label: selectedText(studentSelect) };
  }

  // -- duplicate dialog ----------------------------------------------------

  function openDialog(duplicates, target, requestId) {
    pending = { duplicates: duplicates, target: target,
                requestId: requestId };
    returnFocus = document.activeElement;

    var names = duplicates.map(function (entry) {
      return entry.student.name;
    }).join(', ');
    dupLead.textContent = names + ' already receive“' +
      selectedText(assessmentSelect) + '”. Assigning it again will not '
      + 'replace the route they already have.';

    dupSources.innerHTML = duplicates.map(function (entry) {
      var rows = entry.sources.map(function (source) {
        return '<li>' + esc(source.label)
          + (source.created ? ' — created ' + esc(source.created) : '')
          + (source.created_by ? ' by ' + esc(source.created_by) : '')
          + ' <span class="pw-muted">(' + esc(source.assignment_id)
          + ')</span></li>';
      }).join('');
      return '<li><b>' + esc(entry.student.name) + '</b><ul>' + rows
        + '</ul></li>';
    }).join('');

    scrim.hidden = false;
    dupConfirm.focus();
  }

  function closeDialog() {
    scrim.hidden = true;
    pending = null;
    if (returnFocus && document.contains(returnFocus)) { returnFocus.focus(); }
    returnFocus = null;
  }

  dupCancel.addEventListener('click', function () {
    say(status, 'Cancelled. Nothing was changed.');
    closeDialog();
  });

  dupConfirm.addEventListener('click', function () {
    var payload = pending;
    closeDialog();
    if (!payload) { return; }
    submitAssignment(payload.target, true, payload.requestId);
  });

  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape' && !scrim.hidden) { closeDialog(); }
  });

  // Keep focus inside the dialog while it is open.
  document.addEventListener('keydown', function (event) {
    if (event.key !== 'Tab' || scrim.hidden) { return; }
    var focusables = scrim.querySelectorAll('button');
    if (!focusables.length) { return; }
    var first = focusables[0];
    var last = focusables[focusables.length - 1];
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault(); last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault(); first.focus();
    }
  });

  // -- assign ---------------------------------------------------------------

  function submitAssignment(target, confirmDuplicate, requestId) {
    assignButton.disabled = true;
    say(status, confirmDuplicate ? 'Assigning again…' : 'Assigning…');
    post('/prototype/api/trainer/assignments', {
      assessment_id: assessmentSelect.value,
      target_type: target.type,
      target_id: target.id,
      confirm_duplicate: !!confirmDuplicate,
      request_id: requestId
    }).then(function (result) {
      assignButton.disabled = false;

      if (result.status === 409 && result.data.error
          && result.data.error.code === 'duplicate_assignment') {
        say(status, 'Already assigned to at least one of these learners. '
            + 'Confirm whether to assign again.');
        openDialog(result.data.error.detail.duplicates, target, requestId);
        return;
      }
      if (!result.ok) {
        say(status, errorText(result, 'That assignment could not be made.'));
        return;
      }

      var assignment = result.data.assignment;
      if (result.data.replayed) {
        say(status, 'Already recorded — this was the same request, not a '
            + 'second assignment.');
        return;
      }
      appendLog('“' + selectedText(assessmentSelect) + '” assigned to '
        + target.label + ' (' + assignment.source + ', '
        + assignment.id + ')'
        + (assignment.confirmed_duplicate
            ? ' — kept separately from the existing route.' : '.'));
      say(status, 'Assigned to ' + target.label
          + (assignment.confirmed_duplicate
              ? '. Both routes are preserved on their record.'
              : '.'));
      // The table above is server-rendered; reload so the new provenance is
      // read back from storage rather than drawn from this response.
      window.setTimeout(function () { window.location.reload(); }, 900);
    }).catch(function () {
      assignButton.disabled = false;
      say(status, 'Could not reach the server.');
    });
  }

  assignButton.addEventListener('click', function () {
    submitAssignment(currentTarget(), false, newRequestId());
  });

  // -- create ---------------------------------------------------------------

  var createButton = qs('#pw-new-btn');
  if (createButton) {
    var focusField = qs('#pw-new-focus');
    var interactionField = qs('#pw-new-interactions');
    var capacityHint = qs('#pw-new-capacity');

    function selectedCapacity() {
      var option = focusField.options[focusField.selectedIndex];
      return Number(option && option.getAttribute('data-capacity')) || 1;
    }

    function syncCapacity() {
      var capacity = selectedCapacity();
      var interactions = Number(interactionField.value);
      interactionField.max = String(capacity);
      capacityHint.textContent = selectedText(focusField) + ' supports 1–'
        + capacity + ' scored interactions under the current versioned '
        + 'runtime policy. Benign traffic is never counted.';
      var valid = Number.isInteger(interactions)
        && interactions >= 1 && interactions <= capacity;
      interactionField.setCustomValidity(valid ? ''
        : 'Choose a whole number from 1 to ' + capacity + ' for this focus.');
      createButton.disabled = !valid;
    }

    focusField.addEventListener('change', syncCapacity);
    interactionField.addEventListener('input', syncCapacity);
    syncCapacity();

    createButton.addEventListener('click', function () {
      var newStatus = qs('#pw-new-status-msg');
      var name = qs('#pw-new-name').value.trim();
      var interactions = Number(interactionField.value);
      var capacity = selectedCapacity();

      if (!name) {
        say(newStatus, 'Give the assessment a name first.');
        qs('#pw-new-name').focus();
        return;
      }
      if (!Number.isInteger(interactions) || interactions < 1
          || interactions > capacity) {
        say(newStatus, 'Required scored interactions must be a whole number '
          + 'from 1 to ' + capacity + ' for this focus.');
        interactionField.focus();
        return;
      }

      createButton.disabled = true;
      say(newStatus, 'Saving…');
      post('/prototype/api/trainer/assessments', {
        name: name,
        focus: focusField.value,
        required_interactions: interactions,
        max_attempts: Number(qs('#pw-new-attempts').value) || 1,
        status: qs('#pw-new-status').value,
        window_label: qs('#pw-new-window').value.trim() || null
      }).then(function (result) {
        createButton.disabled = false;
        if (!result.ok) {
          say(newStatus,
              errorText(result, 'That assessment could not be saved.'));
          return;
        }
        window.location.reload();
      }).catch(function () {
        createButton.disabled = false;
        say(newStatus, 'Could not reach the server.');
      });
    });
  }

  // Exposed for the console's own smoke checks. Reads only.
  window.rewindsecTrainer = {
    assignmentSources: function (assessmentId, studentId) {
      return get('/prototype/api/trainer/assignment-sources?assessment_id='
        + encodeURIComponent(assessmentId) + '&student_id='
        + encodeURIComponent(studentId));
    }
  };
}());
