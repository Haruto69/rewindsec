"""The runtime document catalogue: what the pipeline actually produced.

Built once, at import time, by running every document through the full
pipeline -- provenance -> sanitize -> normalize (already done, in
:mod:`rewindsec.content.archetypes`) -> generate -> bind -> here. Nothing in
this module reads a raw external row: every document below traces to an
archetype in :mod:`rewindsec.content.archetypes`, which traces to a
provenance record in :mod:`rewindsec.content.provenance`.

Why these documents are static rather than session-randomized
---------------------------------------------------------------
These particular documents are bound to *fixed* authored files and mail
attachments that the rest of the product (mail bodies, the vendor payment
policy preview, the BEC narrative) already references by specific detail --
the invoice's account of record, for one, is quoted verbatim in
:data:`rewindsec.workstation.content.world.MAIL` and has to match here
exactly, in every session, or the BEC scenario stops making sense. So this
catalogue is generated once, deterministically, from a fixed non-session
stream (:data:`_CATALOG_SEED`) rather than per-session -- the *mechanism* in
:mod:`rewindsec.content.generate` is genuinely session-stream-shaped and
tested as such; these documents simply do not need session-level variety.
See the Batch 4 completion report for the full scope note.
"""

from rewindsec.content import bind
from rewindsec.content.archetypes import DOCUMENT_ARCHETYPES
from rewindsec.content.generate import derive_content_id
from rewindsec.content.schema import (SyntheticDocument, doc_list, heading,
                                      key_value, paragraph, table)

__all__ = ["DOCUMENT_BY_ID", "all_documents"]

#: A fixed, non-session identity this catalogue's own content is generated
#: under. Not a simulation session id -- it never reaches
#: ``rewindsec.core.rng.SeededRandom`` -- but it plays the same structural
#: role: every id below is derived from ``(this identity, archetype, seq)``,
#: never from ``hash()``, so the catalogue is stable across processes.
_CATALOG_SEED = "rewindsec2-content-catalog/v1"


def _doc_id(archetype_id, seq):
    return derive_content_id(_CATALOG_SEED, archetype_id, seq)


def _build_catalog():
    org = bind.organization()
    learner = bind.learner()
    v = bind.vendor()
    finance = bind.employee_by_role("finance")
    docs = {}

    # -- Ops review agenda (memo) --------------------------------------------
    doc = SyntheticDocument(
        document_id=_doc_id("arche-doc-memo", 0),
        title="Q3 Operations Review — Agenda",
        kind="memo",
        blocks=[
            heading("Q3 Operations Review", level=1),
            key_value([("Organized by", "Marcus Hale"),
                      ("Attendees", "Operations, Finance, %s" % learner["given_name"]),
                      ("Location", "Meeting Room 2")]),
            paragraph("Agenda for Tuesday's review. Bring the revised "
                     "headcount model rather than the July version."),
            doc_list([
                "09:00 — Welcome and minutes of the last review",
                "09:10 — Throughput and staffing (10 minutes)",
                "09:20 — Facilities contract renewal status",
                "09:35 — Q3 metrics walkthrough",
                "09:50 — AOB",
            ]),
        ],
        provenance_id="src-document-archetypes-v1")
    docs[doc.document_id] = doc
    ops_agenda_id = doc.document_id

    # -- Personal review notes (a separate, shorter memo) --------------------
    doc = SyntheticDocument(
        document_id=_doc_id("arche-doc-memo", 1),
        title="Ops Review — My Notes",
        kind="memo",
        blocks=[
            heading("Notes for Tuesday", level=2),
            doc_list([
                "Bring the revised headcount model, not the July one",
                "Ask Marcus about the facilities contract renewal date",
                "Ten minutes on throughput — keep it tight",
            ]),
        ],
        provenance_id="src-document-archetypes-v1")
    docs[doc.document_id] = doc
    ops_notes_id = doc.document_id

    # -- Headcount model (spreadsheet-like table) ---------------------------
    doc = SyntheticDocument(
        document_id=_doc_id("arche-doc-spreadsheet", 0),
        title="Headcount Model",
        kind="spreadsheet",
        blocks=[
            heading("Headcount Model — Draft", level=1),
            table(
                headers=["Department", "Current", "Approved", "Requested"],
                rows=[
                    ["Operations", "18", "18", "20"],
                    ["Finance", "6", "6", "6"],
                    ["Facilities", "4", "5", "5"],
                ]),
            paragraph("Requested headcount reflects the contractor uplift "
                     "discussed with Marcus for Q4."),
        ],
        provenance_id="src-document-archetypes-v1")
    docs[doc.document_id] = doc
    headcount_id = doc.document_id

    # -- Vendor payment process (policy pdf) ---------------------------------
    doc = SyntheticDocument(
        document_id=_doc_id("arche-doc-policy", 0),
        title="Vendor Payment Process",
        kind="pdf_page",
        blocks=[
            heading("Vendor Payment Process — rev 4", level=1),
            paragraph("%s, accounts payable policy." % org["name"]),
            heading("3.2 Changing a settlement account", level=2),
            paragraph("A change to a supplier's settlement account is "
                     "accepted only after a call-back to the telephone "
                     "number held in the supplier's Directory record. "
                     "Confirmation by reply, by a number supplied in the "
                     "request, or by any other channel offered by the "
                     "requester is not sufficient."),
            heading("3.3 Separation of duties", level=2),
            paragraph("The person who confirms the change may not be the "
                     "person who releases the payment."),
        ],
        provenance_id="src-document-archetypes-v1")
    docs[doc.document_id] = doc
    policy_id = doc.document_id

    # -- Invoice CF-20411 (the account-of-record evidence) -------------------
    vendor_name = v["name"] if v else "Calderwood Facilities Ltd"
    doc = SyntheticDocument(
        document_id=_doc_id("arche-doc-invoice", 0),
        title="Invoice CF-20411",
        kind="invoice",
        blocks=[
            heading("Invoice CF-20411", level=1),
            key_value([
                ("Supplier", vendor_name),
                ("Bill to", org["name"]),
                ("Amount", "GBP 4180.00"),
                ("Terms", "30 days"),
                ("Settlement account", "Nordvale Bank, account ending 4417"),
                ("Approved by", finance["name"] if finance else "Arjun Rao"),
            ]),
            paragraph("August cleaning and grounds contract, as agreed."),
        ],
        provenance_id="src-document-archetypes-v1")
    docs[doc.document_id] = doc
    invoice_id = doc.document_id

    # -- Team handbook (report) ----------------------------------------------
    doc = SyntheticDocument(
        document_id=_doc_id("arche-doc-report", 0),
        title="Team Handbook",
        kind="report",
        blocks=[
            heading("%s — Team Handbook" % org["short_name"], level=1),
            paragraph("General reference for day-to-day working practice."),
            doc_list([
                "Core hours and flexible working",
                "Expense claims and approval limits",
                "Remote access and the reconnection guide",
                "Reporting a security concern",
            ]),
        ],
        provenance_id="src-document-archetypes-v1")
    docs[doc.document_id] = doc
    handbook_id = doc.document_id

    # -- Remote access / reconnection guide ----------------------------------
    doc = SyntheticDocument(
        document_id=_doc_id("arche-doc-policy", 1),
        title="Remote Access Guide",
        kind="pdf_page",
        blocks=[
            heading("Reconnecting after maintenance", level=1),
            paragraph("If your workstation has been taken off the network, "
                     "reconnect from the Service Desk panel once any "
                     "containment steps are complete."),
            doc_list([
                "Confirm with the Service Desk that containment is finished",
                "Reconnect from the workstation's network control",
                "Sign in again if remote access was interrupted",
            ]),
        ],
        provenance_id="src-document-archetypes-v1")
    docs[doc.document_id] = doc
    access_guide_id = doc.document_id

    # -- Facilities update draft (Batch 4: reaches the learner via mail, not
    #    only Files -- the first document the runtime pipeline delivers as a
    #    mail attachment beyond the original invoice) ------------------------
    doc = SyntheticDocument(
        document_id=_doc_id("arche-doc-memo", 2),
        title="Facilities Update — Draft",
        kind="memo",
        blocks=[
            heading("What's changing", level=1),
            paragraph("Draft wording for the all-staff note about the "
                     "Thursday lift inspection and the temporary changes to "
                     "the ground-floor entrance while it runs."),
            doc_list([
                "Lift 2 out of service 07:00-11:00 Thursday",
                "Use the north stairwell or Lift 1",
                "Ground-floor entrance barrier moves to the side door",
            ]),
            paragraph("Let me know if anything here reads wrong before it "
                     "goes out to the wider team."),
        ],
        provenance_id="src-document-archetypes-v1")
    docs[doc.document_id] = doc
    facilities_update_id = doc.document_id

    return docs, {
        "f-ops-notes": ops_notes_id,
        "f-agenda": ops_agenda_id,
        "f-headcount-model": headcount_id,
        "f-vendor-process": policy_id,
        "f-invoice": invoice_id,
        "f-handbook": handbook_id,
        "_access_guide": access_guide_id,
        "_facilities_update_memo": facilities_update_id,
    }


DOCUMENT_BY_ID, _STATIC_BINDINGS = _build_catalog()


def all_documents():
    return tuple(DOCUMENT_BY_ID[key] for key in sorted(DOCUMENT_BY_ID))
