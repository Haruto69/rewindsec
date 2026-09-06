"""Safe, high-level archetypes built from normalized features.

Architecture Spec v1.1 (Batch 4) S42: archetypes are feature templates, never
copies of real messages. Each archetype here names its normalized feature
source and a small set of authored template *slots* that
:mod:`rewindsec.content.generate` fills in deterministically per session --
the archetype itself carries no organisation names, no employee names, no
specific numbers. Those come from :mod:`rewindsec.content.bind`.
"""

from rewindsec.content.normalize import (normalize_document_feature,
                                         normalize_mail_feature,
                                         normalize_mfa_feature)

__all__ = ["DOCUMENT_ARCHETYPES", "MAIL_ARCHETYPES", "MFA_ARCHETYPES"]

# ---------------------------------------------------------------------------
# Document archetypes
# ---------------------------------------------------------------------------
#
# Each maps directly onto one of the presentation kinds
# ``rewindsec.content.schema.SyntheticDocument`` supports. ``slots`` names
# the binding-time placeholders a generator will fill from the fictional
# organisation (see ``rewindsec.content.bind``) -- never from anything
# resembling a real company.

DOCUMENT_ARCHETYPES = {
    "arche-doc-memo": normalize_document_feature(
        "src-document-archetypes-v1",
        document_kind="memo", operational_context="internal_communication",
        sensitivity="routine"),
    "arche-doc-invoice": normalize_document_feature(
        "src-document-archetypes-v1",
        document_kind="invoice", operational_context="accounts_payable",
        sensitivity="financial"),
    "arche-doc-report": normalize_document_feature(
        "src-document-archetypes-v1",
        document_kind="report", operational_context="operations_review",
        sensitivity="routine"),
    "arche-doc-spreadsheet": normalize_document_feature(
        "src-document-archetypes-v1",
        document_kind="spreadsheet", operational_context="workforce_planning",
        sensitivity="internal"),
    "arche-doc-policy": normalize_document_feature(
        "src-document-archetypes-v1",
        document_kind="pdf_page", operational_context="it_operations",
        sensitivity="routine"),
}

# ---------------------------------------------------------------------------
# Mail archetypes
# ---------------------------------------------------------------------------
#
# Reserved for future runtime candidate generation (Architecture Spec v1.1
# S46). Not wired into the training engine's candidate catalogue in this
# batch -- see the Batch 4 completion report's scope note -- but implemented
# and tested end to end so that doing so is additive, not a redesign.

MAIL_ARCHETYPES = {
    "arche-mail-payroll-login-lure": normalize_mail_feature(
        "src-mail-archetypes-v1", communication_purpose="credential_harvest",
        sender_role="hr_system", urgency="high", requested_action_type="sign_in",
        link_present=True, attachment_present=False,
        identity_mismatch_archetype="lookalike_domain"),
    "arche-mail-invoice-account-change": normalize_mail_feature(
        "src-mail-archetypes-v1", communication_purpose="payment_redirect",
        sender_role="external_supplier", urgency="medium",
        requested_action_type="update_payment_details", link_present=False,
        attachment_present=False, financial_change_archetype="account_of_record"),
    "arche-mail-supplier-followup": normalize_mail_feature(
        "src-mail-archetypes-v1", communication_purpose="routine_followup",
        sender_role="external_supplier", urgency="low",
        requested_action_type="acknowledge", link_present=False,
        attachment_present=False),
    "arche-mail-legitimate-payroll-notice": normalize_mail_feature(
        "src-mail-archetypes-v1", communication_purpose="informational",
        sender_role="hr_system", urgency="low", requested_action_type="none",
        link_present=False, attachment_present=True),
    "arche-mail-legitimate-vpn-reauth": normalize_mail_feature(
        "src-mail-archetypes-v1", communication_purpose="informational",
        sender_role="it_system", urgency="low", requested_action_type="none",
        link_present=False, attachment_present=False),
    "arche-mail-ordinary-team-update": normalize_mail_feature(
        "src-mail-archetypes-v1", communication_purpose="team_coordination",
        sender_role="colleague", urgency="low", requested_action_type="none",
        link_present=False, attachment_present=False),
    "arche-mail-document-review-request": normalize_mail_feature(
        "src-mail-archetypes-v1", communication_purpose="review_request",
        sender_role="colleague", urgency="medium",
        requested_action_type="review_document", link_present=False,
        attachment_present=True),
    "arche-mail-ransomware-attachment-lure": normalize_mail_feature(
        "src-mail-archetypes-v1", communication_purpose="malware_delivery",
        sender_role="external_supplier", urgency="medium",
        requested_action_type="open_attachment", link_present=False,
        attachment_present=True),
    "arche-mail-browser-download-lure": normalize_mail_feature(
        "src-mail-archetypes-v1", communication_purpose="malware_delivery",
        sender_role="internal_notice", urgency="low",
        requested_action_type="download", link_present=True,
        attachment_present=False),
}

# ---------------------------------------------------------------------------
# MFA archetypes
# ---------------------------------------------------------------------------

MFA_ARCHETYPES = {
    "arche-mfa-fatigue-unsolicited": normalize_mfa_feature(
        "src-mfa-archetypes-v1", app_context="authenticator", expected=False,
        device_class="unrecognised", location_class="unexpected_region"),
    "arche-mfa-legitimate-reauth": normalize_mfa_feature(
        "src-mfa-archetypes-v1", app_context="vpn", expected=True,
        device_class="own_device", location_class="usual"),
}
