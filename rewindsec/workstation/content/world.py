"""Authored synthetic workplace content for the RewindSec 2.0 UI prototype.

Everything in this module is invented. The organisation, its people, its
vendors, its domains, its mail, its files and its authentication history exist
only here. No record is derived from a dataset, a real mailbox, a real person
or a real incident, and every host name ends in ``.example`` -- a reserved TLD
that cannot resolve -- so nothing here can reach the network even by accident.

Two vocabularies live side by side in these records and must not be confused:

``surface`` fields
    Everything the learner can see inside the workstation: subjects, bodies,
    sender names and addresses, file names, notification text, chat lines,
    directory rows, browser pages. These are ordinary workplace language. A
    hostile message must read exactly like a real one -- it carries no
    ``PHISHING``/``BEC``/``RANSOMWARE``/``MALICIOUS``/``THREAT`` label, no
    warning colour and no training vocabulary of any kind.

``analysis`` blocks
    The authored ground truth used *outside* the workstation surface -- by the
    post-hoc comparison screen, the results debrief and the prototype
    developer panel. Family names and dispositions live here and only here.
    ``tests/test_prototype_ui.py`` holds that line mechanically.
"""

# ---------------------------------------------------------------------------
# Organisation
# ---------------------------------------------------------------------------

ORGANIZATION = {
    "name": "Northbridge Systems",
    "short_name": "Northbridge",
    "domain": "northbridge.example",
    "sites": ["Bengaluru", "Manchester"],
    "workstation_id": "NB-LT-4471",
    "known_hosts": {
        "intranet": "intranet.northbridge.example",
        "payroll": "payroll.northbridge.example",
        "vpn": "access.northbridge.example",
        "files": "files.northbridge.example",
    },
    "processes": [
        "Vendor bank details change only after a call-back to the number held "
        "in the Directory record.",
        "Payroll never asks for a password outside payroll.northbridge.example.",
        "Anything you are unsure about goes to the Service Desk on extension "
        "2200.",
    ],
}

LEARNER = {
    "id": "stu-aarti-venkatesh",
    "name": "Aarti Venkatesh",
    "given_name": "Aarti",
    "initials": "AV",
    "role": "Operations Analyst",
    "department": "Operations",
    "email": "aarti.venkatesh@northbridge.example",
    "manager": "Marcus Hale",
    "employee_ref": "NB-4471",
    "joined": "March 2025",
}

# ---------------------------------------------------------------------------
# People and the trusted directory
# ---------------------------------------------------------------------------

DIRECTORY = [
    {
        "id": "dir-marcus-hale",
        "name": "Marcus Hale",
        "initials": "MH",
        "role": "Operations Lead",
        "department": "Operations",
        "email": "marcus.hale@northbridge.example",
        "extension": "2104",
        "location": "Bengaluru · Floor 3",
        "relationship": "Your manager",
        "kind": "employee",
        "channels": ["Messages", "Extension 2104"],
        "callback": "Marcus confirms the headcount request is his and asks "
                    "again for the number before Friday.",
    },
    {
        "id": "dir-priya-menon",
        "name": "Priya Menon",
        "initials": "PM",
        "role": "Payroll Coordinator",
        "department": "People Operations",
        "email": "priya.menon@northbridge.example",
        "extension": "2318",
        "location": "Bengaluru · Floor 2",
        "relationship": "Payroll contact",
        "kind": "employee",
        "channels": ["payroll@northbridge.example", "Extension 2318"],
        "note": "Payroll correspondence comes from payroll@northbridge.example "
                "and links only to payroll.northbridge.example.",
        "callback": "Priya picks up on the second ring. Nothing has gone out "
                    "from payroll today, and she says they would never ask "
                    "anyone to confirm a record by signing in from a link.",
    },
    {
        "id": "dir-arjun-rao",
        "name": "Arjun Rao",
        "initials": "AR",
        "role": "Head of Finance",
        "department": "Finance",
        "email": "arjun.rao@northbridge.example",
        "extension": "2201",
        "location": "Bengaluru · Floor 4",
        "relationship": "Approves supplier payments",
        "kind": "employee",
        "channels": ["Messages", "Extension 2201"],
        "callback": "Arjun is clear: he approved an amount, not a change of "
                    "account, and nothing should move until Facilities "
                    "confirm it on the number held on file.",
    },
    {
        "id": "dir-lena-fischer",
        "name": "Lena Fischer",
        "initials": "LF",
        "role": "Security Operations Analyst",
        "department": "Technology",
        "email": "lena.fischer@northbridge.example",
        "extension": "2277",
        "location": "Manchester · Floor 1",
        "relationship": "Handles reported messages",
        "kind": "employee",
        "channels": ["Messages", "security@northbridge.example"],
        "callback": "Lena takes the details and asks you to forward anything "
                    "you still have rather than act on it.",
    },
    {
        "id": "dir-daniel-okonkwo",
        "name": "Daniel Okonkwo",
        "initials": "DO",
        "role": "Service Desk Engineer",
        "department": "Technology",
        "email": "daniel.okonkwo@northbridge.example",
        "extension": "2200",
        "location": "Manchester · Floor 1",
        "relationship": "Service Desk",
        "kind": "employee",
        "channels": ["it.servicedesk@northbridge.example", "Extension 2200"],
        "callback": "Daniel takes the details. He confirms nobody at the "
                    "Service Desk has started a sign-in on your behalf, and "
                    "logs it.",
    },
    {
        "id": "dir-tom-brennan",
        "name": "Tom Brennan",
        "initials": "TB",
        "role": "Operations Analyst",
        "department": "Operations",
        "email": "tom.brennan@northbridge.example",
        "extension": "2119",
        "location": "Bengaluru · Floor 3",
        "relationship": "Works on the same reporting pack",
        "kind": "employee",
        "channels": ["Messages", "Extension 2119"],
    },
    {
        "id": "dir-sofia-lindqvist",
        "name": "Sofia Lindqvist",
        "initials": "SL",
        "role": "HR Business Partner",
        "department": "People Operations",
        "email": "sofia.lindqvist@northbridge.example",
        "extension": "2330",
        "location": "Manchester · Floor 2",
        "relationship": "HR contact for Operations",
        "kind": "employee",
        "channels": ["Messages", "Extension 2330"],
        "callback": "Sofia confirms Benefits has sent nothing this week, and "
                    "that enrolment confirmations are never done by signing "
                    "in from a mail link.",
    },
    {
        "id": "dir-ravi-krishnan",
        "name": "Ravi Krishnan",
        "initials": "RK",
        "role": "Project Manager",
        "department": "Operations",
        "email": "ravi.krishnan@northbridge.example",
        "extension": "2142",
        "location": "Bengaluru · Floor 3",
        "relationship": "Runs the Q3 review",
        "kind": "employee",
        "channels": ["Messages", "Extension 2142"],
    },
    {
        "id": "dir-kavya-shah",
        "name": "Kavya Shah",
        "initials": "KS",
        "role": "Chief Executive",
        "department": "Executive",
        "email": "kavya.shah@northbridge.example",
        "extension": "2001",
        "location": "Bengaluru · Floor 5",
        "relationship": "Executive",
        "kind": "employee",
        "channels": ["Executive Office, extension 2001"],
    },
    {
        "id": "dir-calderwood",
        "name": "Ines Duarte",
        "initials": "ID",
        "role": "Account Manager",
        "department": "Calderwood Facilities Ltd",
        "email": "ines.duarte@calderwood.example",
        "extension": "+44 20 7946 0318",
        "location": "Supplier · Manchester",
        "relationship": "Facilities supplier since 2023",
        "kind": "vendor",
        "channels": ["ines.duarte@calderwood.example", "+44 20 7946 0318"],
        "note": "Settlement account on file: Nordvale Bank, ending 4417. "
                "Changes are confirmed by calling the number in this record.",
        "callback": "Ines answers. Calderwood have not changed banks, nobody "
                    "there has written to you today, and the Nordvale account "
                    "is still the one to use.",
    },
    {
        "id": "dir-meridian",
        "name": "Gordon Whyte",
        "initials": "GW",
        "role": "Client Services",
        "department": "Meridian Print Services",
        "email": "gordon.whyte@meridianprint.example",
        "extension": "+44 161 496 0022",
        "location": "Supplier · Manchester",
        "relationship": "Print and stationery supplier",
        "kind": "vendor",
        "channels": ["gordon.whyte@meridianprint.example"],
        "note": "Settlement account on file: Bramwell Trust, ending 7729. "
                "Changes are confirmed by calling the number in this record.",
        "callback": "Gordon answers. Meridian have not changed banks, nobody "
                    "there has written to you today, and the Bramwell Trust "
                    "account is still the one to use.",
    },
]

# ---------------------------------------------------------------------------
# Mail
# ---------------------------------------------------------------------------
#
# ``surface`` = everything rendered inside the Mail app.
# ``analysis`` = authored ground truth, never rendered inside Mail.
#
# ``arrival`` is either "opening" (already in the mailbox when the session
# starts, i.e. the workplace history that makes later events fair) or
# "scheduled" (delivered during the session by the prototype's event timeline)
# or "consequence" (delivered only as the effect of a learner decision).

MAIL = [
    # -- opening mailbox: the workplace history ----------------------------
    {
        "id": "m-payslip-aug",
        "arrival": "opening",
        "folder": "inbox",
        "thread_id": "t-payroll",
        "unread": False,
        "received": "Mon 08:12",
        "order": 10,
        "surface": {
            "subject": "August payslip is available",
            "from_name": "Northbridge Payroll",
            "from_address": "payroll@northbridge.example",
            "reply_to": "priya.menon@northbridge.example",
            "to": "aarti.venkatesh@northbridge.example",
            "body": [
                "Hi Aarti,",
                "Your August payslip has been published. You can open it in the "
                "payroll portal with your usual single sign-on — there is "
                "nothing to download and nothing to confirm.",
                "If a figure looks wrong, reply to this message or call me on "
                "extension 2318 and I will pick it up.",
                "Priya Menon\nPayroll Coordinator, Northbridge Systems",
            ],
            "links": [
                {"text": "Open the payroll portal",
                 "href": "https://payroll.northbridge.example/payslips"},
            ],
            "attachments": [],
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "why": "Genuine payroll notice from the payroll sender of record, "
                   "linking to the payroll host of record.",
            "establishes_context": ["payroll_sender", "payroll_host"],
        },
    },
    {
        "id": "m-vendor-invoice",
        "arrival": "opening",
        "folder": "inbox",
        "thread_id": "t-calderwood",
        "unread": False,
        "received": "Tue 11:47",
        "order": 20,
        "surface": {
            "subject": "Calderwood Facilities — invoice CF-20411",
            "from_name": "Ines Duarte",
            "from_address": "ines.duarte@calderwood.example",
            "reply_to": None,
            "to": "aarti.venkatesh@northbridge.example",
            "cc": "arjun.rao@northbridge.example",
            "body": [
                "Hello Aarti,",
                "Invoice CF-20411 for the August cleaning and grounds contract "
                "is attached. Total is £4,180.00, payable on our usual "
                "30-day terms.",
                "Settlement account is unchanged: Nordvale Bank, sort code "
                "60-14-22, account ending 4417.",
                "Ines Duarte\nAccount Manager, Calderwood Facilities Ltd",
            ],
            "links": [],
            "attachments": [
                {"name": "Invoice_CF-20411.pdf", "size": "214 KB",
                 "kind": "pdf"},
            ],
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "why": "The real supplier thread. It is the record of the account "
                   "details a later request will try to change.",
            "establishes_context": ["vendor_contact", "vendor_account"],
        },
    },
    {
        # Batch 4 review correction: a second, distinct BEC surface -- a
        # different real vendor thread (Meridian, not Calderwood), so the
        # payment-redirection pretext is not limited to one supplier.
        "id": "m-meridian-invoice",
        "arrival": "opening",
        "folder": "inbox",
        "thread_id": "t-meridian",
        "unread": False,
        "received": "Mon 09:15",
        "order": 22,
        "surface": {
            "subject": "Meridian Print Services — invoice MP-7734",
            "from_name": "Gordon Whyte",
            "from_address": "gordon.whyte@meridianprint.example",
            "reply_to": None,
            "to": "aarti.venkatesh@northbridge.example",
            "cc": "arjun.rao@northbridge.example",
            "body": [
                "Hello Aarti,",
                "Invoice MP-7734 for the quarterly stationery order is "
                "attached. Total is £612.40, payable on our usual 30-day "
                "terms.",
                "Settlement account is unchanged: Bramwell Trust, account "
                "ending 7729.",
                "Gordon Whyte\nClient Services, Meridian Print Services",
            ],
            "links": [],
            "attachments": [
                {"name": "Invoice_MP-7734.pdf", "size": "98 KB", "kind": "pdf"},
            ],
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "why": "The real supplier thread. It is the record of the account "
                   "details a later request will try to change.",
            "establishes_context": ["meridian_contact", "meridian_account"],
        },
    },
    {
        "id": "m-vpn-maintenance",
        "arrival": "opening",
        "folder": "inbox",
        "thread_id": "t-it-maintenance",
        "unread": False,
        "received": "Wed 16:30",
        "order": 30,
        "surface": {
            "subject": "Scheduled maintenance: remote access gateway, Saturday "
                       "06:00–08:00",
            "from_name": "Northbridge Service Desk",
            "from_address": "it.servicedesk@northbridge.example",
            "reply_to": "daniel.okonkwo@northbridge.example",
            "to": "all-staff@northbridge.example",
            "body": [
                "The remote access gateway at access.northbridge.example will "
                "be unavailable on Saturday between 06:00 and 08:00 while we "
                "move it to the new cluster.",
                "Nothing changes for you afterwards. The address, the sign-in "
                "page and the approval prompt on your phone all stay the same.",
                "Daniel Okonkwo\nService Desk, extension 2200",
            ],
            "links": [
                {"text": "Maintenance calendar",
                 "href": "https://intranet.northbridge.example/it/maintenance"},
            ],
            "attachments": [],
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "why": "Routine IT notice. It is also where the VPN host of record "
                   "is stated.",
            "establishes_context": ["vpn_host", "servicedesk_contact"],
        },
    },
    {
        "id": "m-password-change",
        "arrival": "opening",
        "folder": "inbox",
        "thread_id": "t-account-notices",
        "unread": False,
        "received": "Wed 09:05",
        "order": 40,
        "surface": {
            "subject": "Your Northbridge password was changed",
            "from_name": "Northbridge Account Notices",
            "from_address": "no-reply@northbridge.example",
            "reply_to": None,
            "to": "aarti.venkatesh@northbridge.example",
            "body": [
                "Your account password was changed on Wednesday at 09:04 from "
                "NB-LT-4471 in Bengaluru.",
                "If that was you, nothing further is needed. If it was not, "
                "call the Service Desk on extension 2200.",
                "This mailbox is not monitored.",
            ],
            "links": [],
            "attachments": [],
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "why": "A genuine account notice that reads like a classic lure. "
                   "Present so the learner cannot pass by keyword alone.",
            "establishes_context": ["account_notice_sender"],
        },
    },
    {
        "id": "m-benefits",
        "arrival": "opening",
        "folder": "inbox",
        "thread_id": "t-benefits",
        "unread": True,
        "received": "Thu 10:22",
        "order": 50,
        "surface": {
            "subject": "Benefits enrolment closes on 19 September",
            "from_name": "Sofia Lindqvist",
            "from_address": "sofia.lindqvist@northbridge.example",
            "reply_to": None,
            "to": "operations-team@northbridge.example",
            "body": [
                "A reminder that the enrolment window for the 2026–27 "
                "benefits year closes on Friday 19 September.",
                "If you are not changing anything, you do not need to do "
                "anything — your current selections roll forward.",
                "Sofia Lindqvist\nHR Business Partner",
            ],
            "links": [
                {"text": "Benefits summary",
                 "href": "https://intranet.northbridge.example/people/benefits"},
            ],
            "attachments": [],
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "why": "Ordinary HR traffic.",
            "establishes_context": [],
        },
    },
    {
        "id": "m-shared-workbook",
        "arrival": "opening",
        "folder": "inbox",
        "thread_id": "t-q3-metrics",
        "unread": True,
        "received": "Thu 17:40",
        "order": 60,
        "surface": {
            "subject": "Q3 metrics workbook is in the shared folder",
            "from_name": "Tom Brennan",
            "from_address": "tom.brennan@northbridge.example",
            "reply_to": None,
            "to": "aarti.venkatesh@northbridge.example",
            "body": [
                "Aarti — I have put Q3_Metrics.xlsx in the shared folder. "
                "The regional splits are done, the headcount tab is still "
                "waiting on your numbers.",
                "No rush before Monday.",
                "Tom",
            ],
            "links": [
                {"text": "Shared folder",
                 "href": "https://files.northbridge.example/operations/shared"},
            ],
            "attachments": [],
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "why": "Establishes the shared file that a later file incident "
                   "makes unavailable.",
            "establishes_context": ["shared_workbook"],
        },
    },
    {
        "id": "m-room-change",
        "arrival": "opening",
        "folder": "inbox",
        "thread_id": "t-standup",
        "unread": True,
        "received": "08:41",
        "order": 70,
        "surface": {
            "subject": "Updated: Thursday stand-up moved to Meeting Room 2",
            "from_name": "Ravi Krishnan",
            "from_address": "ravi.krishnan@northbridge.example",
            "reply_to": None,
            "to": "operations-team@northbridge.example",
            "body": [
                "Room 5 is being recarpeted, so Thursday's stand-up is in "
                "Meeting Room 2 from this week. Same time.",
                "Calendar invites have been updated already.",
                "Ravi",
            ],
            "links": [],
            "attachments": [],
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "why": "Ordinary calendar traffic.",
            "establishes_context": [],
        },
    },
    {
        "id": "m-ops-agenda",
        "arrival": "opening",
        "folder": "inbox",
        "thread_id": "t-ops-review",
        "unread": True,
        "received": "08:55",
        "order": 80,
        "surface": {
            "subject": "Q3 operations review — agenda and pre-read",
            "from_name": "Marcus Hale",
            "from_address": "marcus.hale@northbridge.example",
            "reply_to": None,
            "to": "aarti.venkatesh@northbridge.example",
            "cc": "tom.brennan@northbridge.example",
            "body": [
                "Morning Aarti,",
                "Agenda for Tuesday attached. You have the throughput section "
                "— ten minutes, and please bring the revised headcount "
                "model rather than the July one.",
                "Marcus",
            ],
            "links": [],
            "attachments": [
                {"name": "Ops_Review_Agenda.pdf", "size": "96 KB",
                 "kind": "pdf"},
            ],
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "why": "Ordinary manager traffic with a genuine attachment.",
            "establishes_context": ["manager_contact"],
        },
    },

    # -- scheduled during the session --------------------------------------
    {
        "id": "m-travel-reimb",
        "arrival": "scheduled",
        "folder": "inbox",
        "thread_id": "t-expenses",
        "unread": True,
        "received": "09:14",
        "order": 90,
        "surface": {
            "subject": "Travel claim TR-8842 approved",
            "from_name": "Northbridge Finance",
            "from_address": "finance-notices@northbridge.example",
            "reply_to": "arjun.rao@northbridge.example",
            "to": "aarti.venkatesh@northbridge.example",
            "body": [
                "Claim TR-8842 (₹8,240) was approved on Friday and will "
                "be paid with September salary.",
                "Receipts are held for seven years; you do not need to keep "
                "the paper copies.",
            ],
            "links": [],
            "attachments": [],
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "why": "Ordinary finance traffic, and a distractor for the "
                   "payment-related events.",
            "establishes_context": [],
        },
    },
    {
        "id": "m-headcount",
        "arrival": "scheduled",
        "folder": "inbox",
        "thread_id": "t-headcount",
        "unread": True,
        "received": "09:21",
        "order": 100,
        "surface": {
            "subject": "Headcount numbers before Friday, please",
            "from_name": "Marcus Hale",
            "from_address": "marcus.hale@northbridge.example",
            "reply_to": None,
            "to": "aarti.venkatesh@northbridge.example",
            "body": [
                "Aarti — I need the confirmed contractor headcount for "
                "the Q3 pack before Friday close. Finance are waiting on it to "
                "sign off the review.",
                "The model is in your Documents folder. Just reply with the "
                "final number, no need for the whole workbook.",
                "Marcus",
            ],
            "links": [],
            "attachments": [],
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "requires_action": "reply",
            "why": "A genuine, slightly pressing manager request. It exists so "
                   "that reporting everything and ignoring everything both "
                   "have a visible cost.",
            "establishes_context": [],
        },
    },
    {
        "id": "m-payroll-restructure",
        "arrival": "scheduled",
        "folder": "inbox",
        "thread_id": "t-payroll-restructure",
        "unread": True,
        "received": "09:28",
        "order": 110,
        "surface": {
            "subject": "Salary structure revision — confirmation required",
            "from_name": "Northbridge Payroll",
            "from_address": "payroll@northbridge-payroll.example",
            "reply_to": "hr-review@nbsystems-secure.example",
            "to": "aarti.venkatesh@northbridge.example",
            "body": [
                "Dear Aarti Venkatesh,",
                "As part of the September pay-band review your salary record "
                "has been updated. Employees are asked to confirm their record "
                "before the payroll run closes at 17:00 today, otherwise the "
                "September payment may be held.",
                "Confirm your record using the employee portal below. You will "
                "need to sign in with your Northbridge account.",
                "Payroll Services\nNorthbridge Systems",
            ],
            "links": [
                {"text": "Confirm my employee record",
                 "href": "https://payroll-northbridge.example/employee/verify"},
            ],
            "attachments": [],
        },
        "analysis": {
            "disposition": "hostile",
            "family": "phishing",
            "why": "Credential-harvesting lure dressed as a payroll deadline.",
            "signals": [
                "The sending domain is northbridge-payroll.example. Payroll of "
                "record sends from northbridge.example.",
                "Reply-To points at nbsystems-secure.example, a third "
                "unrelated domain.",
                "The link host is payroll-northbridge.example, not the "
                "payroll.northbridge.example subdomain used in every previous "
                "payroll message.",
                "Payroll has never asked anyone to confirm a record by signing "
                "in from a mail link.",
            ],
            "evidence": [
                {"id": "ev-phish-sender", "label": "Sending domain",
                 "where": "Mail → message header",
                 "action": "inspect_headers:m-payroll-restructure"},
                {"id": "ev-phish-replyto", "label": "Reply-To domain",
                 "where": "Mail → message header",
                 "action": "inspect_headers:m-payroll-restructure"},
                {"id": "ev-phish-link", "label": "Link destination host",
                 "where": "Mail → link inspection",
                 "action": "inspect_link:m-payroll-restructure"},
                {"id": "ev-phish-history", "label": "Earlier genuine payroll "
                                                    "message",
                 "where": "Mail → search for 'payroll'",
                 "action": "search_mail:payroll"},
                {"id": "ev-phish-directory", "label": "Payroll contact of "
                                                      "record",
                 "where": "Directory → Priya Menon",
                 "action": "open_contact:dir-priya-menon"},
            ],
        },
    },
    {
        "id": "m-rate-card",
        "arrival": "scheduled",
        "folder": "inbox",
        "thread_id": "t-rate-card",
        "unread": True,
        "received": "09:33",
        "order": 120,
        "surface": {
            "subject": "Updated Q4 rate card — please review before "
                       "Thursday",
            "from_name": "Calderwood Accounts",
            "from_address": "accounts@calderwood-billing.example",
            "reply_to": "accounts@calderwood-billing.example",
            "to": "aarti.venkatesh@northbridge.example",
            "body": [
                "Hello,",
                "Please find the revised Q4 rate card attached ahead of "
                "Thursday's contract call. The macro sheet recalculates the "
                "grounds-maintenance lines automatically — enable content "
                "when it opens or the totals stay blank.",
                "Any queries, reply to this address.",
                "Calderwood Accounts Team",
            ],
            "links": [],
            "attachments": [
                {"name": "Calderwood_Rates_Q4.xlsm", "size": "1.4 MB",
                 "kind": "spreadsheet-macro"},
            ],
        },
        "analysis": {
            "disposition": "hostile",
            "family": "ransomware",
            "why": "Macro-bearing attachment from a look-alike supplier "
                   "domain, with a built-in reason to enable content.",
            "signals": [
                "The supplier of record is calderwood.example. This came from "
                "calderwood-billing.example.",
                "Ines Duarte is the named account manager on this contract; "
                "this arrives from an unnamed 'accounts team'.",
                "The message supplies a reason to enable macros before you "
                "have any reason to trust the file.",
                "Nothing on the Thursday contract call was expected by mail.",
            ],
            "evidence": [
                {"id": "ev-ransom-sender", "label": "Sending domain against "
                                                    "the supplier of record",
                 "where": "Mail → message header",
                 "action": "inspect_headers:m-rate-card"},
                {"id": "ev-ransom-thread", "label": "The genuine Calderwood "
                                                    "thread",
                 "where": "Mail → search for 'Calderwood'",
                 "action": "search_mail:calderwood"},
                {"id": "ev-ransom-directory", "label": "Supplier record and "
                                                       "call-back number",
                 "where": "Directory → Ines Duarte",
                 "action": "open_contact:dir-calderwood"},
                {"id": "ev-ransom-attachment", "label": "Attachment type",
                 "where": "Mail → attachment details",
                 "action": "inspect_attachment:m-rate-card"},
            ],
        },
    },
    {
        # Batch 4 review correction: a second, distinct ransomware lure --
        # an audit checklist pretext instead of a rate card, from a
        # look-alike compliance contact. Independent decisions
        # (d-ransom2-*), independent opportunity, same generic
        # file-availability consequence model as the rate-card lure.
        "id": "m-audit-checklist",
        "arrival": "scheduled",
        "folder": "inbox",
        "thread_id": "t-audit-checklist",
        "unread": True,
        "received": "09:37",
        "order": 125,
        "surface": {
            "subject": "Compliance self-audit checklist — due this week",
            "from_name": "Northbridge Compliance",
            "from_address": "compliance@northbridge-audits.example",
            "reply_to": "compliance@northbridge-audits.example",
            "to": "aarti.venkatesh@northbridge.example",
            "body": [
                "Hello,",
                "Please complete the attached self-audit checklist ahead of "
                "this quarter's review. The macro sheet totals your answers "
                "automatically — enable content when it opens or the totals "
                "stay blank.",
                "Any queries, reply to this address.",
                "Northbridge Compliance",
            ],
            "links": [],
            "attachments": [
                {"name": "Compliance_Checklist_Q3.xlsm", "size": "1.1 MB",
                 "kind": "spreadsheet-macro"},
            ],
        },
        "analysis": {
            "disposition": "hostile",
            "family": "ransomware",
            "why": "Macro-bearing attachment from a look-alike internal "
                   "domain, with a built-in reason to enable content -- the "
                   "same pattern as the rate-card lure, on a different "
                   "pretext.",
            "signals": [
                "Northbridge Compliance sends from northbridge.example. This "
                "came from northbridge-audits.example.",
                "The message supplies a reason to enable macros before there "
                "is any reason to trust the file.",
                "No self-audit checklist was flagged by the actual "
                "compliance calendar.",
            ],
            "evidence": [
                {"id": "ev-ransom2-sender", "label": "Sending domain",
                 "where": "Mail → message header",
                 "action": "inspect_headers:m-audit-checklist"},
                {"id": "ev-ransom2-attachment", "label": "Attachment type",
                 "where": "Mail → attachment details",
                 "action": "inspect_attachment:m-audit-checklist"},
            ],
        },
    },
    {
        # Batch 4 correction (content pipeline wiring): the audit-checklist
        # candidate's second, generated occurrence. Its subject, sender
        # persona and opening line are overridden at delivery time from the
        # ``content_variation`` stream (see
        # rewindsec.training.recurrence/rewindsec.training.delivery); the
        # values authored here are the fallback surface -- what a reader of
        # this file, or a test that never delivers this mail, actually sees.
        # Independent decisions (d-ransom3-*), independent opportunity, the
        # same generic file-availability consequence model every macro lure
        # in this catalogue already uses.
        "id": "m-audit-checklist-o2",
        "arrival": "scheduled",
        "folder": "inbox",
        "thread_id": "t-audit-checklist-o2",
        "unread": True,
        "received": "09:37",
        "order": 126,
        "surface": {
            "subject": "Reminder: compliance self-audit checklist still due",
            "from_name": "Northbridge Compliance",
            "from_address": "compliance@northbridge-audits.example",
            "reply_to": "compliance@northbridge-audits.example",
            "to": "aarti.venkatesh@northbridge.example",
            "body": [
                "Hello,",
                "Please complete the attached self-audit checklist ahead of "
                "this quarter's review. The macro sheet totals your answers "
                "automatically — enable content when it opens or the totals "
                "stay blank.",
                "Any queries, reply to this address.",
                "Northbridge Compliance",
            ],
            "links": [],
            "attachments": [
                {"name": "Compliance_Checklist_Q3_v2.xlsm", "size": "1.1 MB",
                 "kind": "spreadsheet-macro"},
            ],
        },
        "analysis": {
            "disposition": "hostile",
            "family": "ransomware",
            "why": "The same macro-bearing look-alike pretext as the first "
                   "audit-checklist message, resent -- a recurring lure, not "
                   "a new one.",
            "signals": [
                "Northbridge Compliance sends from northbridge.example. This "
                "came from northbridge-audits.example.",
                "The message supplies a reason to enable macros before there "
                "is any reason to trust the file.",
                "No self-audit checklist was flagged by the actual "
                "compliance calendar.",
            ],
            "evidence": [
                {"id": "ev-ransom3-sender", "label": "Sending domain",
                 "where": "Mail → message header",
                 "action": "inspect_headers:m-audit-checklist-o2"},
                {"id": "ev-ransom3-attachment", "label": "Attachment type",
                 "where": "Mail → attachment details",
                 "action": "inspect_attachment:m-audit-checklist-o2"},
            ],
        },
    },
    {
        "id": "m-invoice-amend",
        "arrival": "scheduled",
        "folder": "inbox",
        "thread_id": "t-calderwood",
        "unread": True,
        "received": "09:41",
        "order": 130,
        "surface": {
            "subject": "Re: Calderwood Facilities — invoice CF-20411",
            "from_name": "Ines Duarte",
            "from_address": "ines.duarte@calderwood-billing.example",
            "reply_to": "ines.duarte@calderwood-billing.example",
            "to": "aarti.venkatesh@northbridge.example",
            "body": [
                "Hi Aarti,",
                "Apologies for the second message on this. Our banking moved "
                "to a new provider on Monday and the account on CF-20411 is no "
                "longer live — anything sent there will bounce back and "
                "delay us another cycle.",
                "New settlement details: Aveley Trust Bank, sort code "
                "23-08-71, account ending 9032. Could you get it released "
                "today? Arjun signed off the amount last week, so it only "
                "needs the account updating on your side.",
                "Ines",
                "——— Original message ———\n"
                "Invoice CF-20411 for the August cleaning and grounds "
                "contract is attached. Total is £4,180.00…",
            ],
            "links": [],
            "attachments": [],
        },
        "analysis": {
            "disposition": "hostile",
            "family": "bec",
            "why": "Payment-redirection request that reuses a real thread, a "
                   "real amount and a real approver's name.",
            "signals": [
                "The address is ines.duarte@calderwood-billing.example. The "
                "thread it is quoting came from ines.duarte@calderwood.example.",
                "It asks for a bank account change by mail, which the vendor "
                "payment process does not allow.",
                "It borrows Arjun Rao's earlier approval to make a *new* "
                "instruction look already approved.",
                "The urgency is supplied by the sender, not by the contract.",
            ],
            "evidence": [
                {"id": "ev-bec-sender", "label": "Sender address against the "
                                                 "original thread",
                 "where": "Mail → message header",
                 "action": "inspect_headers:m-invoice-amend"},
                {"id": "ev-bec-original", "label": "Account details on the "
                                                   "original invoice",
                 "where": "Mail → the CF-20411 thread",
                 "action": "open_mail:m-vendor-invoice"},
                {"id": "ev-bec-directory", "label": "Supplier call-back number",
                 "where": "Directory → Ines Duarte",
                 "action": "open_contact:dir-calderwood"},
                {"id": "ev-bec-finance", "label": "Finance approver on the "
                                                  "known channel",
                 "where": "Messages → Arjun Rao",
                 "action": "open_conversation:conv-arjun-rao"},
            ],
        },
    },
    {
        # Batch 4 review correction: a second, distinct BEC surface -- a
        # different real vendor thread (Meridian), independent decisions
        # (d-bec2-*), independent opportunity. Same payment-redirection
        # pretext, different supplier and account, so this is not the same
        # opportunity re-fired.
        "id": "m-meridian-amend",
        "arrival": "scheduled",
        "folder": "inbox",
        "thread_id": "t-meridian",
        "unread": True,
        "received": "09:47",
        "order": 132,
        "surface": {
            "subject": "Re: Meridian Print Services — invoice MP-7734",
            "from_name": "Gordon Whyte",
            "from_address": "gordon.whyte@meridian-print-services.example",
            "reply_to": "gordon.whyte@meridian-print-services.example",
            "to": "aarti.venkatesh@northbridge.example",
            "body": [
                "Hi Aarti,",
                "One more thing on MP-7734 — we switched banking providers "
                "this week and the Bramwell Trust account is no longer live. "
                "Anything sent there will bounce and delay us a cycle.",
                "New settlement details: Corvane Bank, sort code 40-19-55, "
                "account ending 3384. Could you get it released today? Arjun "
                "signed off the amount last week, so it only needs the "
                "account updating on your side.",
                "Gordon",
                "——— Original message ———\n"
                "Invoice MP-7734 for the quarterly stationery order is "
                "attached. Total is £612.40…",
            ],
            "links": [],
            "attachments": [],
        },
        "analysis": {
            "disposition": "hostile",
            "family": "bec",
            "why": "Payment-redirection request that reuses a real thread, a "
                   "real amount and a real approver's name -- the same "
                   "pattern as the Calderwood request, on a different "
                   "supplier.",
            "signals": [
                "The address is gordon.whyte@meridian-print-services.example. "
                "The thread it is quoting came from "
                "gordon.whyte@meridianprint.example.",
                "It asks for a bank account change by mail, which the vendor "
                "payment process does not allow.",
                "It borrows Arjun Rao's earlier approval to make a *new* "
                "instruction look already approved.",
                "The urgency is supplied by the sender, not by the contract.",
            ],
            "evidence": [
                {"id": "ev-bec2-sender", "label": "Sender address against the "
                                                  "original thread",
                 "where": "Mail → message header",
                 "action": "inspect_headers:m-meridian-amend"},
                {"id": "ev-bec2-original", "label": "Account details on the "
                                                    "original invoice",
                 "where": "Mail → the MP-7734 thread",
                 "action": "open_mail:m-meridian-invoice"},
                {"id": "ev-bec2-directory", "label": "Supplier call-back number",
                 "where": "Directory → Gordon Whyte",
                 "action": "open_contact:dir-meridian"},
            ],
        },
    },
    {
        # Batch 4 correction (content pipeline wiring): the Meridian
        # candidate's second, generated occurrence -- a follow-up on the
        # *same* payment-redirection request. Subject, sender persona and
        # opening line are overridden at delivery time from the
        # ``content_variation`` stream; every financial fact below (vendor,
        # bank, sort code, account, amount) is byte-identical to the first
        # occurrence, deliberately -- this is one fraud followed up on
        # twice, never a second fabricated vendor. Independent decisions
        # (d-bec3-*), independent opportunity.
        "id": "m-meridian-amend-o2",
        "arrival": "scheduled",
        "folder": "inbox",
        "thread_id": "t-meridian-o2",
        "unread": True,
        "received": "09:47",
        "order": 133,
        "surface": {
            "subject": "Re: Meridian Print Services — invoice MP-7734 "
                      "(following up)",
            "from_name": "Gordon Whyte",
            "from_address": "gordon.whyte@meridian-print-services.example",
            "reply_to": "gordon.whyte@meridian-print-services.example",
            "to": "aarti.venkatesh@northbridge.example",
            "body": [
                "Hi Aarti,",
                "Checking in on this — were you able to get the account "
                "details updated on your side yet?",
                "New settlement details: Corvane Bank, sort code 40-19-55, "
                "account ending 3384. Arjun signed off the amount last "
                "week, so it only needs the account updating on your side.",
                "Gordon",
                "——— Original message ———\n"
                "Invoice MP-7734 for the quarterly stationery order is "
                "attached. Total is £612.40…",
            ],
            "links": [],
            "attachments": [],
        },
        "analysis": {
            "disposition": "hostile",
            "family": "bec",
            "why": "The same payment-redirection request as the first "
                   "Meridian message, followed up -- not a second, "
                   "independent supplier relationship.",
            "signals": [
                "The address is gordon.whyte@meridian-print-services.example. "
                "The thread it is quoting came from "
                "gordon.whyte@meridianprint.example.",
                "It asks for a bank account change by mail, which the vendor "
                "payment process does not allow.",
                "It repeats the earlier, already-suspicious account change "
                "rather than treating it as settled.",
            ],
            "evidence": [
                {"id": "ev-bec3-sender", "label": "Sender address against the "
                                                   "original thread",
                 "where": "Mail → message header",
                 "action": "inspect_headers:m-meridian-amend-o2"},
                {"id": "ev-bec3-original", "label": "Account details on the "
                                                     "original invoice",
                 "where": "Mail → the MP-7734 thread",
                 "action": "open_mail:m-meridian-invoice"},
                {"id": "ev-bec3-directory", "label": "Supplier call-back number",
                 "where": "Directory → Gordon Whyte",
                 "action": "open_contact:dir-meridian"},
            ],
        },
    },
    {
        "id": "m-newsletter",
        "arrival": "scheduled",
        "folder": "inbox",
        "thread_id": "t-newsletter",
        "unread": True,
        "received": "09:52",
        "order": 140,
        "surface": {
            "subject": "Northbridge Weekly — September, issue 3",
            "from_name": "Internal Communications",
            "from_address": "comms@northbridge.example",
            "reply_to": None,
            "to": "all-staff@northbridge.example",
            "body": [
                "In this issue: the Manchester floor plan changes, two new "
                "starters in Finance, and the cycle-to-work window reopening "
                "in October.",
                "The full issue is on the intranet.",
            ],
            "links": [
                {"text": "Read on the intranet",
                 "href": "https://intranet.northbridge.example/comms/weekly"},
            ],
            "attachments": [],
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "why": "Background traffic.",
            "establishes_context": [],
        },
    },

    # -- consequence mail ---------------------------------------------------
    {
        "id": "m-signin-alert",
        "arrival": "consequence",
        "folder": "inbox",
        "thread_id": "t-account-notices",
        "unread": True,
        "received": "+ later",
        "order": 200,
        "surface": {
            "subject": "New sign-in to your Northbridge account",
            "from_name": "Northbridge Account Notices",
            "from_address": "no-reply@northbridge.example",
            "reply_to": None,
            "to": "aarti.venkatesh@northbridge.example",
            "body": [
                "A new sign-in was recorded on your account.",
                "Device: unrecognised · Windows\nLocation: Frankfurt, DE\n"
                "Application: Northbridge Mail (web)",
                "If this was not you, call the Service Desk on extension 2200.",
                "This mailbox is not monitored.",
            ],
            "links": [],
            "attachments": [],
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "why": "A genuine system notice reporting the outcome of an "
                   "earlier decision.",
            "establishes_context": [],
        },
    },
    {
        "id": "m-security-followup",
        "arrival": "consequence",
        "folder": "archive",
        "thread_id": "t-security",
        "unread": True,
        "received": "+ later",
        "order": 210,
        "surface": {
            "subject": "Unusual activity on your mailbox",
            "from_name": "Lena Fischer",
            "from_address": "security@northbridge.example",
            "reply_to": "lena.fischer@northbridge.example",
            "to": "aarti.venkatesh@northbridge.example",
            "body": [
                "Aarti, we are seeing mail sent from your account that you do "
                "not appear to have written, and a new inbox rule we did not "
                "create.",
                "Please call extension 2277 before you send anything else.",
                "Lena Fischer\nSecurity Operations",
            ],
            "links": [],
            "attachments": [],
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "why": "Delivered into Archive rather than Inbox because a mailbox "
                   "rule created earlier in the chain moves it there. The "
                   "learner can still find it; it just does not arrive where "
                   "they are looking.",
            "establishes_context": [],
        },
    },

    # -- Batch 3 candidate material ---------------------------------------
    #
    # Four more messages, added because the training engine needs something to
    # choose *between*. Three of them are legitimate, and that is the point:
    # each threat family now has a genuine counterpart that arrives from the
    # same kind of sender, about the same kind of thing, and is separated from
    # the attack only by evidence the learner has to go and find. Without them
    # a focused session would be a corpus of nothing but attacks, and "report
    # everything" would be the correct strategy.
    #
    # All of it is authored synthetic content written for this repository. No
    # phishing corpus is ingested, nothing is derived from a real message, and
    # every address is under a reserved TLD. The dataset provenance and
    # sanitisation pipeline the architecture specifies is Batch 4's.
    {
        "id": "m-payroll-genuine",
        "arrival": "scheduled",
        "folder": "inbox",
        "thread_id": "t-payroll",
        "unread": True,
        "received": "+ later",
        "order": 120,
        "surface": {
            "subject": "Payslip access is moving to single sign-on",
            "from_name": "Northbridge Payroll",
            "from_address": "payroll@northbridge.example",
            "reply_to": "priya.menon@northbridge.example",
            "to": "all-staff@northbridge.example",
            "body": [
                "Hi all,",
                "From the end of the month the payroll portal will only "
                "accept single sign-on. You will not be asked to set a "
                "separate password, and payroll will never ask you to confirm "
                "your salary details by email.",
                "Nothing is required from you. If you cannot reach the portal "
                "after the change, call the Service Desk on 2200.",
                "Priya Menon\nPayroll Coordinator, Northbridge Systems",
            ],
            "links": [
                {"text": "Payroll portal",
                 "href": "https://payroll.northbridge.example/payslips"},
            ],
            "attachments": [],
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "why": "The phishing family's honest counterpart. Payroll sender "
                   "of record, payroll host of record, and it asks for "
                   "nothing -- which is the difference the learner has to "
                   "find, rather than a difference in tone.",
            "establishes_context": ["payroll_sender", "payroll_host"],
        },
    },
    {
        "id": "m-it-attachment",
        "arrival": "scheduled",
        "folder": "inbox",
        "thread_id": "t-it-maintenance",
        "unread": True,
        "received": "+ later",
        "order": 130,
        "surface": {
            "subject": "Remote access: short guide before the maintenance "
                       "window",
            "from_name": "IT Service Desk",
            "from_address": "it.servicedesk@northbridge.example",
            "reply_to": None,
            "to": "operations@northbridge.example",
            "body": [
                "Hello,",
                "Ahead of the gateway maintenance on Saturday, the two-page "
                "guide attached covers reconnecting afterwards. It is a PDF; "
                "there is nothing to enable and nothing to sign in to.",
                "Any problems, raise a ticket or call 2200.",
                "Northbridge IT Service Desk",
            ],
            "links": [],
            "attachments": [
                {"name": "Remote_Access_Guide.pdf", "size": "186 KB",
                 "kind": "pdf"},
            ],
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "why": "A genuine attachment from the service desk of record. The "
                   "ransomware family's counterpart: an attachment is not a "
                   "threat, while a macro-enabled workbook from an unfamiliar "
                   "billing domain is a question.",
            "establishes_context": ["servicedesk_contact"],
        },
    },
    {
        "id": "m-vendor-po-update",
        "arrival": "scheduled",
        "folder": "inbox",
        "thread_id": "t-calderwood",
        "unread": True,
        "received": "+ later",
        "order": 140,
        "surface": {
            "subject": "Calderwood Facilities - PO reference for CF-20411",
            "from_name": "Ines Duarte",
            "from_address": "ines.duarte@calderwood.example",
            "reply_to": None,
            "to": "aarti.venkatesh@northbridge.example",
            "cc": "arjun.rao@northbridge.example",
            "body": [
                "Hello Aarti,",
                "Your finance team asked us to quote the purchase order "
                "reference on future statements. For CF-20411 that is "
                "PO-NB-3391. Nothing else changes and no action is needed "
                "from you.",
                "Settlement details are as they have always been.",
                "Ines Duarte\nAccount Manager, Calderwood Facilities Ltd",
            ],
            "links": [],
            "attachments": [],
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "why": "The BEC family's counterpart: the real supplier, on the "
                   "real domain, in the real thread, explicitly changing "
                   "nothing about settlement. Reporting it is an "
                   "over-suspicious response to routine work.",
            "establishes_context": ["vendor_contact"],
        },
    },
    {
        "id": "m-facilities-notice",
        "arrival": "scheduled",
        "folder": "inbox",
        "thread_id": None,
        "unread": True,
        "received": "+ later",
        "order": 150,
        "surface": {
            "subject": "Lift 2 out of service Thursday morning",
            "from_name": "Northbridge Facilities",
            "from_address": "facilities@northbridge.example",
            "reply_to": None,
            "to": "all-staff@northbridge.example",
            "body": [
                "Lift 2 will be out of service from 07:00 until about 11:00 "
                "on Thursday for its annual inspection. Lift 1 and the north "
                "stairwell are unaffected.",
                "Northbridge Facilities",
            ],
            "links": [],
            "attachments": [],
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "why": "Ordinary workplace noise. It carries no decision, no "
                   "evidence and no consequence -- which is exactly why it "
                   "belongs here.",
            "establishes_context": [],
        },
    },
    {
        # Batch 4: the first mail candidate delivered through the runtime
        # content pipeline's document catalogue rather than only through
        # Files -- a colleague's review request, matching the previously
        # unwired "arche-mail-document-review-request" archetype (see
        # rewindsec.content.archetypes). Ordinary work with an attachment
        # worth actually reading, not a threat surface.
        "id": "m-facilities-followup",
        "arrival": "scheduled",
        "folder": "inbox",
        "thread_id": None,
        "unread": True,
        "received": "+ later",
        "order": 160,
        "surface": {
            "subject": "Quick look before it goes out?",
            "from_name": "Marcus Hale",
            "from_address": "marcus.hale@northbridge.example",
            "reply_to": "marcus.hale@northbridge.example",
            "to": "aarti.venkatesh@northbridge.example",
            "body": [
                "Could you look over the attached before it goes to the "
                "wider team? Nothing urgent, just want a second pair of eyes "
                "on the wording before Thursday.",
                "Marcus",
            ],
            "links": [],
            "attachments": [
                {"name": "Facilities_Update_Draft.pdf", "size": "96 KB",
                 "kind": "pdf"},
            ],
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "why": "A colleague's routine review request with an ordinary "
                   "attachment. No lure, no urgency manufactured by the "
                   "sender, no request to sign in or change anything.",
            "establishes_context": [],
        },
    },
    {
        # Batch 4 review correction: the second previously-unwired background
        # archetype ("arche-mail-ordinary-team-update") now live, so
        # ordinary workplace breadth is not carried by one candidate alone.
        "id": "m-standup-notes",
        "arrival": "scheduled",
        "folder": "inbox",
        "thread_id": None,
        "unread": True,
        "received": "+ later",
        "order": 155,
        "surface": {
            "subject": "Notes from this morning's stand-up",
            "from_name": "Ravi Krishnan",
            "from_address": "ravi.krishnan@northbridge.example",
            "reply_to": "ravi.krishnan@northbridge.example",
            "to": "aarti.venkatesh@northbridge.example",
            "body": [
                "Quick recap in case you missed stand-up: the Q3 review "
                "pre-read needs to be with Marcus by Friday, and Facilities "
                "confirmed Lift 2 is back Thursday afternoon.",
                "Nothing needed from you unless the pre-read isn't ready.",
                "Ravi",
            ],
            "links": [],
            "attachments": [],
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "why": "Ordinary team coordination. No decision, no evidence, no "
                   "consequence -- the second background surface alongside "
                   "the facilities follow-up.",
            "establishes_context": [],
        },
    },
    {
        # Batch 4 review correction: a second, distinct phishing surface --
        # a benefits/HR themed credential-harvest lure, matching the
        # reviewer's own example. Independent decisions (d-phish2-*),
        # independent opportunity, independent training candidate
        # (cand-phish-benefits-lure); converges on the same generic
        # "chain-credentials"/"chain-reported-hostile" consequence model the
        # original payroll lure already uses -- one safe synthetic account-
        # compromise outcome, not a second parallel one.
        "id": "m-benefits-verify",
        "arrival": "scheduled",
        "folder": "inbox",
        "thread_id": "t-benefits-verify",
        "unread": True,
        "received": "10:02",
        "order": 145,
        "surface": {
            "subject": "Benefits enrolment — confirm your selections",
            "from_name": "Northbridge Benefits",
            "from_address": "benefits@northbridge-benefits.example",
            "reply_to": "enrolment-support@nb-benefits-portal.example",
            "to": "aarti.venkatesh@northbridge.example",
            "body": [
                "Dear Aarti Venkatesh,",
                "Annual enrolment closes today. Our records show your "
                "benefits selections have not yet been confirmed for this "
                "cycle. Unconfirmed selections default to the minimum plan.",
                "Confirm your selections using the portal below. Sign in "
                "with your Northbridge account to continue.",
                "Northbridge Benefits",
            ],
            "links": [
                {"text": "Confirm my benefits selections",
                 "href": "https://benefits-northbridge.example/portal/verify"},
            ],
            "attachments": [],
        },
        "analysis": {
            "disposition": "hostile",
            "family": "phishing",
            "why": "Credential-harvesting lure dressed as a benefits "
                   "enrolment deadline -- the same pattern as the payroll "
                   "lure, on a different pretext.",
            "signals": [
                "The sending domain is northbridge-benefits.example. HR "
                "systems send from northbridge.example.",
                "Reply-To points at nb-benefits-portal.example, a third "
                "unrelated domain.",
                "The link host is benefits-northbridge.example, not a "
                "subdomain of northbridge.example.",
                "Benefits enrolment has never been confirmed by signing in "
                "from a mail link.",
            ],
            "evidence": [
                {"id": "ev-phish2-sender", "label": "Sending domain",
                 "where": "Mail → message header",
                 "action": "inspect_headers:m-benefits-verify"},
                {"id": "ev-phish2-replyto", "label": "Reply-To domain",
                 "where": "Mail → message header",
                 "action": "inspect_headers:m-benefits-verify"},
                {"id": "ev-phish2-link", "label": "Link destination host",
                 "where": "Mail → link inspection",
                 "action": "inspect_link:m-benefits-verify"},
                {"id": "ev-phish2-directory", "label": "HR contact of record",
                 "where": "Directory → Sofia Lindqvist",
                 "action": "open_contact:dir-sofia-lindqvist"},
            ],
        },
    },
    {
        # Batch 4 correction (content pipeline wiring): the benefits-lure
        # candidate's second, generated occurrence. Subject, sender persona
        # and opening line are overridden at delivery time from the
        # ``content_variation`` stream; the link and its destination host
        # are byte-identical to the first occurrence -- the same look-alike
        # portal, followed up on, not a second one. Independent decisions
        # (d-phish3-*), independent opportunity.
        "id": "m-benefits-verify-o2",
        "arrival": "scheduled",
        "folder": "inbox",
        "thread_id": "t-benefits-verify-o2",
        "unread": True,
        "received": "10:02",
        "order": 146,
        "surface": {
            "subject": "Reminder: your benefits selections are still "
                      "unconfirmed",
            "from_name": "Northbridge Benefits",
            "from_address": "benefits@northbridge-benefits.example",
            "reply_to": "enrolment-support@nb-benefits-portal.example",
            "to": "aarti.venkatesh@northbridge.example",
            "body": [
                "Dear Aarti Venkatesh,",
                "Following up on our earlier note — enrolment closes at the "
                "end of the day and your selections are still showing as "
                "unconfirmed.",
                "Confirm your selections using the portal below. Sign in "
                "with your Northbridge account to continue.",
                "Northbridge Benefits",
            ],
            "links": [
                {"text": "Confirm my benefits selections",
                 "href": "https://benefits-northbridge.example/portal/verify"},
            ],
            "attachments": [],
        },
        "analysis": {
            "disposition": "hostile",
            "family": "phishing",
            "why": "The same credential-harvesting lure as the first "
                   "benefits message, followed up -- not a second, "
                   "independent look-alike site.",
            "signals": [
                "The sending domain is northbridge-benefits.example. HR "
                "systems send from northbridge.example.",
                "Reply-To points at nb-benefits-portal.example, a third "
                "unrelated domain.",
                "The link host is benefits-northbridge.example, not a "
                "subdomain of northbridge.example.",
                "Benefits enrolment has never been confirmed by signing in "
                "from a mail link.",
            ],
            "evidence": [
                {"id": "ev-phish3-sender", "label": "Sending domain",
                 "where": "Mail → message header",
                 "action": "inspect_headers:m-benefits-verify-o2"},
                {"id": "ev-phish3-replyto", "label": "Reply-To domain",
                 "where": "Mail → message header",
                 "action": "inspect_headers:m-benefits-verify-o2"},
                {"id": "ev-phish3-link", "label": "Link destination host",
                 "where": "Mail → link inspection",
                 "action": "inspect_link:m-benefits-verify-o2"},
                {"id": "ev-phish3-directory", "label": "HR contact of record",
                 "where": "Directory → Sofia Lindqvist",
                 "action": "open_contact:dir-sofia-lindqvist"},
            ],
        },
    },
]

# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------
#
# Nothing here is a real file. These are rows in a synthetic explorer. No path
# is ever resolved, opened, written or executed; ``state`` is a label.

FILE_TREE = [
    {
        "id": "loc-desktop", "name": "Desktop", "kind": "location",
        "files": [
            {"id": "f-ops-notes", "name": "Ops_Review_Notes.docx",
             "kind": "document", "size": "48 KB", "modified": "Yesterday 17:22",
             "state": "normal"},
            {"id": "f-team-rota", "name": "Team_Rota_September.xlsx",
             "kind": "spreadsheet", "size": "112 KB",
             "modified": "Monday 09:40", "state": "normal"},
            {"id": "f-scratch", "name": "scratch.txt", "kind": "text",
             "size": "2 KB", "modified": "Today 08:58", "state": "normal"},
        ],
    },
    {
        "id": "loc-documents", "name": "Documents", "kind": "location",
        "files": [
            {"id": "f-headcount-model", "name": "Headcount_Model.xlsx",
             "kind": "spreadsheet", "size": "486 KB",
             "modified": "Thursday 15:03", "state": "normal"},
            {"id": "f-quarterly-draft", "name": "Quarterly_Report_Draft.docx",
             "kind": "document", "size": "1.1 MB",
             "modified": "Thursday 11:19", "state": "normal"},
            {"id": "f-vendor-process", "name": "Vendor_Payment_Process.pdf",
             "kind": "pdf", "size": "302 KB", "modified": "12 June",
             "state": "normal",
             "preview": [
                 "Vendor payment process — Northbridge Systems, rev 4",
                 "3.2  A change to a supplier's settlement account is accepted "
                 "only after a call-back to the telephone number held in the "
                 "supplier's Directory record. Confirmation by reply, by a "
                 "number supplied in the request, or by any other channel "
                 "offered by the requester is not sufficient.",
                 "3.3  The person who confirms the change may not be the "
                 "person who releases the payment.",
             ]},
        ],
    },
    {
        "id": "loc-downloads", "name": "Downloads", "kind": "location",
        "files": [
            {"id": "f-agenda", "name": "Ops_Review_Agenda.pdf", "kind": "pdf",
             "size": "96 KB", "modified": "Today 08:56", "state": "normal"},
            {"id": "f-invoice", "name": "Invoice_CF-20411.pdf", "kind": "pdf",
             "size": "214 KB", "modified": "Tuesday 11:50", "state": "normal"},
        ],
    },
    {
        "id": "loc-shared", "name": "Shared", "kind": "location",
        "path": "files.northbridge.example / operations",
        "files": [
            {"id": "f-q3-metrics", "name": "Q3_Metrics.xlsx",
             "kind": "spreadsheet", "size": "2.3 MB",
             "modified": "Thursday 17:38", "state": "normal",
             "owner": "Tom Brennan"},
            {"id": "f-facilities", "name": "Facilities_Contracts_2026.xlsx",
             "kind": "spreadsheet", "size": "740 KB", "modified": "4 August",
             "state": "normal", "owner": "Arjun Rao"},
            {"id": "f-handbook", "name": "Team_Handbook.pdf", "kind": "pdf",
             "size": "1.8 MB", "modified": "2 May", "state": "normal",
             "owner": "Sofia Lindqvist"},
        ],
    },
]

# ---------------------------------------------------------------------------
# Notes
# ---------------------------------------------------------------------------

NOTES = [
    {
        "id": "note-onboarding",
        "title": "Things I keep forgetting",
        "updated": "12 August",
        "body": "Payroll portal: payroll.northbridge.example\n"
                "Remote access: access.northbridge.example\n"
                "Service Desk: extension 2200\n"
                "Marcus: extension 2104",
    },
    {
        "id": "note-q3",
        "title": "Q3 pack — open items",
        "updated": "Yesterday",
        "body": "- headcount tab still mine\n"
                "- Tom has regional splits done\n"
                "- Marcus wants revised model, not July\n"
                "- Calderwood invoice CF-20411 to check against contract",
    },
]

# ---------------------------------------------------------------------------
# Authenticator
# ---------------------------------------------------------------------------

AUTH_HISTORY = [
    {"id": "auth-h1", "app": "Northbridge Mail", "result": "Approved",
     "device": "NB-LT-4471 · Windows", "location": "Bengaluru, IN",
     "when": "Today 08:47"},
    {"id": "auth-h2", "app": "Remote Access", "result": "Approved",
     "device": "NB-LT-4471 · Windows", "location": "Bengaluru, IN",
     "when": "Yesterday 09:02"},
    {"id": "auth-h3", "app": "Northbridge Mail", "result": "Approved",
     "device": "NB-LT-4471 · Windows", "location": "Bengaluru, IN",
     "when": "Yesterday 08:51"},
    {"id": "auth-h4", "app": "Expenses", "result": "Approved",
     "device": "Aarti's phone · Android", "location": "Bengaluru, IN",
     "when": "Wednesday 14:20"},
]

MFA_PROMPTS = [
    {
        "id": "mfa-vpn",
        "arrival": "triggered",
        "trigger": "browser_signin:access.northbridge.example",
        "surface": {
            "app": "Remote Access",
            "requested": "just now",
            "device": "NB-LT-4471 · Windows",
            "location": "Bengaluru, IN",
            "network": "Northbridge office network",
            "ip_class": "Corporate range",
            "number_match": "47",
        },
        "analysis": {
            "disposition": "legitimate",
            "family": None,
            "why": "This is the learner's own sign-in, seconds old, from this "
                   "workstation, on the office network.",
            "denying_costs": True,
        },
    },
    {
        "id": "mfa-unexpected",
        "arrival": "scheduled",
        "surface": {
            "app": "Northbridge Mail",
            "requested": "just now",
            "device": "Unrecognised device · Windows",
            "location": "Frankfurt, DE",
            "network": "Unknown",
            "ip_class": "Outside the corporate range",
            "number_match": "12",
        },
        "analysis": {
            "disposition": "hostile",
            "family": "mfa",
            "why": "An approval request for a sign-in the learner did not "
                   "start, from a place and device that appear nowhere in "
                   "their own approval history.",
            "signals": [
                "Nothing was signed into from this workstation in the minutes "
                "before the prompt.",
                "Every approval in the history is from Bengaluru on NB-LT-4471 "
                "or the learner's own phone.",
                "The device is not named, where genuine prompts name it.",
            ],
            "evidence": [
                {"id": "ev-mfa-history", "label": "Your own approval history",
                 "where": "Authenticator → Recent activity",
                 "action": "open_auth_history"},
                {"id": "ev-mfa-details", "label": "Device and location on the "
                                                  "prompt",
                 "where": "Authenticator → Details",
                 "action": "inspect_mfa:mfa-unexpected"},
                {"id": "ev-mfa-servicedesk", "label": "Service Desk contact",
                 "where": "Directory → Daniel Okonkwo",
                 "action": "open_contact:dir-daniel-okonkwo"},
            ],
        },
    },
]

# ---------------------------------------------------------------------------
# Messages
# ---------------------------------------------------------------------------

CONVERSATIONS = [
    {
        "id": "conv-tom-brennan",
        "contact_id": "dir-tom-brennan",
        "name": "Tom Brennan",
        "initials": "TB",
        "presence": "available",
        "messages": [
            {"from": "Tom Brennan", "when": "Yesterday 17:41",
             "text": "Workbook's up. Headcount tab is yours whenever."},
            {"from": "Aarti Venkatesh", "when": "Yesterday 17:44",
             "text": "Got it, will do it Monday morning."},
        ],
    },
    {
        "id": "conv-marcus-hale",
        "contact_id": "dir-marcus-hale",
        "name": "Marcus Hale",
        "initials": "MH",
        "presence": "in a meeting",
        "messages": [
            {"from": "Marcus Hale", "when": "08:56",
             "text": "Sent you the agenda. Ten minutes on throughput, that's "
                     "all I need."},
        ],
    },
    {
        "id": "conv-arjun-rao",
        "contact_id": "dir-arjun-rao",
        "name": "Arjun Rao",
        "initials": "AR",
        "presence": "available",
        "messages": [
            {"from": "Arjun Rao", "when": "Tuesday 12:02",
             "text": "Seen CF-20411, amount is fine. Release it on the normal "
                     "terms when you're ready."},
        ],
        "verification_reply": {
            "prompt": "Ask Arjun whether the account change is genuine",
            "sent": "Have you approved a change of settlement account for "
                    "Calderwood? A mail has come in asking to pay CF-20411 to "
                    "a different bank today.",
            "reply": {
                "from": "Arjun Rao",
                "text": "No. Nothing has been approved and nothing should move "
                        "until Facilities confirm it on the number we hold. "
                        "Forward me what you got and don't reply to it.",
            },
        },
    },
    {
        "id": "conv-priya-menon",
        "contact_id": "dir-priya-menon",
        "name": "Priya Menon",
        "initials": "PM",
        "presence": "available",
        "messages": [
            {"from": "Priya Menon", "when": "Monday 08:14",
             "text": "Payslips are out. Shout if anything looks off."},
        ],
        "verification_reply": {
            "prompt": "Ask Priya whether payroll has asked anyone to confirm "
                      "a record",
            "sent": "Has payroll sent anything asking people to confirm their "
                    "salary record today?",
            "reply": {
                "from": "Priya Menon",
                "text": "No, nothing has gone out today, and we would never "
                        "ask you to sign in from a mail link. Send it to "
                        "security and delete it.",
            },
        },
    },
    {
        "id": "conv-lena-fischer",
        "contact_id": "dir-lena-fischer",
        "name": "Lena Fischer",
        "initials": "LF",
        "presence": "available",
        "messages": [
            {"from": "Lena Fischer", "when": "Monday 10:30",
             "text": "Thanks for the one you sent last week — it was the "
                     "same batch three other people got."},
        ],
    },
    {
        "id": "conv-ops-team",
        "contact_id": None,
        "name": "Operations team",
        "initials": "OT",
        "presence": "group",
        "members": ["Marcus Hale", "Tom Brennan", "Ravi Krishnan",
                    "Aarti Venkatesh"],
        "messages": [
            {"from": "Ravi Krishnan", "when": "08:42",
             "text": "Stand-up in Meeting Room 2 from this week, room 5 is "
                     "being recarpeted."},
        ],
    },
]

# ---------------------------------------------------------------------------
# Browser
# ---------------------------------------------------------------------------
#
# Every page is authored here. The prototype browser cannot leave this table:
# anything else renders an inert "outside the synthetic network" page. No
# request is ever made, and no field value is read or retained.

BROWSER_HOME = "intranet.northbridge.example"

BROWSER_PAGES = {
    "intranet.northbridge.example": {
        "title": "Northbridge Intranet",
        "chrome": "internal",
        "kind": "portal",
        "heading": "Northbridge Systems",
        "subheading": "Operations · Bengaluru",
        "sections": [
            {"title": "Today", "items": [
                "Q3 operations review — Tuesday, 11:00, Meeting Room 2",
                "Benefits enrolment closes 19 September",
                "Remote access maintenance Saturday 06:00–08:00",
            ]},
            {"title": "Frequently used", "items": [
                "payroll.northbridge.example — payslips and tax documents",
                "access.northbridge.example — remote access",
                "files.northbridge.example — team shared folders",
            ]},
        ],
    },
    "payroll.northbridge.example": {
        "title": "Northbridge Payroll",
        "chrome": "internal",
        "kind": "signin",
        "heading": "Northbridge Payroll",
        "subheading": "Sign in with your Northbridge account",
        "signin_id": "payroll-legit",
        "note": "Payslips, tax documents and salary records.",
        "analysis": {"disposition": "legitimate"},
    },
    "payroll.northbridge.example/payslips": {
        "title": "Northbridge Payroll — payslips",
        "chrome": "internal",
        "kind": "signin",
        "heading": "Northbridge Payroll",
        "subheading": "Sign in to see your payslips",
        "signin_id": "payroll-legit",
        "analysis": {"disposition": "legitimate"},
    },
    "access.northbridge.example": {
        "title": "Northbridge Remote Access",
        "chrome": "internal",
        "kind": "signin",
        "heading": "Remote access",
        "subheading": "Sign in, then approve the request on your "
                      "authenticator.",
        "signin_id": "vpn-legit",
        "note": "Approval is required for every new session.",
        "analysis": {"disposition": "legitimate"},
    },
    "files.northbridge.example/operations/shared": {
        "title": "Northbridge Files — Operations",
        "chrome": "internal",
        "kind": "filelist",
        "heading": "Operations → Shared",
        "subheading": "Team shared folder",
        "location_id": "loc-shared",
    },
    "intranet.northbridge.example/it/maintenance": {
        # A legitimate download, so that "this page offers a file" is not
        # itself a signal. Both pages present the resource identically; what
        # differs is the site it is on and the file it materialises.
        "resources": [
            {"id": "res-access-guide", "name": "Remote_Access_Guide.pdf",
             "size": "186 KB", "kind": "pdf",
             "label": "Reconnection guide"},
        ],
        "title": "Maintenance calendar",
        "chrome": "internal",
        "kind": "portal",
        "heading": "Planned maintenance",
        "subheading": "Technology · next 30 days",
        "sections": [
            {"title": "This month", "items": [
                "Saturday 06:00–08:00 — remote access gateway, "
                "access.northbridge.example",
                "27 September 22:00 — file service reindex, no downtime "
                "expected",
            ]},
        ],
    },
    "intranet.northbridge.example/people/benefits": {
        "title": "Benefits 2026–27",
        "chrome": "internal",
        "kind": "portal",
        "heading": "Benefits enrolment",
        "subheading": "People Operations",
        "sections": [
            {"title": "What is changing", "items": [
                "Dental cover moves to the Tier 2 provider on 1 October",
                "Cycle-to-work reopens in October",
                "No action needed if your selections are unchanged",
            ]},
        ],
    },
    "intranet.northbridge.example/comms/weekly": {
        "title": "Northbridge Weekly",
        "chrome": "internal",
        "kind": "portal",
        "heading": "Northbridge Weekly",
        "subheading": "September, issue 3",
        "sections": [
            {"title": "In this issue", "items": [
                "Manchester floor plan changes from October",
                "Two new starters in Finance",
                "Cycle-to-work window reopens in October",
            ]},
        ],
    },
    "intranet.northbridge.example/finance/payments": {
        "title": "Supplier payments",
        "chrome": "internal",
        "kind": "payments",
        "heading": "Supplier payments",
        "subheading": "Operations · release queue",
        "note": "Account changes follow the vendor payment process. See "
                "Vendor_Payment_Process.pdf in your Documents folder.",
        "invoice": {
            "reference": "CF-20411",
            "supplier": "Calderwood Facilities Ltd",
            "amount": "£4,180.00",
            "approved_by": "Arjun Rao, 12:02 Tuesday",
            "account_of_record": "Nordvale Bank · 60-14-22 · ending 4417",
        },
        "authorize_decision": "d-bec-authorize",
        # Batch 4 review correction (BEC occurrence-scoped authorization):
        # a payments page is a *release queue*, and every entry in it is one
        # payment context -- a stable id, its own queue reference, and the
        # presented BEC occurrence it belongs to. The Calderwood surface has
        # exactly one entry and never recurs, so this table restates what
        # ``invoice``/``authorize_decision`` above already said; the shape is
        # here so the generic handler has one code path, not two.
        #
        # ``requires_mail`` is ``None``: the invoice is genuinely due and its
        # queue entry exists whether or not any account-change request ever
        # arrives. The redirection request does not create the payment, it
        # only asks for it to go somewhere else.
        "payment_contexts": (
            {
                "id": "pay-cf-20411-r1",
                "queue_ref": "RQ-3187",
                "occurrence_key": "m-invoice-amend",
                "authorize_decision": "d-bec-authorize",
                "requires_mail": None,
            },
        ),
        "analysis": {"disposition": "legitimate"},
    },
    "intranet.northbridge.example/finance/payments-meridian": {
        # Batch 4 review correction: the second BEC surface's own release
        # queue entry -- same page kind, same generic handler
        # (``service._browser_release_payment``), a different authored
        # ``authorize_decision`` so the two surfaces stay independently
        # scored.
        "title": "Supplier payments — Meridian",
        "chrome": "internal",
        "kind": "payments",
        "heading": "Supplier payments",
        "subheading": "Operations · release queue",
        "note": "Account changes follow the vendor payment process. See "
                "Vendor_Payment_Process.pdf in your Documents folder.",
        "invoice": {
            "reference": "MP-7734",
            "supplier": "Meridian Print Services",
            "amount": "£612.40",
            "approved_by": "Arjun Rao, 09:20 Monday",
            "account_of_record": "Bramwell Trust · ending 7729",
        },
        "authorize_decision": "d-bec2-authorize",
        # Batch 4 review correction (BEC occurrence-scoped authorization):
        # the Meridian relationship is the one BEC surface that *recurs*
        # (``cand-bec2-account-change``, ``max_occurrences=2``), so its
        # release queue carries one entry per presented occurrence.
        #
        # Both entries settle the same invoice of record -- MP-7734, Meridian
        # Print Services, £612.40, Bramwell Trust ending 7729 -- because the
        # second occurrence is a follow-up chase on the same fraud, not a
        # second fabricated supplier or a second fabricated invoice. What is
        # occurrence-specific is the *release request*: its queue reference
        # (``RQ-4482`` / ``RQ-4519``) and its payment-context id. Finance
        # raising a second release line after a supplier chases an invoice
        # they say is unpaid is ordinary; inventing a second supplier
        # relationship to justify a second button would not be.
        #
        # The second entry only exists once its own occurrence's message has
        # actually been delivered (``requires_mail``), so a learner cannot
        # act on a release request that nothing in their day has raised.
        #
        # Both entries authorize through the *same* semantic decision class,
        # ``d-bec2-authorize`` -- releasing a supplier payment to an account
        # that arrived by mail is the same mistake the second time. What
        # separates them is ``occurrence_key``, which scopes the recorded
        # decision, its consequence chain and its scoring opportunity to the
        # occurrence it actually resolved. See
        # ``rewindsec.workstation.consequences._record_id``.
        "payment_contexts": (
            {
                "id": "pay-mp-7734-r1",
                "queue_ref": "RQ-4482",
                "occurrence_key": "m-meridian-amend",
                "authorize_decision": "d-bec2-authorize",
                "requires_mail": None,
            },
            {
                "id": "pay-mp-7734-r2",
                "queue_ref": "RQ-4519",
                "occurrence_key": "m-meridian-amend-o2",
                "authorize_decision": "d-bec2-authorize",
                "requires_mail": "m-meridian-amend-o2",
            },
        ),
        "analysis": {"disposition": "legitimate"},
    },
    "intranet.northbridge.example/it/support": {
        "title": "Service Desk",
        "chrome": "internal",
        "kind": "support",
        "heading": "Service Desk",
        "subheading": "Technology · extension 2200",
        "note": "Disconnecting takes this workstation off the network "
                "immediately. You will lose mail and shared folders until it "
                "is reconnected.",
        "sections": [
            {"title": "Before you call", "items": [
                "Note what you were doing when the problem started.",
                "Do not restart the machine if files are failing to open.",
            ]},
        ],
    },
    "calderwood.example": {
        "title": "Calderwood Facilities Ltd",
        "chrome": "external",
        "kind": "portal",
        "heading": "Calderwood Facilities Ltd",
        "subheading": "Supplier portal",
        "sections": [
            {"title": "Contact", "items": [
                "Account manager: Ines Duarte",
                "ines.duarte@calderwood.example",
                "+44 20 7946 0318",
            ]},
            {"title": "Remittance", "items": [
                "Account changes are confirmed by telephone only.",
            ]},
        ],
        "analysis": {"disposition": "legitimate"},
    },
    "payroll-northbridge.example/employee/verify": {
        "title": "Employee record confirmation",
        "chrome": "external",
        "kind": "signin",
        "heading": "Northbridge Employee Services",
        "subheading": "Confirm your salary record to complete the September "
                      "run",
        "signin_id": "portal-hostile",
        "note": "Session expires in 09:41.",
        "analysis": {
            "disposition": "hostile",
            "family": "phishing",
            "why": "A credential-collection page. In this prototype it stores "
                   "nothing: the field is cleared on submit and its value is "
                   "never read.",
        },
    },
    "benefits-northbridge.example/portal/verify": {
        # Batch 4 review correction: the second phishing lure's own
        # credential-collection page, distinct from the payroll one. Stores
        # nothing here either -- see the payroll page's own note.
        "title": "Confirm your benefits selections",
        "chrome": "external",
        "kind": "signin",
        "heading": "Northbridge Benefits Enrolment",
        "subheading": "Confirm your selections before enrolment closes",
        "signin_id": "portal-hostile-2",
        "note": "Session expires in 04:12.",
        "analysis": {
            "disposition": "hostile",
            "family": "phishing",
            "why": "A second credential-collection page. In this prototype it "
                   "stores nothing: the field is cleared on submit and its "
                   "value is never read.",
        },
    },
    "nb-benefits-portal.example": {
        "title": "NB Benefits Portal",
        "chrome": "external",
        "kind": "portal",
        "heading": "NB Benefits Portal",
        "subheading": "Enrolment support gateway",
        "sections": [
            {"title": "Services", "items": [
                "Selection confirmation",
                "Dependant record updates",
            ]},
        ],
        "analysis": {"disposition": "hostile", "family": "phishing"},
    },
    "nbsystems-secure.example": {
        "title": "NB Systems Secure",
        "chrome": "external",
        "kind": "portal",
        "heading": "NB Systems Secure",
        "subheading": "Employee services gateway",
        "sections": [
            {"title": "Services", "items": [
                "Record confirmation",
                "Document retrieval",
            ]},
        ],
        "analysis": {"disposition": "hostile", "family": "phishing"},
    },
    "calderwood-billing.example": {
        "title": "Calderwood Billing Services",
        "chrome": "external",
        "kind": "portal",
        "heading": "Calderwood Billing Services",
        "subheading": "Accounts and remittance",
        # A downloadable resource, which is new in Batch 3 and is the second
        # entry vector into the ransomware family. "Download" here means: the
        # server materialises a row in the synthetic Downloads folder, through
        # the same collision resolver a mail attachment uses. Nothing is
        # fetched, no request leaves the process, no byte is written to disk,
        # and the client sends this resource id -- never a filename or a path.
        "resources": [
            {"id": "res-rate-card", "name": "Calderwood_Rates_Q4.xlsm",
             "size": "268 KB", "kind": "spreadsheet-macro",
             "label": "Current rate card"},
        ],
        "sections": [
            {"title": "Remittance", "items": [
                "Aveley Trust Bank · sort code 23-08-71 · account "
                "ending 9032",
            ]},
        ],
        "analysis": {"disposition": "hostile", "family": "bec"},
    },
}

BROWSER_BOOKMARKS = [
    {"label": "Intranet", "url": "intranet.northbridge.example"},
    {"label": "Payroll", "url": "payroll.northbridge.example"},
    {"label": "Remote access", "url": "access.northbridge.example"},
    {"label": "Shared files",
     "url": "files.northbridge.example/operations/shared"},
]

BROWSER_HISTORY = [
    {"url": "intranet.northbridge.example", "when": "Today 08:44"},
    {"url": "payroll.northbridge.example/payslips", "when": "Monday 08:20"},
    {"url": "files.northbridge.example/operations/shared",
     "when": "Thursday 17:45"},
]

# ---------------------------------------------------------------------------
# Notifications present at session start
# ---------------------------------------------------------------------------

OPENING_NOTIFICATIONS = [
    {
        "id": "n-open-1",
        "kind": "mail",
        "title": "4 unread messages",
        "body": "Marcus Hale, Ravi Krishnan, Tom Brennan and one other.",
        "when": "09:00",
        "opens": {"app": "mail"},
    },
    {
        "id": "n-open-2",
        "kind": "system",
        "title": "Backup completed",
        "body": "Documents and Desktop backed up at 07:30.",
        "when": "07:30",
        "opens": None,
    },
]
