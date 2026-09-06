"""The fail-closed sanitizer every string entering the content pipeline passes.

Architecture Spec v1.1 (Batch 4) S40 requires this to fail closed: an
unsupported or unsafe pattern is rejected, never silently stripped or passed
through. Nothing here tries to be clever about "cleaning" unsafe input --
cleaning implies the rest of the string is still trustworthy, and that is
exactly the assumption this module refuses to make.

Used by :mod:`rewindsec.content.provenance` (before a source record is
accepted), :mod:`rewindsec.content.normalize`, and
:mod:`rewindsec.content.schema` (every leaf string in a
:class:`~rewindsec.content.schema.SyntheticDocument`).
"""

import re

__all__ = ["SanitizationError", "sanitize_text", "ALLOWED_DOMAINS"]


class SanitizationError(ValueError):
    """A string failed sanitization. Raised rather than silently cleaned."""


#: Fictional/reserved domains this pipeline is allowed to reference. Anything
#: else that looks like a real, resolvable domain is rejected -- this content
#: is synthetic and must never point at a real address, even by accident.
#: ``.example`` is IANA-reserved for documentation (RFC 2606) and is what the
#: rest of the RewindSec 2.0 content already uses throughout.
ALLOWED_DOMAINS = (".example",)

_CONTROL_CHARS = frozenset(chr(i) for i in range(0, 32)) - {"\n", "\r", "\t"}
_CONTROL_CHARS |= {chr(127)}

_UNSAFE_PATTERNS = (
    re.compile(r"<\s*script", re.IGNORECASE),
    re.compile(r"<\s*/?\s*[a-z][a-z0-9]*[\s/>]", re.IGNORECASE),  # any HTML tag
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"on[a-z]+\s*=", re.IGNORECASE),  # onclick=, onerror=, ...
    re.compile(r"\.\./"),  # path traversal
    re.compile(r"\.\.\\"),
    re.compile(r"\bexec\s*\(|\beval\s*\(", re.IGNORECASE),
    re.compile(r"#!\s*/"),  # shebang
)

#: Credential/token-shaped strings: long runs that look like an API key,
#: bearer token or password assignment. Fail closed rather than guess intent.
_CREDENTIAL_PATTERNS = (
    re.compile(r"(?i)\b(api[_-]?key|secret|bearer|password|passwd)\s*[:=]\s*\S+"),
    re.compile(r"\b[A-Za-z0-9_\-]{32,}\b"),
)

_EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+\-]+@([A-Za-z0-9.\-]+\.[A-Za-z]{2,})")
_PHONE_PATTERN = re.compile(r"(?<!\w)(?:\+?\d[\s\-().]*){7,}\d(?!\w)")
_URL_PATTERN = re.compile(r"(?i)\b(?:https?://|www\.)([A-Za-z0-9.\-]+)")

_MAX_LENGTH_DEFAULT = 2000


def _domain_allowed(domain):
    domain = domain.lower()
    return any(domain.endswith(suffix) for suffix in ALLOWED_DOMAINS)


def sanitize_text(value, max_length=_MAX_LENGTH_DEFAULT, allow_email_domains=True):
    """Return *value* if it is safe synthetic text, else raise.

    Fail-closed: any recognised unsafe pattern raises. This is not an
    HTML/JS parser -- it does not need to be, because nothing downstream ever
    interprets its output as anything but literal display text -- but it does
    reject the shapes that would matter if something downstream ever did.
    """
    if not isinstance(value, str):
        raise SanitizationError("expected a string, got %s" % type(value).__name__)
    if len(value) > max_length:
        raise SanitizationError("text exceeds %d characters" % max_length)

    for char in value:
        if char in _CONTROL_CHARS:
            raise SanitizationError("text contains a control character")

    for pattern in _UNSAFE_PATTERNS:
        if pattern.search(value):
            raise SanitizationError("text contains an unsafe pattern: %r"
                                    % pattern.pattern)

    for pattern in _CREDENTIAL_PATTERNS:
        if pattern.search(value):
            raise SanitizationError("text looks like a credential or token")

    for match in _EMAIL_PATTERN.finditer(value):
        if allow_email_domains and _domain_allowed(match.group(1)):
            continue
        raise SanitizationError("text contains a real-looking email address")

    for match in _URL_PATTERN.finditer(value):
        if _domain_allowed(match.group(1)):
            continue
        raise SanitizationError("text contains a live, non-reserved domain")

    if _PHONE_PATTERN.search(value):
        raise SanitizationError("text contains a phone-number-shaped string")

    return value


def sanitize_record(record, allowed_fields):
    """Sanitize every string value in a flat ``{field: value}`` mapping.

    Rejects any field not in *allowed_fields* outright -- an unsupported
    field is unreviewed by definition, so it cannot enter the pipeline no
    matter what it contains.
    """
    if not isinstance(record, dict):
        raise SanitizationError("record must be an object")
    unknown = set(record) - set(allowed_fields)
    if unknown:
        raise SanitizationError("unsupported field(s): %s" % ", ".join(sorted(unknown)))
    out = {}
    for key, value in record.items():
        if isinstance(value, str):
            out[key] = sanitize_text(value)
        elif isinstance(value, (int, float, bool)) or value is None:
            out[key] = value
        elif isinstance(value, list):
            out[key] = [sanitize_text(item) if isinstance(item, str) else item
                       for item in value]
        else:
            raise SanitizationError(
                "field %r has an unsupported type %s" % (key, type(value).__name__))
    return out
