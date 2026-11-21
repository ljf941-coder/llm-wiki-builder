# -*- coding: utf-8 -*-
"""Local redaction contract (reference implementation).

This module demonstrates the shared sensitive_guard contract used by the
skill: redact suspected credential fragments in place, keep the rest of
the context, and never echo original values in titles, filenames, indexes,
status, logs, or errors.

It is not a production collector, scheduler, or a claim that target-wiki
adapters have been migrated. Detection has blind spots and does not
promise zero misses.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple


@dataclass(frozen=True)
class _Span:
    start: int
    end: int
    kind: str
    annotate_at: int
    certain: bool = True


NOTE = "疑似凭据已脱敏"
PLACEHOLDER = "xxx"
ANNOTATION = "（%s）" % NOTE
MAX_PASSES = 5

# Match kinds are labels only; never attach matched text to messages.
KIND_PRIVATE_KEY = "private_key"
KIND_CREDENTIAL_URI = "credentialed_uri"
KIND_TOKEN = "token"
KIND_JWT = "jwt"
KIND_PASSWORD = "password_assignment"

# Conventional PKCS/OpenSSH PEM labels plus PGP private key blocks.
_ARMOR_LABEL = r"[A-Z0-9][A-Z0-9 ]{0,50}PRIVATE KEY(?: BLOCK)?"
_COMPLETE_ARMOR = re.compile(
    r"-----BEGIN (" + _ARMOR_LABEL + r")-----"
    r"[\s\S]*?"
    r"-----END \1-----",
    re.IGNORECASE,
)
_ARMOR_BEGIN = re.compile(
    r"-----BEGIN (" + _ARMOR_LABEL + r")-----",
    re.IGNORECASE,
)
_BASE64_LINE = re.compile(r"^[A-Za-z0-9+/=]+$")
_PGP_CHECKSUM = re.compile(r"^=[A-Za-z0-9+/=]{4}$")
_ARMOR_HEADER_LINE = re.compile(
    r"(?i)^(Proc-Type|DEK-Info|Version|Comment|Charset|Hash|"
    r"MessageID|Originator-ID|Passphrase-Charset|CRL):\s*\S"
)
_ORPHAN_BAG_HEADER = re.compile(
    r"(?im)^(?:Proc-Type:\s*4,\s*ENCRYPTED|DEK-Info:\s*[A-Za-z0-9-]+,.+)$"
)

# userinfo password before '@', including empty usernames such as redis://:pass@host.
# Ordinary URLs without userinfo are not matched.
_CREDENTIAL_URI = re.compile(
    r"(?i)\b(?:[a-z][a-z0-9+.-]{0,32})://[^\s/@:#\"']*:[^\s/@#\"']+@[^\s\"'<>]+"
)
_USERINFO = re.compile(
    r"(?i)^(.*?://)([^/@:#\"']*:[^/@#\"']+)(@.*)$"
)

_TOKEN_PATTERNS = (
    re.compile(r"\bghp_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{16,}\b"),
    re.compile(r"\bgho_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{16,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"),
    re.compile(r"\b(?:Bearer|token)[ \t]+[A-Za-z0-9._\-+=/]{16,}", re.IGNORECASE),
)

_JWT = re.compile(
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
)

_PASSWORD_ASSIGNMENT = re.compile(
    r"(?i)(['\"]?(?:password|passwd|pwd|db_password|db_passwd|"
    r"api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)['\"]?"
    r"\s*[:=]\s*['\"]?)(?!xxx\b)([^\s'\"]{4,})(['\"]?)"
)


class RedactionError(Exception):
    """Error that must not include original credential values."""

    def __init__(self, message: str) -> None:
        super().__init__(message)


@dataclass
class RedactionResult:
    text: str
    changed: bool
    annotation_count: int
    residual_gaps: List[str] = field(default_factory=list)
    clean: bool = True

    @property
    def blocked(self) -> bool:
        # Legacy alias kept so callers do not treat a hit as a session block.
        return False


def _line_col(text: str, index: int) -> Tuple[int, int]:
    line = text.count("\n", 0, index) + 1
    last_nl = text.rfind("\n", 0, index)
    col = index - last_nl
    return line, col


def _gap(kind: str, text: str, index: int, reason: str) -> str:
    line, col = _line_col(text, index)
    return (
        "line %d column %d: %s fragment %s; original value omitted"
        % (line, col, kind, reason)
    )


def _overlaps(start: int, end: int, spans: Sequence[_Span]) -> bool:
    for span in spans:
        if start < span.end and end > span.start:
            return True
    return False


def _is_armor_payload_line(stripped: str) -> bool:
    if stripped == "":
        return True
    if _ARMOR_HEADER_LINE.match(stripped):
        return True
    if _BASE64_LINE.match(stripped):
        return True
    if _PGP_CHECKSUM.match(stripped):
        return True
    return False


def _extend_incomplete_armor(text: str, header_end: int) -> Tuple[int, bool, bool]:
    """Extend a BEGIN without END through headers, blank lines, and body.

    Returns (end_index, saw_body, reached_clear_boundary).
    A clear boundary is EOF or a following line that is not armor payload.
    """
    i = header_end
    last = header_end
    n = len(text)
    saw_body = False
    reached_boundary = i >= n
    while i < n:
        nl = text.find("\n", i)
        if nl == -1:
            line = text[i:]
            end = n
            has_nl = False
        else:
            line = text[i:nl]
            end = nl + 1
            has_nl = True
        stripped = line.strip()
        if _is_armor_payload_line(stripped):
            if _BASE64_LINE.match(stripped) or _PGP_CHECKSUM.match(stripped):
                saw_body = True
            last = end
            i = end
            if not has_nl:
                reached_boundary = True
                break
            continue
        reached_boundary = True
        break
    else:
        reached_boundary = True
    return last, saw_body, reached_boundary


def _span(
    start: int,
    end: int,
    kind: str,
    annotate_at: Optional[int] = None,
    certain: bool = True,
) -> _Span:
    return _Span(
        start,
        end,
        kind,
        end if annotate_at is None else annotate_at,
        certain,
    )


def _find_spans(text: str) -> List[_Span]:
    spans: List[_Span] = []

    for match in _COMPLETE_ARMOR.finditer(text):
        spans.append(_span(match.start(), match.end(), KIND_PRIVATE_KEY, certain=True))

    for match in _ARMOR_BEGIN.finditer(text):
        if _overlaps(match.start(), match.end(), spans):
            continue
        end, saw_body, reached_boundary = _extend_incomplete_armor(text, match.end())
        certain = bool(saw_body and reached_boundary)
        spans.append(_span(match.start(), end, KIND_PRIVATE_KEY, certain=certain))

    for match in _ORPHAN_BAG_HEADER.finditer(text):
        if _overlaps(match.start(), match.end(), spans):
            continue
        end, saw_body, reached_boundary = _extend_incomplete_armor(text, match.end())
        certain = bool(saw_body and reached_boundary)
        spans.append(_span(match.start(), end, KIND_PRIVATE_KEY, certain=certain))

    for match in _CREDENTIAL_URI.finditer(text):
        if not _overlaps(match.start(), match.end(), spans):
            spans.append(_span(match.start(), match.end(), KIND_CREDENTIAL_URI))

    for match in _JWT.finditer(text):
        if not _overlaps(match.start(), match.end(), spans):
            spans.append(_span(match.start(), match.end(), KIND_JWT))

    for pattern in _TOKEN_PATTERNS:
        for match in pattern.finditer(text):
            if not _overlaps(match.start(), match.end(), spans):
                spans.append(_span(match.start(), match.end(), KIND_TOKEN))

    for match in _PASSWORD_ASSIGNMENT.finditer(text):
        value_start = match.start(2)
        value_end = match.end(2)
        if not _overlaps(value_start, value_end, spans):
            spans.append(_span(value_start, value_end, KIND_PASSWORD, match.end()))

    spans.sort(key=lambda item: (item.start, -(item.end - item.start)))
    merged: List[_Span] = []
    for span in spans:
        if _overlaps(span.start, span.end, merged):
            continue
        merged.append(span)
    merged.sort(key=lambda item: item.start)
    return merged


def _replace_credential_uri(fragment: str) -> str:
    match = _USERINFO.match(fragment)
    if match:
        return "%s%s%s" % (match.group(1), PLACEHOLDER, match.group(3))
    return PLACEHOLDER


def _replacement_for(kind: str, fragment: str) -> str:
    if kind == KIND_PRIVATE_KEY:
        return PLACEHOLDER
    if kind == KIND_CREDENTIAL_URI:
        return _replace_credential_uri(fragment)
    return PLACEHOLDER


def _has_nearby_annotation(text: str, index: int) -> bool:
    window = text[index:index + len(ANNOTATION) + 8]
    return NOTE in window


def _apply_spans(text: str, spans: Sequence[_Span]) -> str:
    pieces: List[str] = []
    cursor = 0
    for span in spans:
        pieces.append(text[cursor:span.start])
        pieces.append(_replacement_for(span.kind, text[span.start:span.end]))
        pieces.append(text[span.end:span.annotate_at])
        if not _has_nearby_annotation(text, span.annotate_at):
            pieces.append(ANNOTATION)
        cursor = span.annotate_at
    pieces.append(text[cursor:])
    return "".join(pieces)


def redact_text(text: str, max_passes: int = MAX_PASSES) -> RedactionResult:
    """Redact suspected credential fragments and keep remaining context.

    Rechecks the result and continues while spans remain, up to max_passes.
    Residual fragments are reported as gaps without original values. The
    whole text is never dropped in favor of an empty result.
    """
    if text is None:
        raise RedactionError("redact_text received no text")

    current = text
    changed = False
    annotations_before = current.count(NOTE)
    uncertain_reasons: List[str] = []

    try:
        for _pass in range(max(1, max_passes)):
            spans = _find_spans(current)
            if not spans:
                break
            for span in spans:
                if not span.certain:
                    uncertain_reasons.append(
                        _gap(
                            span.kind,
                            current,
                            span.start,
                            "block end could not be determined",
                        )
                    )
            current = _apply_spans(current, spans)
            changed = True
        residual = _find_spans(current)
        gaps = [
            _gap(span.kind, current, span.start, "could not be fully redacted")
            for span in residual
        ]
        # Keep earlier uncertainty reports even after the fragment is replaced,
        # but never include original values. Deduplicate exact messages.
        for item in uncertain_reasons:
            if item not in gaps:
                gaps.append(item)
    except RedactionError:
        raise
    except Exception:
        raise RedactionError("redaction failed; original value omitted") from None

    annotation_count = current.count(NOTE)
    if annotation_count > annotations_before:
        changed = True
    return RedactionResult(
        text=current,
        changed=changed or current != text,
        annotation_count=annotation_count,
        residual_gaps=gaps,
        clean=not gaps,
    )


def _mostly_placeholder(text: str) -> bool:
    stripped = text.replace(PLACEHOLDER, " ").replace(NOTE, " ")
    stripped = re.sub(r"[\s（）()「」【】\[\].,，。:：-]+", "", stripped)
    return stripped == ""


def redact_title(title: str, body: Optional[str] = None) -> str:
    """Locally redact a title, or re-summarize if almost nothing remains.

    Never blocks a source because the title hits a suspected credential.
    The unused body argument is reserved so callers can later re-summarize
    from already-redacted body text without sending original values.
    """
    del body  # reference implementation does not call a model
    result = redact_text(title or "")
    if _mostly_placeholder(result.text):
        return "已重新概括" + ANNOTATION
    return result.text


def contains_residual_credentials(text: str) -> bool:
    """True when a recheck still finds suspected fragments."""
    return bool(_find_spans(text or ""))
