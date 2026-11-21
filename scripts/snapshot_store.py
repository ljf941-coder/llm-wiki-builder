# -*- coding: utf-8 -*-
"""Read-only snapshot import helpers (reference implementation).

Provides source-level deduplication and new-version writes after local
redaction. Existing snapshot files are never overwritten, rewritten, or
renamed. Import records the source as 已采集 / 待整理; a short summary
only moves review status to 部分提炼, never 已整理.

Untrusted identifiers such as source_key are stored as irreversible
stable hashes so different sources do not collide and original values
never appear in titles, filenames, indexes, status, logs, or errors.

This is not a collector, scheduler, or historical-session reprocessor,
and does not call other tools' CLIs.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Dict, List, Optional

from .sensitive_guard import NOTE, RedactionResult, redact_text, redact_title


INGEST_COLLECTED = "已采集"
REVIEW_PENDING = "待整理"
REVIEW_PARTIAL = "部分提炼"
REVIEW_DONE = "已整理"
ADAPTER_NAME = "reference"
_SAFE_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,31}$")
# Adapter prefix, but not a URI scheme (scheme is followed by //).
_SAFE_ADAPTER_PREFIX = re.compile(r"^([A-Za-z][A-Za-z0-9_]{0,31}):(?!//).+")


class SnapshotError(Exception):
    """Error that must not include original credential values."""

    def __init__(self, message: str) -> None:
        super().__init__(message)


@dataclass
class ImportResult:
    action: str
    path: Path
    ingest_status: str
    review_status: str
    content_hash: str
    redaction: RedactionResult
    title: str
    source_index: str
    gaps: List[str] = field(default_factory=list)


def _safe_segment(text: str, max_len: int) -> str:
    cleaned = re.sub(r"[^\w\u4e00-\u9fff-]+", "-", text, flags=re.UNICODE)
    cleaned = re.sub(r"-{2,}", "-", cleaned).strip("-")
    if not cleaned:
        cleaned = "untitled"
    return cleaned[:max_len].rstrip("-") or "untitled"


def _source_digest(source_key: str) -> str:
    return sha256(source_key.encode("utf-8")).hexdigest()


def source_index_key(source_key: str) -> str:
    """Stable irreversible index key for an untrusted source identifier."""
    digest = _source_digest(source_key)
    match = _SAFE_ADAPTER_PREFIX.match(source_key)
    if match:
        return "%s:src-%s" % (match.group(1), digest)
    return "src-%s" % digest


def _short_source_id(index_key: str) -> str:
    digest = index_key.rsplit("src-", 1)[-1]
    return digest[:16]


def _content_hash(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest()


class SnapshotStore:
    def __init__(self, root: Path, adapter: str = ADAPTER_NAME) -> None:
        self.root = Path(root)
        if _SAFE_NAME.fullmatch(adapter or ""):
            self.adapter = adapter
        else:
            self.adapter = "adapter-" + _source_digest(adapter or ADAPTER_NAME)[:16]
        self.snapshot_dir = self.root / "conversations" / self.adapter
        self.state_path = self.root / "state" / "sources.json"

    def _load_state(self) -> Dict:
        if not self.state_path.is_file():
            return {"sources": {}}
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raise SnapshotError("failed to read machine-maintained state") from None
        if not isinstance(data, dict) or "sources" not in data:
            raise SnapshotError("state file missing sources mapping")
        return data

    def _ensure_dir(self, path: Path) -> None:
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError:
            raise SnapshotError(
                "failed to create directory; original value omitted"
            ) from None

    def _write_text(self, path: Path, text: str) -> None:
        self._ensure_dir(path.parent)
        try:
            with path.open("w", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
        except OSError:
            raise SnapshotError("failed to write file; original value omitted") from None

    def _save_state(self, data: Dict) -> None:
        payload = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True)
        self._write_text(self.state_path, payload + "\n")

    def _filename(self, title: str, index_key: str, version: int) -> str:
        base = "%s--%s" % (_safe_segment(title, 60), _short_source_id(index_key))
        if version > 1:
            base = "%s--v%d" % (base, version)
        return base + ".md"

    def _unique_path(self, title: str, index_key: str, version: int) -> Path:
        self._ensure_dir(self.snapshot_dir)
        path = self.snapshot_dir / self._filename(title, index_key, version)
        while path.exists():
            version += 1
            path = self.snapshot_dir / self._filename(title, index_key, version)
        return path

    def _render_snapshot(
        self,
        title: str,
        index_key: str,
        body: str,
        content_hash: str,
        ingest_status: str,
        review_status: str,
        redacted: bool,
    ) -> str:
        note = "脱敏快照仅供来源追溯，不能直接当作正式知识。"
        flags = "是" if redacted else "否"
        header = "\n".join(
            [
                "# %s" % title,
                "",
                "- source: %s" % index_key,
                "- content_hash: %s" % content_hash,
                "- ingest_status: %s" % ingest_status,
                "- review_status: %s" % review_status,
                "- redacted: %s" % flags,
                "- note: %s" % note,
                "",
            ]
        )
        return header + body.rstrip() + "\n"

    def import_text(
        self,
        source_key: str,
        text: str,
        title: Optional[str] = None,
    ) -> ImportResult:
        if not source_key or not str(source_key).strip():
            raise SnapshotError("source_key is required")

        index_key = source_index_key(source_key)
        redaction = redact_text(text)
        body = redaction.text
        digest = _content_hash(body)
        safe_title = redact_title(title or "", body=body)
        if not (title or "").strip():
            safe_title = "待生成"

        state = self._load_state()
        record = state["sources"].setdefault(
            index_key,
            {
                "ingest_status": INGEST_COLLECTED,
                "review_status": REVIEW_PENDING,
                "versions": [],
            },
        )
        versions = record.setdefault("versions", [])
        for item in versions:
            if item.get("content_hash") == digest:
                existing = self.root / item["path"]
                return ImportResult(
                    action="duplicate",
                    path=existing,
                    ingest_status=record.get("ingest_status", INGEST_COLLECTED),
                    review_status=record.get("review_status", REVIEW_PENDING),
                    content_hash=digest,
                    redaction=redaction,
                    title=str(item.get("title") or safe_title),
                    source_index=index_key,
                    gaps=list(redaction.residual_gaps),
                )

        version = len(versions) + 1
        path = self._unique_path(safe_title, index_key, version)
        # Import itself never marks 已整理. A later version of a source that
        # was already 部分提炼 or 已整理 becomes 部分提炼; otherwise 待整理.
        review = REVIEW_PENDING
        if version > 1 and record.get("review_status") in (REVIEW_PARTIAL, REVIEW_DONE):
            review = REVIEW_PARTIAL
        payload = self._render_snapshot(
            safe_title,
            index_key,
            body,
            digest,
            INGEST_COLLECTED,
            review,
            redacted=redaction.changed,
        )
        self._write_text(path, payload)

        rel = path.relative_to(self.root).as_posix()
        versions.append(
            {
                "content_hash": digest,
                "path": rel,
                "title": safe_title,
            }
        )
        record["ingest_status"] = INGEST_COLLECTED
        record["review_status"] = review
        self._save_state(state)
        return ImportResult(
            action="created" if version == 1 else "new_version",
            path=path,
            ingest_status=INGEST_COLLECTED,
            review_status=review,
            content_hash=digest,
            redaction=redaction,
            title=safe_title,
            source_index=index_key,
            gaps=list(redaction.residual_gaps),
        )

    def record_partial_distill(self, source_key: str, summary: str) -> Dict:
        """Store a short redacted summary. This is 部分提炼, not 已整理."""
        state = self._load_state()
        record = state["sources"].get(source_index_key(source_key))
        if not record:
            raise SnapshotError("cannot distill an unknown source")
        redacted = redact_text(summary)
        if NOTE in (summary or "") or redacted.changed:
            # Keep only the redacted summary in machine state.
            stored = redacted.text
        else:
            stored = summary
        record["review_status"] = REVIEW_PARTIAL
        record["partial_summary"] = stored
        self._save_state(state)
        return {
            "review_status": REVIEW_PARTIAL,
            "partial_summary": stored,
            "ingest_status": record.get("ingest_status", INGEST_COLLECTED),
        }

    def source_record(self, source_key: str) -> Optional[Dict]:
        return self._load_state()["sources"].get(source_index_key(source_key))
