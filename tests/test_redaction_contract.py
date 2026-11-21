# -*- coding: utf-8 -*-
"""Fictional-data regression tests for the redaction contract.

These tests exercise the repository's reference implementation only.
They do not run a collector or scheduler, do not connect to a model or
database, and do not claim that target-wiki adapters have been migrated.
All credentials below are obviously fictional and must never appear in
failure messages.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.sensitive_guard import (  # noqa: E402
    NOTE,
    PLACEHOLDER,
    RedactionError,
    contains_residual_credentials,
    redact_text,
    redact_title,
)
from scripts.snapshot_store import (  # noqa: E402
    INGEST_COLLECTED,
    REVIEW_DONE,
    REVIEW_PARTIAL,
    REVIEW_PENDING,
    SnapshotError,
    SnapshotStore,
    source_index_key,
)


# Clearly fictional samples. Do not substitute real user data.
FAKE_TOKEN = "ghp_EXAMPLETESTONLY0000000000000000"
FAKE_TOKEN_2 = "ghp_EXAMPLETESTONLY0000000000001111"
FAKE_PEM_BODY_1 = "MIIEFakeTestOnlyPrivateKeyMaterialNotRealAAAAB3NzaC1yc2EAAAADAQAB"
FAKE_PEM_BODY_2 = "AAABAQCthisIsClearlyFictionalKeyBodyForRegressionTestsOnlyXX0001"
FAKE_PEM = "\n".join(
    [
        "-----BEGIN EXAMPLE TEST PRIVATE KEY-----",
        FAKE_PEM_BODY_1,
        FAKE_PEM_BODY_2,
        "-----END EXAMPLE TEST PRIVATE KEY-----",
    ]
)
FAKE_INCOMPLETE_PEM = "\n".join(
    [
        "-----BEGIN RSA PRIVATE KEY-----",
        FAKE_PEM_BODY_1,
        FAKE_PEM_BODY_2,
    ]
)
FAKE_DEK_IV = "00112233445566778899aabbccddeeff"
FAKE_ENCRYPTED_PEM = "\n".join(
    [
        "-----BEGIN RSA PRIVATE KEY-----",
        "Proc-Type: 4,ENCRYPTED",
        "DEK-Info: AES-256-CBC,%s" % FAKE_DEK_IV,
        "",
        FAKE_PEM_BODY_1,
        FAKE_PEM_BODY_2,
    ]
)
FAKE_PGP = "\n".join(
    [
        "-----BEGIN PGP PRIVATE KEY BLOCK-----",
        "Version: GnuPG v1",
        "",
        FAKE_PEM_BODY_1,
        FAKE_PEM_BODY_2,
        "-----END PGP PRIVATE KEY BLOCK-----",
    ]
)
FAKE_PASSWORD = "FictionalPass_NotReal-123"
FAKE_PASSWORD_2 = "FictionalPass_NotReal-456"
FAKE_DB_URI = "postgres://testuser:%s@db.example.test:5432/appdb" % FAKE_PASSWORD
FAKE_DB_URI_2 = "postgres://testuser:%s@db.example.test:5432/appdb" % FAKE_PASSWORD_2
FAKE_HTTPS_URI = "https://demo_user:%s@api.example.test/v1" % FAKE_PASSWORD
HARMLESS_URL = "https://docs.example.com/guide/intro?q=wiki"
FAKE_JWT = (
    "eyJhbGciOiJIUzI1NiJ9."
    "eyJzdWIiOiJmaWN0aW9uYWwtdGVzdC1vbmx5In0."
    "FictionalTestSignatureXX"
)
CONTEXT_BEFORE = "讨论主题是知识库整理与标题生成。"
CONTEXT_AFTER = "下一步是继续写文档并保留普通链接。"
CONTEXT_BEFORE_SHORT = "前文"
CONTEXT_AFTER_SHORT = "后文"

FICTIONAL_SECRETS = (
    FAKE_TOKEN,
    FAKE_TOKEN_2,
    FAKE_PEM_BODY_1,
    FAKE_PEM_BODY_2,
    FAKE_PASSWORD,
    FAKE_PASSWORD_2,
    FAKE_DEK_IV,
    FAKE_JWT,
    "eyJhbGciOiJIUzI1NiJ9",
    "testuser:%s" % FAKE_PASSWORD,
    "testuser:%s" % FAKE_PASSWORD_2,
    "demo_user:%s" % FAKE_PASSWORD,
    ":%s@" % FAKE_PASSWORD,
    ":%s@" % FAKE_PASSWORD_2,
)


def _leaks(blob: str) -> bool:
    return any(secret in blob for secret in FICTIONAL_SECRETS)


def _tree_blob(root: Path) -> str:
    parts = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        parts.append(path.name)
        parts.append(path.as_posix())
        try:
            parts.append(path.relative_to(root).as_posix())
        except ValueError:
            pass
        if path.is_file():
            parts.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(parts)


class SecretSafeTestCase(unittest.TestCase):
    def assert_no_leak(self, *parts: object) -> None:
        blob = "\n".join("" if part is None else str(part) for part in parts)
        if _leaks(blob):
            self.fail(
                "a result, path, status, or message leaked a fictional "
                "credential; value omitted"
            )

    def assert_tree_clean(self, root: Path, *extra: object) -> None:
        blob = _tree_blob(root)
        self.assert_no_leak(blob, *extra)

    def assert_context_kept(self, text: str, before: str = CONTEXT_BEFORE, after: str = CONTEXT_AFTER) -> None:
        if before not in text or after not in text:
            self.fail("useful surrounding context was not preserved")
        if text.strip() in ("", PLACEHOLDER, NOTE):
            self.fail("redaction dropped the whole text instead of a fragment")


class RedactionTests(SecretSafeTestCase):
    def test_local_replacement_keeps_context(self) -> None:
        source = "%s 访问令牌示例：%s。%s" % (CONTEXT_BEFORE, FAKE_TOKEN, CONTEXT_AFTER)
        result = redact_text(source)
        self.assert_no_leak(result.text, result.residual_gaps, result.clean)
        self.assert_context_kept(result.text)
        self.assertIn(PLACEHOLDER, result.text)
        self.assertIn(NOTE, result.text)
        self.assertTrue(result.changed)
        self.assertTrue(result.clean)
        self.assertFalse(result.blocked)
        # The rest of the same message must remain; dropping the message is not redaction.
        self.assertGreater(len(result.text), len(CONTEXT_BEFORE))

    def test_multiline_private_key_cleared_including_body(self) -> None:
        source = "%s\n%s\n%s" % (CONTEXT_BEFORE, FAKE_PEM, CONTEXT_AFTER)
        result = redact_text(source)
        self.assert_no_leak(result.text, result.residual_gaps)
        self.assert_context_kept(result.text)
        self.assertIn(NOTE, result.text)
        if "BEGIN " in result.text.upper() and "PRIVATE KEY" in result.text.upper():
            self.fail("private-key header remained after redaction")
        if "END " in result.text.upper() and "PRIVATE KEY" in result.text.upper():
            self.fail("private-key footer remained after redaction")

    def test_incomplete_private_key_body_is_not_left_behind(self) -> None:
        source = "%s\n%s\n%s" % (CONTEXT_BEFORE, FAKE_INCOMPLETE_PEM, CONTEXT_AFTER)
        result = redact_text(source)
        self.assert_no_leak(result.text, result.residual_gaps)
        self.assert_context_kept(result.text)
        if "BEGIN " in result.text.upper() and "PRIVATE KEY" in result.text.upper():
            self.fail("incomplete private-key header remained after redaction")

    def test_encrypted_incomplete_pem_headers_and_body_cleared(self) -> None:
        source = "%s\n%s\n%s" % (CONTEXT_BEFORE_SHORT, FAKE_ENCRYPTED_PEM, CONTEXT_AFTER_SHORT)
        result = redact_text(source)
        self.assert_no_leak(result.text, result.residual_gaps)
        self.assert_context_kept(result.text, CONTEXT_BEFORE_SHORT, CONTEXT_AFTER_SHORT)
        if "Proc-Type" in result.text or "DEK-Info" in result.text:
            self.fail("encrypted PEM bag headers remained after redaction")
        if "BEGIN " in result.text.upper() and "PRIVATE KEY" in result.text.upper():
            self.fail("encrypted PEM header remained after redaction")
        self.assertTrue(result.changed)
        self.assertTrue(result.clean)
        if result.residual_gaps:
            self.fail("fully bounded encrypted PEM body was reported as a gap")
        if contains_residual_credentials(result.text):
            self.fail("recheck still found a suspected fragment after encrypted PEM redaction")

        crlf_source = source.replace("\n", "\r\n")
        crlf = redact_text(crlf_source)
        self.assert_no_leak(crlf.text, crlf.residual_gaps)
        self.assert_context_kept(crlf.text, CONTEXT_BEFORE_SHORT, CONTEXT_AFTER_SHORT)
        if "Proc-Type" in crlf.text or FAKE_DEK_IV in crlf.text:
            self.fail("CRLF encrypted PEM was not fully cleared")
        self.assertTrue(crlf.clean)

    def test_uncertain_pem_block_end_is_reported_not_marked_clean(self) -> None:
        source = "%s\n-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\n%s" % (
            CONTEXT_BEFORE_SHORT,
            CONTEXT_AFTER_SHORT,
        )
        result = redact_text(source)
        self.assert_no_leak(result.text, result.residual_gaps)
        self.assert_context_kept(result.text, CONTEXT_BEFORE_SHORT, CONTEXT_AFTER_SHORT)
        if "BEGIN " in result.text.upper() and "PRIVATE KEY" in result.text.upper():
            self.fail("header-only PEM begin line remained")
        if "Proc-Type" in result.text:
            self.fail("header-only PEM bag header remained")
        if result.clean or not result.residual_gaps:
            self.fail("uncertain private-key block end was marked clean")
        self.assert_no_leak(*result.residual_gaps)

    def test_pgp_private_key_block_is_redacted(self) -> None:
        source = "%s\n%s\n%s" % (CONTEXT_BEFORE_SHORT, FAKE_PGP, CONTEXT_AFTER_SHORT)
        result = redact_text(source)
        self.assert_no_leak(result.text, result.residual_gaps)
        self.assert_context_kept(result.text, CONTEXT_BEFORE_SHORT, CONTEXT_AFTER_SHORT)
        if "PGP PRIVATE KEY" in result.text.upper() or "BEGIN PGP" in result.text.upper():
            self.fail("PGP private key armor remained after redaction")
        self.assertTrue(result.changed)
        self.assertTrue(result.clean)
        if contains_residual_credentials(result.text):
            self.fail("recheck still found a PGP private-key fragment")

        incomplete = "%s\n-----BEGIN PGP PRIVATE KEY BLOCK-----\nVersion: GnuPG v1\n\n%s\n%s\n%s" % (
            CONTEXT_BEFORE_SHORT,
            FAKE_PEM_BODY_1,
            FAKE_PEM_BODY_2,
            CONTEXT_AFTER_SHORT,
        )
        leftover = redact_text(incomplete)
        self.assert_no_leak(leftover.text, leftover.residual_gaps)
        self.assert_context_kept(leftover.text, CONTEXT_BEFORE_SHORT, CONTEXT_AFTER_SHORT)
        if "BEGIN PGP" in leftover.text.upper() or "Version: GnuPG" in leftover.text:
            self.fail("incomplete PGP private key was not fully cleared")
        self.assertTrue(leftover.clean)

    def test_credentialed_url_is_redacted_ordinary_url_is_kept(self) -> None:
        source = "%s 数据库：%s 文档：%s 接口：%s。%s" % (
            CONTEXT_BEFORE,
            FAKE_DB_URI,
            HARMLESS_URL,
            FAKE_HTTPS_URI,
            CONTEXT_AFTER,
        )
        result = redact_text(source)
        self.assert_no_leak(result.text, result.residual_gaps)
        self.assert_context_kept(result.text)
        if HARMLESS_URL not in result.text:
            self.fail("a harmless URL was removed")
        self.assertIn("postgres://%s@db.example.test:5432/appdb" % PLACEHOLDER, result.text)
        self.assertIn("https://%s@api.example.test/v1" % PLACEHOLDER, result.text)
        self.assertIn(NOTE, result.text)

    def test_empty_username_credential_uris_are_redacted(self) -> None:
        uris = (
            "redis://:%s@redis.example.test:6379/0" % FAKE_PASSWORD,
            "rediss://:%s@redis.example.test:6379/0" % FAKE_PASSWORD,
            "mysql://:%s@db.example.test:3306/app" % FAKE_PASSWORD,
            "postgres://:%s@db.example.test:5432/appdb" % FAKE_PASSWORD,
        )
        source = "%s %s 文档 %s %s" % (
            CONTEXT_BEFORE,
            " ".join(uris),
            HARMLESS_URL,
            CONTEXT_AFTER,
        )
        result = redact_text(source)
        self.assert_no_leak(result.text, result.residual_gaps)
        self.assert_context_kept(result.text)
        if HARMLESS_URL not in result.text:
            self.fail("a harmless URL was removed")
        for scheme, host in (
            ("redis", "redis.example.test:6379/0"),
            ("rediss", "redis.example.test:6379/0"),
            ("mysql", "db.example.test:3306/app"),
            ("postgres", "db.example.test:5432/appdb"),
        ):
            expected = "%s://%s@%s" % (scheme, PLACEHOLDER, host)
            if expected not in result.text:
                self.fail("empty-username credential URI was not locally redacted")
        self.assertTrue(result.changed)
        self.assertTrue(result.clean)
        if contains_residual_credentials(result.text):
            self.fail("recheck missed a supported credential URI")
        again = redact_text(result.text)
        if again.text != result.text or again.changed:
            self.fail("empty-username URI redaction was not idempotent")

    def test_password_assignment_and_jwt_are_redacted(self) -> None:
        source = '%s db_password="%s" jwt=%s %s' % (
            CONTEXT_BEFORE,
            FAKE_PASSWORD,
            FAKE_JWT,
            CONTEXT_AFTER,
        )
        result = redact_text(source)
        self.assert_no_leak(result.text, result.residual_gaps)
        self.assert_context_kept(result.text)
        self.assertIn('db_password="%s"' % PLACEHOLDER, result.text)

    def test_redaction_is_idempotent(self) -> None:
        source = "%s %s %s %s" % (CONTEXT_BEFORE, FAKE_TOKEN, FAKE_DB_URI, CONTEXT_AFTER)
        first = redact_text(source)
        second = redact_text(first.text)
        self.assert_no_leak(first.text, second.text, second.residual_gaps)
        if first.text != second.text:
            self.fail("second pass changed already-redacted text")
        if second.changed:
            self.fail("second pass reported a change on already-redacted text")
        self.assertTrue(second.clean)

    def test_recheck_after_redaction_is_clean(self) -> None:
        source = "\n".join(
            [CONTEXT_BEFORE, FAKE_PEM, FAKE_TOKEN, FAKE_DB_URI, HARMLESS_URL, CONTEXT_AFTER]
        )
        result = redact_text(source)
        self.assert_no_leak(result.text, result.residual_gaps)
        self.assert_context_kept(result.text)
        if contains_residual_credentials(result.text):
            self.fail("recheck still found a suspected fragment after redaction")
        self.assertTrue(result.clean)
        self.assertEqual(result.residual_gaps, [])
        if HARMLESS_URL not in result.text:
            self.fail("a harmless URL was removed during mixed-source redaction")

    def test_title_is_redacted_or_resummarized_without_blocking(self) -> None:
        mixed = "整理知识库并检查 %s" % FAKE_TOKEN
        redacted = redact_title(mixed)
        self.assert_no_leak(redacted)
        if "整理知识库并检查" not in redacted:
            self.fail("title context was dropped instead of locally redacted")
        self.assertIn(NOTE, redacted)
        only_secret = redact_title(FAKE_TOKEN)
        self.assert_no_leak(only_secret)
        if only_secret != "已重新概括（%s）" % NOTE:
            self.fail("a title that was only a credential was not re-summarized")

    def test_errors_do_not_echo_secrets(self) -> None:
        try:
            redact_text(None)  # type: ignore[arg-type]
        except RedactionError as exc:
            self.assert_no_leak(exc, str(exc))
        else:
            self.fail("expected RedactionError for missing text")


class SnapshotStoreTests(SecretSafeTestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.store = SnapshotStore(self.root)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _read(self, path: Path) -> str:
        return path.read_text(encoding="utf-8")

    def test_import_redacts_before_write_and_keeps_pending_status(self) -> None:
        source = "%s 令牌 %s 文档 %s。%s" % (
            CONTEXT_BEFORE,
            FAKE_TOKEN,
            HARMLESS_URL,
            CONTEXT_AFTER,
        )
        result = self.store.import_text(
            "reference:sample-alpha",
            source,
            title="整理知识库 %s" % FAKE_TOKEN,
        )
        saved = self._read(result.path)
        state = self.store.state_path.read_text(encoding="utf-8")
        self.assert_tree_clean(
            self.root,
            result.path,
            result.title,
            result.action,
            result.ingest_status,
            result.review_status,
            result.content_hash,
            result.source_index,
            result.gaps,
            saved,
            state,
        )
        self.assert_context_kept(saved)
        if HARMLESS_URL not in saved:
            self.fail("a harmless URL was not kept in the snapshot")
        self.assertEqual(result.action, "created")
        self.assertEqual(result.ingest_status, INGEST_COLLECTED)
        self.assertEqual(result.review_status, REVIEW_PENDING)
        self.assertNotEqual(result.review_status, REVIEW_DONE)
        if FAKE_TOKEN in result.path.name:
            self.fail("filename contained a fictional credential")

    def test_repeat_import_is_deduplicated(self) -> None:
        source = "%s %s %s" % (CONTEXT_BEFORE, FAKE_TOKEN, CONTEXT_AFTER)
        first = self.store.import_text("reference:sample-beta", source, title="去重测试")
        first_bytes = first.path.read_bytes()
        first_mtime = first.path.stat().st_mtime_ns
        second = self.store.import_text("reference:sample-beta", source, title="去重测试")
        self.assert_tree_clean(self.root, first.path, second.path, self._read(first.path))
        if second.action != "duplicate":
            self.fail("repeat import did not report a duplicate")
        if first.path != second.path:
            self.fail("repeat import pointed at a different snapshot")
        if first.path.read_bytes() != first_bytes:
            self.fail("repeat import changed the existing snapshot bytes")
        if first.path.stat().st_mtime_ns != first_mtime:
            self.fail("repeat import rewrote the existing snapshot")
        versions = self.store.source_record("reference:sample-beta")["versions"]
        if len(versions) != 1:
            self.fail("repeat import added an extra version record")

    def test_changed_content_writes_new_version_without_overwriting_old(self) -> None:
        first_source = "%s 第一版 %s %s" % (CONTEXT_BEFORE, FAKE_TOKEN, CONTEXT_AFTER)
        first = self.store.import_text("reference:sample-gamma", first_source, title="版本一")
        old_bytes = first.path.read_bytes()
        old_name = first.path.name
        old_mtime = first.path.stat().st_mtime_ns
        # A pre-existing orphan with the would-be v2 name must also be left intact.
        orphan = first.path.with_name(first.path.stem + "--v2" + first.path.suffix)
        orphan.write_text("orphan-read-only\n", encoding="utf-8")
        orphan_bytes = orphan.read_bytes()

        second_source = "%s 第二版 %s 文档 %s。%s" % (
            CONTEXT_BEFORE,
            FAKE_DB_URI,
            HARMLESS_URL,
            CONTEXT_AFTER,
        )
        second = self.store.import_text("reference:sample-gamma", second_source, title="版本二")
        self.assert_tree_clean(
            self.root,
            first.path,
            second.path,
            orphan,
            self._read(first.path),
            self._read(second.path),
            self.store.state_path.read_text(encoding="utf-8"),
        )
        if second.action != "new_version":
            self.fail("changed content was not stored as a new version")
        if second.path == first.path:
            self.fail("new version reused the old snapshot path")
        if first.path.read_bytes() != old_bytes:
            self.fail("old snapshot bytes were changed")
        if first.path.stat().st_mtime_ns != old_mtime:
            self.fail("old snapshot was rewritten")
        if first.path.name != old_name:
            self.fail("old snapshot was renamed")
        if orphan.read_bytes() != orphan_bytes:
            self.fail("an existing file was overwritten when choosing a new version path")
        if second.path == orphan:
            self.fail("new version overwrote an existing file")
        self.assert_context_kept(self._read(second.path))
        if HARMLESS_URL not in self._read(second.path):
            self.fail("a harmless URL was not kept in the new version")

    def test_short_summary_is_partial_not_complete(self) -> None:
        source = "%s %s %s" % (CONTEXT_BEFORE, FAKE_TOKEN, CONTEXT_AFTER)
        imported = self.store.import_text("reference:sample-delta", source, title="摘要状态")
        update = self.store.record_partial_distill(
            "reference:sample-delta",
            "用户明确表达需要局部脱敏；助手历史报告已安装不能当作复核。令牌 %s" % FAKE_TOKEN,
        )
        record = self.store.source_record("reference:sample-delta")
        self.assert_tree_clean(
            self.root,
            imported.path,
            update,
            record,
            self.store.state_path.read_text(encoding="utf-8"),
        )
        if update["review_status"] != REVIEW_PARTIAL:
            self.fail("a short summary was not recorded as 部分提炼")
        if record["review_status"] == REVIEW_DONE:
            self.fail("a short summary marked the source as 已整理")
        if record["ingest_status"] != INGEST_COLLECTED:
            self.fail("ingest status was not kept as 已采集")
        if _leaks(str(record.get("partial_summary"))):
            self.fail("partial summary leaked a fictional credential; value omitted")

    def test_source_key_metadata_is_hashed_and_absent_from_tree(self) -> None:
        cases = (
            ("uri", FAKE_DB_URI, "普通标题"),
            ("token", "cursor:%s" % FAKE_TOKEN, "普通标题"),
        )
        for label, source_key, title in cases:
            with self.subTest(label=label):
                tmp = tempfile.TemporaryDirectory()
                try:
                    root = Path(tmp.name)
                    store = SnapshotStore(root)
                    result = store.import_text(source_key, "前文 后文", title=title)
                    state = store.state_path.read_text(encoding="utf-8")
                    saved = self._read(result.path)
                    expected_index = source_index_key(source_key)
                    self.assert_tree_clean(
                        root,
                        result.path,
                        result.title,
                        result.source_index,
                        result.gaps,
                        saved,
                        state,
                        list(store._load_state()["sources"].keys()),
                    )
                    if expected_index != result.source_index:
                        self.fail("source index was not the irreversible digest")
                    if expected_index not in state or expected_index not in saved:
                        self.fail("hashed source index was not recorded")
                    if source_key in state or source_key in saved or source_key in result.path.name:
                        self.fail("raw source_key was written to snapshot metadata")
                    if "前文" not in saved or "后文" not in saved:
                        self.fail("body context was not preserved")
                finally:
                    tmp.cleanup()

    def test_source_hashes_avoid_collision_and_preserve_versions(self) -> None:
        first = self.store.import_text(FAKE_DB_URI, "前文 第一份 后文", title="碰撞一")
        second = self.store.import_text(FAKE_DB_URI_2, "前文 第一份 后文", title="碰撞二")
        if first.action != "created" or second.action != "created":
            self.fail("distinct credentialed source keys were collapsed")
        if first.source_index == second.source_index:
            self.fail("distinct source keys produced the same index")
        if first.path == second.path:
            self.fail("distinct source keys shared a snapshot path")

        first_bytes = first.path.read_bytes()
        first_name = first.path.name
        first_mtime = first.path.stat().st_mtime_ns
        same = self.store.import_text(FAKE_DB_URI, "前文 第一份 后文", title="碰撞一")
        if same.action != "duplicate" or same.path != first.path:
            self.fail("repeat import of the same source key was not deduplicated")
        if first.path.read_bytes() != first_bytes or first.path.name != first_name:
            self.fail("dedup of a hashed source key changed the old snapshot")

        updated = self.store.import_text(FAKE_DB_URI, "前文 第二份 %s 后文" % HARMLESS_URL, title="碰撞一新版")
        if updated.action != "new_version":
            self.fail("changed content for the same source key was not a new version")
        if updated.path == first.path:
            self.fail("new version reused the old snapshot path")
        if first.path.read_bytes() != first_bytes or first.path.stat().st_mtime_ns != first_mtime:
            self.fail("creating a new version overwrote the old snapshot")
        if first.path.name != first_name:
            self.fail("old snapshot was renamed")
        saved_new = self._read(updated.path)
        if HARMLESS_URL not in saved_new or "前文" not in saved_new or "后文" not in saved_new:
            self.fail("new version did not keep context or the harmless URL")
        records = self.store._load_state()["sources"]
        if len(records) != 2:
            self.fail("hashed source indexes did not keep distinct sources")
        first_versions = self.store.source_record(FAKE_DB_URI)["versions"]
        if len(first_versions) != 2:
            self.fail("new version was not recorded under the same hashed source")
        self.assert_tree_clean(
            self.root,
            first.path,
            second.path,
            updated.path,
            first.source_index,
            second.source_index,
            updated.source_index,
        )

    def test_io_errors_do_not_echo_source_secrets_or_claim_success(self) -> None:
        source_key = "cursor:%s" % FAKE_TOKEN

        def exploding_mkdir(*_args, **_kwargs):
            raise OSError("cannot create %s" % source_key)

        with mock.patch.object(Path, "mkdir", exploding_mkdir):
            try:
                self.store.import_text(source_key, "前文 后文", title="普通标题")
            except SnapshotError as exc:
                self.assert_no_leak(exc, str(exc), repr(exc), getattr(exc, "__cause__", None))
            else:
                self.fail("directory creation failure was swallowed")

        def exploding_open(*_args, **_kwargs):
            raise OSError("cannot write %s" % source_key)

        with mock.patch.object(Path, "open", exploding_open):
            try:
                self.store.import_text(source_key, "前文 后文", title="普通标题")
            except SnapshotError as exc:
                self.assert_no_leak(exc, str(exc), repr(exc), getattr(exc, "__cause__", None))
            else:
                self.fail("write failure was swallowed")
        self.assert_tree_clean(self.root)


if __name__ == "__main__":
    unittest.main()
