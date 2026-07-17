"""Immutable request-package and conversational supplement snapshots."""

from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import re
import shutil
import tempfile
import threading
from pathlib import Path, PurePosixPath

from agentsectool_scanner.paths import DERIVATION_ARTIFACTS

from .repository import (
    DerivationConflictError,
    DerivationRepository,
    canonical_json,
    new_id,
    utc_now,
)

MAX_TEXT_FILE_BYTES = 8 * 1024 * 1024
MAX_AUXILIARY_FILE_BYTES = 32 * 1024 * 1024
MAX_SUPPLEMENT_BYTES = 32 * 1024 * 1024
DOCUMENT_SUFFIXES = {".html", ".htm", ".md", ".markdown", ".txt"}
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class PackageValidationError(ValueError):
    """Raised when a package cannot be snapshotted safely."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def media_type(path: str) -> str:
    return mimetypes.guess_type(path)[0] or "application/octet-stream"


def _package_hash(manifest: dict, artifacts: list[dict]) -> str:
    inventory = [
        {
            "relative_path": item["relative_path"],
            "role": item["role"],
            "kind": item.get("kind"),
            "sha256": item["sha256"],
            "size_bytes": item["size_bytes"],
        }
        for item in sorted(artifacts, key=lambda value: value["relative_path"])
    ]
    value = {"manifest": manifest, "inventory": inventory}
    return sha256_bytes(canonical_json(value).encode("utf-8"))


def _safe_manifest_path(root: Path, relative_path: object) -> tuple[str, Path]:
    if not isinstance(relative_path, str) or not relative_path.strip():
        raise PackageValidationError("manifest 中存在空文件路径")
    if "\\" in relative_path:
        raise PackageValidationError(f"文件路径必须使用 /：{relative_path}")
    pure = PurePosixPath(relative_path)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise PackageValidationError(f"文件路径不是安全相对路径：{relative_path}")
    normalized = pure.as_posix()
    candidate = root.joinpath(*pure.parts)
    if candidate.is_symlink():
        raise PackageValidationError(f"需求包不接受符号链接：{normalized}")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise PackageValidationError(f"manifest 登记的文件不存在：{normalized}") from exc
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise PackageValidationError(f"文件路径越出需求包目录：{normalized}") from exc
    if not resolved.is_file():
        raise PackageValidationError(f"manifest 登记项不是普通文件：{normalized}")
    return normalized, resolved


def _require_utf8(path: Path, relative_path: str) -> None:
    try:
        path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise PackageValidationError(f"代码和主文档必须为 UTF-8 文本：{relative_path}") from exc


class RequestPackageImporter:
    def __init__(
        self,
        repository: DerivationRepository,
        artifacts_root: str | Path = DERIVATION_ARTIFACTS,
    ):
        self.repository = repository
        self.artifacts_root = Path(artifacts_root)
        self._import_lock = threading.Lock()

    def preview(self, package_path: str | Path) -> dict:
        root = Path(package_path).expanduser().resolve()
        if not root.is_dir():
            raise PackageValidationError(f"需求包目录不存在：{root}")
        manifest_path = root / "manifest.json"
        if manifest_path.is_symlink() or not manifest_path.is_file():
            raise PackageValidationError("需求包根目录缺少普通文件 manifest.json")
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PackageValidationError(f"manifest.json 不是有效的 UTF-8 JSON：{exc}") from exc
        if not isinstance(manifest, dict):
            raise PackageValidationError("manifest.json 顶层必须为对象")
        self._validate_manifest_shape(manifest)

        registered: list[tuple[str, str, str | None]] = []
        for item in manifest["code_files"]:
            registered.append((item, "code", None))
        registered.append((manifest["document_file"], "document", None))
        for item in manifest.get("auxiliary_files", []):
            registered.append((item["path"], "auxiliary", item["kind"]))

        artifacts: list[dict] = []
        seen: set[str] = set()
        for raw_path, role, kind in registered:
            relative_path, path = _safe_manifest_path(root, raw_path)
            if relative_path == "manifest.json":
                raise PackageValidationError("manifest.json 不能同时登记为分析材料")
            if relative_path in seen:
                raise PackageValidationError(f"manifest 中重复登记文件：{relative_path}")
            seen.add(relative_path)
            size = path.stat().st_size
            limit = MAX_AUXILIARY_FILE_BYTES if role == "auxiliary" else MAX_TEXT_FILE_BYTES
            if size > limit:
                raise PackageValidationError(f"文件超过 {limit} 字节限制：{relative_path}")
            if role in {"code", "document"}:
                _require_utf8(path, relative_path)
            artifacts.append({
                "relative_path": relative_path,
                "source_path": str(path),
                "role": role,
                "kind": kind,
                "sha256": sha256_file(path),
                "size_bytes": size,
                "media_type": media_type(relative_path),
            })

        listed = seen | {"manifest.json"}
        unlisted = []
        for path in sorted(root.rglob("*")):
            if path.is_file() or path.is_symlink():
                relative = path.relative_to(root).as_posix()
                if relative not in listed:
                    unlisted.append(relative)
        package_hash = _package_hash(manifest, artifacts)
        return {
            "source_path": str(root),
            "request_id": manifest["request_id"],
            "manifest": manifest,
            "package_hash": package_hash,
            "artifacts": artifacts,
            "unlisted_files": unlisted,
        }

    def import_package(
        self, package_path: str | Path, expected_hash: str | None = None
    ) -> dict:
        preview = self.preview(package_path)
        if expected_hash and expected_hash != preview["package_hash"]:
            raise DerivationConflictError("需求包在预览后发生变化，请重新预览")
        with self._import_lock:
            existing = self.repository.source_for_request(preview["request_id"])
            if existing:
                if existing["package_hash"] != preview["package_hash"]:
                    raise DerivationConflictError(
                        f"request_id {preview['request_id']!r} 已对应另一份需求包"
                    )
                return self.repository.get_task(existing["task_id"])

            target = (
                self.artifacts_root
                / "source"
                / f"{preview['request_id']}-{preview['package_hash'][:12]}"
            )
            copied = self._copy_source_snapshot(preview, target)
            try:
                return self.repository.create_source_task(
                    request_id=preview["request_id"],
                    package_hash=preview["package_hash"],
                    manifest=preview["manifest"],
                    source_path=preview["source_path"],
                    storage_path=str(target),
                    artifacts=copied,
                )
            except Exception:
                shutil.rmtree(target, ignore_errors=True)
                raise

    @staticmethod
    def _validate_manifest_shape(manifest: dict) -> None:
        if manifest.get("schema_version") != "1.0":
            raise PackageValidationError("manifest.schema_version 必须为 1.0")
        request_id = manifest.get("request_id")
        if not isinstance(request_id, str) or not REQUEST_ID_RE.fullmatch(request_id):
            raise PackageValidationError("manifest.request_id 格式无效")
        code_files = manifest.get("code_files")
        if not isinstance(code_files, list) or not code_files or not all(
            isinstance(item, str) for item in code_files
        ):
            raise PackageValidationError("manifest.code_files 必须是非空字符串数组")
        document = manifest.get("document_file")
        if not isinstance(document, str) or Path(document).suffix.lower() not in DOCUMENT_SUFFIXES:
            raise PackageValidationError("主文档必须是 HTML、Markdown 或纯文本")
        auxiliary = manifest.get("auxiliary_files", [])
        if not isinstance(auxiliary, list):
            raise PackageValidationError("manifest.auxiliary_files 必须为数组")
        for item in auxiliary:
            if (
                not isinstance(item, dict)
                or not isinstance(item.get("path"), str)
                or not isinstance(item.get("kind"), str)
                or not item["kind"].strip()
            ):
                raise PackageValidationError("每个辅助文件必须包含 path 和 kind")

    def _copy_source_snapshot(self, preview: dict, target: Path) -> list[dict]:
        if target.exists():
            raise DerivationConflictError(f"需求快照目录已存在但未登记：{target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        temp = Path(tempfile.mkdtemp(prefix=".source-", dir=target.parent))
        copied: list[dict] = []
        try:
            (temp / "manifest.json").write_text(
                json.dumps(preview["manifest"], ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            for artifact in preview["artifacts"]:
                destination = temp / artifact["relative_path"]
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(artifact["source_path"], destination)
                if sha256_file(destination) != artifact["sha256"]:
                    raise DerivationConflictError(
                        f"复制期间文件内容发生变化：{artifact['relative_path']}"
                    )
                item = {key: value for key, value in artifact.items() if key != "source_path"}
                item["storage_path"] = str(target / artifact["relative_path"])
                copied.append(item)
            snapshot = {
                "schema_version": "1.0",
                "package_hash": preview["package_hash"],
                "captured_at": utc_now(),
                "source_path": preview["source_path"],
                "inventory": [
                    {key: value for key, value in item.items() if key != "storage_path"}
                    for item in copied
                ],
                "unlisted_files": preview["unlisted_files"],
            }
            (temp / "snapshot.json").write_text(
                json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            os.replace(temp, target)
            return copied
        except Exception:
            shutil.rmtree(temp, ignore_errors=True)
            raise


class SupplementPackageBuilder:
    def __init__(
        self,
        repository: DerivationRepository,
        artifacts_root: str | Path = DERIVATION_ARTIFACTS,
    ):
        self.repository = repository
        self.artifacts_root = Path(artifacts_root)

    def create(self, task_id: str, uploads: list[dict]) -> dict:
        if not uploads:
            raise PackageValidationError("补充包至少包含一个文件")
        total = 0
        names: set[str] = set()
        prepared = []
        for upload in uploads:
            raw_name = upload.get("filename")
            content = upload.get("content")
            kind = str(upload.get("kind") or "user_attachment").strip()
            if not isinstance(raw_name, str) or not raw_name.strip():
                raise PackageValidationError("附件缺少文件名")
            if not isinstance(content, bytes):
                raise PackageValidationError("附件内容必须为字节数据")
            filename = Path(raw_name).name
            if filename != raw_name or filename in {"", ".", ".."}:
                raise PackageValidationError(f"附件文件名无效：{raw_name}")
            if filename in names:
                raise PackageValidationError(f"一条消息中存在重名附件：{filename}")
            names.add(filename)
            total += len(content)
            if total > MAX_SUPPLEMENT_BYTES:
                raise PackageValidationError("单个补充包总大小不能超过 32 MiB")
            prepared.append({
                "relative_path": filename,
                "role": "attachment",
                "kind": kind,
                "content": content,
                "sha256": sha256_bytes(content),
                "size_bytes": len(content),
                "media_type": media_type(filename),
            })
        manifest = {
            "schema_version": "1.0",
            "supplement_id": new_id("supplement_manifest"),
            "files": [
                {
                    "path": item["relative_path"],
                    "kind": item["kind"],
                    "sha256": item["sha256"],
                    "size_bytes": item["size_bytes"],
                }
                for item in prepared
            ],
        }
        hashed = [
            {key: value for key, value in item.items() if key != "content"}
            for item in prepared
        ]
        package_hash = _package_hash(manifest, hashed)
        target = self.artifacts_root / "supplement" / task_id / package_hash[:16]
        if target.exists():
            raise DerivationConflictError("相同补充包已存在")
        target.parent.mkdir(parents=True, exist_ok=True)
        temp = Path(tempfile.mkdtemp(prefix=".supplement-", dir=target.parent))
        try:
            persisted = []
            for item in prepared:
                destination = temp / item["relative_path"]
                destination.write_bytes(item["content"])
                metadata = {key: value for key, value in item.items() if key != "content"}
                metadata["storage_path"] = str(target / item["relative_path"])
                persisted.append(metadata)
            (temp / "manifest.json").write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            os.replace(temp, target)
            return self.repository.create_supplement(
                task_id=task_id,
                package_hash=package_hash,
                manifest=manifest,
                storage_path=str(target),
                artifacts=persisted,
            )
        except Exception:
            shutil.rmtree(temp, ignore_errors=True)
            shutil.rmtree(target, ignore_errors=True)
            raise
