"""
NETFUSION IL-10: Enterprise Investigation Lifecycle Manager - Artifact Manager

Module to manage investigation artifacts including reports, evidence, PCAPs, screenshots,
JSON/CSV/HTML/PDF/Markdown documents, with SHA-256 integrity verification.
"""

from datetime import datetime, timezone
import hashlib
import os
import threading
from typing import Any, Dict, List, Optional, Union
import uuid

from netfusion_investigation.lifecycle.models import Artifact, ArtifactType


class ArtifactManager:
    """Stores, manages, and retrieves investigation artifacts."""

    def __init__(self, storage_dir: Optional[str] = None):
        self._storage_dir = storage_dir or os.path.join(os.getcwd(), "data", "artifacts")
        os.makedirs(self._storage_dir, exist_ok=True)
        self._artifacts: Dict[str, Artifact] = {}
        self._lock = threading.RLock()

    def _compute_sha256(self, content: Union[str, bytes]) -> str:
        data_bytes = content.encode("utf-8") if isinstance(content, str) else content
        return hashlib.sha256(data_bytes).hexdigest()

    def store_artifact(
        self,
        investigation_id: str,
        name: str,
        artifact_type: Union[ArtifactType, str],
        content: Union[str, bytes],
        mime_type: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Artifact:
        with self._lock:
            art_enum = artifact_type if isinstance(artifact_type, ArtifactType) else ArtifactType(artifact_type)
            content_bytes = content.encode("utf-8") if isinstance(content, str) else content
            checksum = self._compute_sha256(content_bytes)
            art_id = f"art-{uuid.uuid4().hex[:12]}"

            # Determine mime-type if not provided
            if not mime_type:
                mime_map = {
                    ArtifactType.REPORT: "application/json",
                    ArtifactType.EVIDENCE: "application/json",
                    ArtifactType.SCREENSHOT: "image/png",
                    ArtifactType.PCAP: "application/vnd.tcpdump.pcap",
                    ArtifactType.JSON: "application/json",
                    ArtifactType.CSV: "text/csv",
                    ArtifactType.HTML: "text/html",
                    ArtifactType.PDF: "application/pdf",
                    ArtifactType.MARKDOWN: "text/markdown",
                    ArtifactType.ATTACHMENT: "application/octet-stream",
                }
                mime_type = mime_map.get(art_enum, "application/octet-stream")

            # Persist content to disk
            safe_name = f"{art_id}_{name.replace('/', '_').replace('\\', '_')}"
            file_path = os.path.join(self._storage_dir, safe_name)
            with open(file_path, "wb") as f:
                f.write(content_bytes)

            artifact = Artifact(
                id=art_id,
                investigation_id=investigation_id,
                name=name,
                artifact_type=art_enum,
                file_path=file_path,
                mime_type=mime_type,
                checksum_sha256=checksum,
                size_bytes=len(content_bytes),
                metadata=metadata or {},
                created_at=datetime.now(timezone.utc).isoformat(),
                content=content,
            )

            self._artifacts[art_id] = artifact
            return artifact

    def get_artifact(self, artifact_id: str) -> Optional[Artifact]:
        with self._lock:
            artifact = self._artifacts.get(artifact_id)
            if artifact and artifact.content is None and artifact.file_path and os.path.exists(artifact.file_path):
                with open(artifact.file_path, "rb") as f:
                    content_bytes = f.read()
                    if artifact.mime_type.startswith("text/") or artifact.mime_type in ["application/json", "text/markdown"]:
                        artifact.content = content_bytes.decode("utf-8", errors="replace")
                    else:
                        artifact.content = content_bytes
            return artifact

    def list_artifacts(
        self,
        investigation_id: str,
        artifact_type: Optional[Union[ArtifactType, str]] = None,
    ) -> List[Artifact]:
        with self._lock:
            res = [a for a in self._artifacts.values() if a.investigation_id == investigation_id]
            if artifact_type:
                target_type = artifact_type.value if isinstance(artifact_type, ArtifactType) else artifact_type
                res = [a for a in res if a.artifact_type.value == target_type or a.artifact_type == target_type]
            res.sort(key=lambda x: x.created_at)
            return res

    def delete_artifact(self, artifact_id: str) -> bool:
        with self._lock:
            artifact = self._artifacts.get(artifact_id)
            if not artifact:
                return False
            if artifact.file_path and os.path.exists(artifact.file_path):
                try:
                    os.remove(artifact.file_path)
                except OSError:
                    pass
            del self._artifacts[artifact_id]
            return True

    def verify_artifact(self, artifact_id: str) -> bool:
        with self._lock:
            artifact = self.get_artifact(artifact_id)
            if not artifact or not artifact.file_path or not os.path.exists(artifact.file_path):
                return False
            with open(artifact.file_path, "rb") as f:
                data = f.read()
            computed = self._compute_sha256(data)
            return computed == artifact.checksum_sha256

    def clear(self) -> None:
        with self._lock:
            self._artifacts.clear()
