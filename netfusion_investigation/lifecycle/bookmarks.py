"""
NETFUSION IL-10: Enterprise Investigation Lifecycle Manager - Bookmark Manager

Module to manage analyst bookmarks across timeline events, evidence, graph nodes,
reasoning steps, reports, and recommendations.
"""

from datetime import datetime, timezone
import threading
from typing import Dict, List, Optional, Union
import uuid

from netfusion_investigation.lifecycle.models import Bookmark, BookmarkType


class BookmarkManager:
    """Manages bookmarks associated with investigations."""

    def __init__(self):
        self._bookmarks: Dict[str, Bookmark] = {}
        self._lock = threading.RLock()

    def add_bookmark(
        self,
        investigation_id: str,
        bookmark_type: Union[BookmarkType, str],
        target_id: str,
        title: str,
        notes: str = "",
        created_by: str = "analyst",
    ) -> Bookmark:
        with self._lock:
            bm_enum = bookmark_type if isinstance(bookmark_type, BookmarkType) else BookmarkType(bookmark_type)
            bm = Bookmark(
                id=f"bm-{uuid.uuid4().hex[:12]}",
                investigation_id=investigation_id,
                bookmark_type=bm_enum,
                target_id=target_id,
                title=title,
                notes=notes,
                created_by=created_by,
                created_at=datetime.now(timezone.utc).isoformat(),
            )
            self._bookmarks[bm.id] = bm
            return bm

    def remove_bookmark(self, bookmark_id: str) -> bool:
        with self._lock:
            if bookmark_id in self._bookmarks:
                del self._bookmarks[bookmark_id]
                return True
            return False

    def get_bookmark(self, bookmark_id: str) -> Optional[Bookmark]:
        with self._lock:
            return self._bookmarks.get(bookmark_id)

    def get_bookmarks(
        self,
        investigation_id: str,
        bookmark_type: Optional[Union[BookmarkType, str]] = None,
    ) -> List[Bookmark]:
        with self._lock:
            res = [b for b in self._bookmarks.values() if b.investigation_id == investigation_id]
            if bookmark_type:
                target_type = bookmark_type.value if isinstance(bookmark_type, BookmarkType) else bookmark_type
                res = [b for b in res if b.bookmark_type.value == target_type or b.bookmark_type == target_type]
            res.sort(key=lambda x: x.created_at)
            return res

    def clear_bookmarks(self, investigation_id: str) -> int:
        with self._lock:
            to_remove = [bid for bid, b in self._bookmarks.items() if b.investigation_id == investigation_id]
            for bid in to_remove:
                del self._bookmarks[bid]
            return len(to_remove)
