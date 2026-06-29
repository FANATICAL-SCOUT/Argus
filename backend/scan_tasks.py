"""In-memory scan task registry for SSE streaming."""
from __future__ import annotations

import queue
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

_TASK_TTL = 3600  # seconds; prune completed tasks older than this


@dataclass
class ScanTask:
    task_id: str
    target: str
    start_port: int
    end_port: int
    created_at: float = field(default_factory=time.monotonic)
    events: queue.Queue = field(default_factory=lambda: queue.Queue(maxsize=20_000))
    db_id: Optional[int] = None
    done: bool = False


_tasks: dict[str, ScanTask] = {}
_lock = threading.Lock()


def create_task(target: str, start_port: int, end_port: int) -> ScanTask:
    _prune_old()
    tid = str(uuid.uuid4())
    task = ScanTask(task_id=tid, target=target, start_port=start_port, end_port=end_port)
    with _lock:
        _tasks[tid] = task
    return task


def get_task(task_id: str) -> Optional[ScanTask]:
    return _tasks.get(task_id)


def _prune_old() -> None:
    cutoff = time.monotonic() - _TASK_TTL
    with _lock:
        stale = [tid for tid, t in _tasks.items() if t.done and t.created_at < cutoff]
        for tid in stale:
            del _tasks[tid]
