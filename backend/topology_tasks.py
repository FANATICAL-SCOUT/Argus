"""SSE task registry for network topology discovery jobs."""
from __future__ import annotations

import queue
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class TopologyTask:
    task_id: str
    subnet: str
    created_at: float = field(default_factory=time.monotonic)
    events: queue.Queue = field(default_factory=lambda: queue.Queue(maxsize=5_000))
    done: bool = False


_tasks: dict[str, TopologyTask] = {}


def create_topology_task(subnet: str) -> TopologyTask:
    task_id = str(uuid.uuid4())
    task = TopologyTask(task_id=task_id, subnet=subnet)
    _tasks[task_id] = task
    return task


def get_topology_task(task_id: str) -> Optional[TopologyTask]:
    return _tasks.get(task_id)
