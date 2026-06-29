"""Domain dataclasses — the single source of truth for scan data structures."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


@dataclass
class Vulnerability:
    name: str
    cve: str
    description: str
    confirmed: bool = False


@dataclass
class PortResult:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str = "unknown"
    banner: str = ""
    vulnerabilities: List[Vulnerability] = field(default_factory=list)


@dataclass
class ScanMeta:
    target: str
    start_port: int
    end_port: int
    start_time: datetime
    end_time: Optional[datetime] = None
    duration: float = 0.0
    total_ports: int = 0
    open_count: int = 0


@dataclass
class ScanResult:
    meta: ScanMeta
    ports: List[PortResult] = field(default_factory=list)

    @property
    def open_ports(self) -> List[PortResult]:
        return [p for p in self.ports if p.state == "open"]
