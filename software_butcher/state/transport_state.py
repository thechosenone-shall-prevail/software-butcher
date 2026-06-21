"""Per-host transport state — backoff timers, egress rotation, rate-limit memory."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from software_butcher.shelves.web.infrastructure_intel import RateLimitSignal


@dataclass
class HostTransportState:
    rate_limit_events: int = 0
    backoff_until: float = 0.0
    last_action: str = ""
    proxy_index: int = 0
    egress_rotations: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "rate_limit_events": self.rate_limit_events,
            "backoff_until": self.backoff_until,
            "last_action": self.last_action,
            "proxy_index": self.proxy_index,
            "egress_rotations": self.egress_rotations,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "HostTransportState":
        return cls(
            rate_limit_events=int(data.get("rate_limit_events") or 0),
            backoff_until=float(data.get("backoff_until") or 0.0),
            last_action=str(data.get("last_action") or ""),
            proxy_index=int(data.get("proxy_index") or 0),
            egress_rotations=int(data.get("egress_rotations") or 0),
        )


@dataclass
class TransportState:
    hosts: dict[str, HostTransportState] = field(default_factory=dict)
    global_proxy_index: int = 0

    def host(self, host: str) -> HostTransportState:
        key = host.lower()
        if key not in self.hosts:
            self.hosts[key] = HostTransportState()
        return self.hosts[key]

    def wait_seconds(self, host: str) -> float:
        state = self.host(host)
        now = time.monotonic()
        if state.backoff_until > now:
            return state.backoff_until - now
        return 0.0

    def apply_wait(self, host: str) -> float:
        delay = self.wait_seconds(host)
        if delay > 0:
            time.sleep(delay)
        return delay

    def record_rate_limit(self, host: str, signal: RateLimitSignal) -> None:
        state = self.host(host)
        state.rate_limit_events += 1
        wait_s = signal.retry_after_s or 10.0
        state.backoff_until = time.monotonic() + wait_s
        state.last_action = signal.recommended_action

    def should_rotate_egress(self, host: str) -> bool:
        state = self.host(host)
        return state.rate_limit_events >= 2 or state.last_action == "rotate_egress"

    def record_rotation(self, host: str) -> None:
        state = self.host(host)
        state.egress_rotations += 1
        self.global_proxy_index += 1
        state.proxy_index = self.global_proxy_index
        state.backoff_until = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "hosts": {k: v.to_dict() for k, v in self.hosts.items()},
            "global_proxy_index": self.global_proxy_index,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TransportState":
        hosts = {
            k: HostTransportState.from_dict(v)
            for k, v in (data.get("hosts") or {}).items()
        }
        return cls(hosts=hosts, global_proxy_index=int(data.get("global_proxy_index") or 0))
