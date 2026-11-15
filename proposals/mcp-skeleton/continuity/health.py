"""Automatic outage detection — so failover does not depend on a human declaring it.

The weakness in a manual "declare incident" switch is that the worst moments are exactly
when nobody has time to press it. This probe watches the identity plane and flips the mode
itself.

Design notes:
  * **Hysteresis on both edges.** Three consecutive failures to go degraded; two
    consecutive successes to come back. A single 502 must not start minting tokens.
  * **Multi-signal.** DNS, TLS and HTTP are checked separately: a DNS failure and an HTTP
    failure look identical to a boolean but need different responses.
  * **Injectable prober** so tests never touch the network.
  * **Every transition is audited** with the reason and the signal that caused it.
"""

import socket
import ssl
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional

PROBE_URL = "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration"
FAIL_THRESHOLD = 3
RECOVER_THRESHOLD = 2


def default_probe(url: str = PROBE_URL, timeout: float = 4.0) -> Dict[str, Any]:
    """One real check of the identity plane. Returns a signal report, never raises."""
    result = {"ok": False, "dns": None, "tls": None, "http": None, "detail": ""}
    host = "login.microsoftonline.com"

    try:
        socket.getaddrinfo(host, 443)
        result["dns"] = True
    except Exception as e:
        result["dns"] = False
        result["detail"] = f"dns: {e}"
        return result

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                ssock.getpeercert()
        result["tls"] = True
    except Exception as e:
        result["tls"] = False
        result["detail"] = f"tls: {e}"
        return result

    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            result["http"] = r.status == 200
            result["ok"] = bool(result["http"])
    except urllib.error.HTTPError as e:
        # A 4xx still proves the service is answering — that is not an outage.
        result["http"] = e.code < 500
        result["ok"] = result["http"]
        result["detail"] = f"http {e.code}"
    except Exception as e:
        result["http"] = False
        result["detail"] = f"http: {e}"

    return result


class HealthMonitor:
    """Drives ContinuityState.mode from probe results, with hysteresis on both edges."""

    def __init__(self, state: Any, prober: Optional[Callable[[], Dict[str, Any]]] = None,
                 fail_threshold: int = FAIL_THRESHOLD,
                 recover_threshold: int = RECOVER_THRESHOLD):
        self.state = state
        self.prober = prober or default_probe
        self.fail_threshold = fail_threshold
        self.recover_threshold = recover_threshold
        self.consecutive_failures = 0
        self.consecutive_successes = 0
        self.last_report: Dict[str, Any] = {}
        self.enabled = False          # opt-in: automatic mode changes
        self.history: List[Dict[str, Any]] = []

    def set_automatic(self, enabled: bool) -> Dict[str, Any]:
        self.enabled = bool(enabled)
        self.state.audit.append("auto_mode", enabled=self.enabled)
        return {"automatic": self.enabled, "mode": self.state.mode}

    def tick(self, now: Optional[float] = None) -> Dict[str, Any]:
        """Run one probe and react. Safe to call on a timer."""
        now = time.time() if now is None else now
        report = self.prober()
        self.last_report = report
        transition = None

        if report.get("ok"):
            self.consecutive_successes += 1
            self.consecutive_failures = 0
            if (self.enabled and self.state.mode == "degraded"
                    and self.consecutive_successes >= self.recover_threshold):
                self.state.set_mode("healthy", reason="idp recovered (auto)")
                transition = "recovered"
        else:
            self.consecutive_failures += 1
            self.consecutive_successes = 0
            if (self.enabled and self.state.mode == "healthy"
                    and self.consecutive_failures >= self.fail_threshold):
                self.state.set_mode("degraded",
                                    reason=f"idp unreachable x{self.consecutive_failures} (auto)")
                transition = "degraded"

        entry = {"at": int(now), "ok": bool(report.get("ok")),
                 "fails": self.consecutive_failures,
                 "successes": self.consecutive_successes,
                 "transition": transition, "detail": report.get("detail", "")}
        self.history.append(entry)
        self.history = self.history[-50:]

        return {"mode": self.state.mode, "transition": transition,
                "report": report, "automatic": self.enabled}
