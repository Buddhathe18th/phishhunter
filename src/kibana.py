"""Thin client for Kibana's Agent Builder API (tools, agents, converse)."""
from __future__ import annotations

import httpx

from .config import Settings

CONVERSE_TIMEOUT = 90.0


class KibanaError(RuntimeError):
    pass


class Kibana:
    def __init__(self, settings: Settings, client: httpx.Client | None = None) -> None:
        if not settings.kibana_url or not settings.kibana_api_key:
            raise KibanaError("KIBANA_URL and KIBANA_API_KEY (or ELASTIC_API_KEY) are required")
        self.base = settings.kibana_url
        self.client = client or httpx.Client(
            headers={"Authorization": f"ApiKey {settings.kibana_api_key}", "kbn-xsrf": "true",
                     "Content-Type": "application/json"},
            timeout=30.0, follow_redirects=False, trust_env=False)

    def _call(self, method: str, path: str, body: dict | None = None, timeout: float | None = None) -> httpx.Response:
        return self.client.request(method, f"{self.base}{path}", json=body, timeout=timeout)

    def upsert(self, kind: str, definition: dict) -> str:
        """Create a tool ('tools') or agent ('agents'); on conflict, update in place. Returns 'created'/'updated'.

        Kibana isn't consistent about the conflict status code: agents return 409, but tools return a plain 400
        with "already exists" in the message. Checking the message text, not just the status code, is what
        actually makes re-running this idempotent as documented.
        """
        path = f"/api/agent_builder/{kind}"
        resp = self._call("POST", path, definition)
        is_conflict = resp.status_code == 409 or (resp.status_code == 400 and "already exists" in resp.text.lower())
        if is_conflict:
            body = {k: v for k, v in definition.items() if k not in {"id", "type"}}
            resp = self._call("PUT", f"{path}/{definition['id']}", body)
            action = "updated"
        else:
            action = "created"
        if resp.status_code >= 400:
            raise KibanaError(f"{kind} '{definition['id']}': HTTP {resp.status_code} {resp.text[:300]}")
        return action

    def converse(self, agent_id: str, message: str) -> str | None:
        resp = self._call("POST", "/api/agent_builder/converse", {"input": message, "agent_id": agent_id},
                          timeout=CONVERSE_TIMEOUT)
        if resp.status_code >= 400:
            raise KibanaError(f"converse: HTTP {resp.status_code}")
        data = resp.json()
        reply = data.get("response")
        text = reply.get("message") if isinstance(reply, dict) else reply
        return text if isinstance(text, str) else None
