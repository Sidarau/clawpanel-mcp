"""First-party Work reads for OAuth-connected agents."""
from typing import Any

import httpx

WORK_ISSUE_URL = "https://clawpanel.app/api/connectors/work/issue"


async def read_work_issue(token: str, issue: str) -> dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=25, follow_redirects=False, trust_env=False) as client:
            response = await client.post(
                WORK_ISSUE_URL,
                headers={"Authorization": f"Bearer {token}"},
                json={"issue": issue},
            )
        if response.status_code in (401, 403):
            raise RuntimeError("Reconnect ClawPanel and check your Work access.")
        if response.status_code == 404:
            raise RuntimeError("That issue is unavailable in the connected workspace.")
        if response.status_code == 400:
            raise RuntimeError("Use a ClawPanel issue UUID or identifier, such as ZEU-10.")
        if response.status_code == 200:
            result = response.json()
            if isinstance(result, dict) and isinstance(result.get("issue"), dict):
                return result
    except (httpx.HTTPError, ValueError):
        pass
    raise RuntimeError("ClawPanel could not load the Work issue. Try again.")
