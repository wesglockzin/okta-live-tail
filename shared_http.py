from __future__ import annotations

import requests


def make_session(tool_name: str, tool_version: str) -> requests.Session:
    session = requests.Session()
    session.headers.update({
        "User-Agent": f"{tool_name}/{tool_version}",
        "Accept": "application/json",
    })
    return session
