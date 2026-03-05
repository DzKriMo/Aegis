from __future__ import annotations

import argparse
import subprocess
import sys
from typing import Any, Dict

import requests


def aegis_post(base_url: str, api_key: str, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    resp = requests.post(
        f"{base_url.rstrip('/')}{path}",
        headers={"x-api-key": api_key, "content-type": "application/json"},
        json=payload,
        timeout=60,
    )
    resp.raise_for_status()
    return resp.json()


def main() -> int:
    parser = argparse.ArgumentParser(description="Guard OpenClaw messages with Aegis input/output checks.")
    parser.add_argument("--aegis-url", default="http://127.0.0.1:8000/v1")
    parser.add_argument("--api-key", default="changeme")
    parser.add_argument("--message", required=True)
    parser.add_argument("--environment", default="dev")
    parser.add_argument("--agent", default="main")
    parser.add_argument(
        "--openclaw-cmd",
        default="openclaw",
        help="OpenClaw executable name/path",
    )
    args = parser.parse_args()

    session_id = aegis_post(args.aegis_url, args.api_key, "/sessions", {})["session_id"]

    guarded_in = aegis_post(
        args.aegis_url,
        args.api_key,
        f"/sessions/{session_id}/guard/input",
        {
            "content": args.message,
            "metadata": {"source": "openclaw_aegis_bridge"},
            "environment": args.environment,
        },
    )
    if guarded_in.get("blocked"):
        print(f"[aegis] blocked input: {guarded_in.get('message') or 'Blocked'}")
        return 2
    if guarded_in.get("require_approval"):
        print(f"[aegis] approval required: {guarded_in.get('message') or 'Approval required'}")
        print(f"[aegis] approval_hash: {guarded_in.get('approval_hash')}")
        return 3

    safe_input = guarded_in.get("sanitized_content") or args.message
    proc = subprocess.run(
        [args.openclaw_cmd, "agent", "--agent", args.agent, "--message", safe_input],
        capture_output=True,
        text=True,
        check=False,
    )
    raw_output = (proc.stdout or proc.stderr or "").strip()
    if not raw_output:
        print("[bridge] OpenClaw returned empty output", file=sys.stderr)
        return 4

    guarded_out = aegis_post(
        args.aegis_url,
        args.api_key,
        f"/sessions/{session_id}/guard/output",
        {
            "content": raw_output,
            "metadata": {"source": "openclaw_aegis_bridge"},
            "environment": args.environment,
        },
    )
    if guarded_out.get("blocked"):
        print(f"[aegis] blocked output: {guarded_out.get('message') or 'Blocked'}")
        return 5
    if guarded_out.get("require_approval"):
        print(f"[aegis] output approval required: {guarded_out.get('message') or 'Approval required'}")
        print(f"[aegis] approval_hash: {guarded_out.get('approval_hash')}")
        return 6

    print(guarded_out.get("sanitized_output") or raw_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
