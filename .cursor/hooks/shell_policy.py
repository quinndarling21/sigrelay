#!/usr/bin/env python3
"""beforeShellExecution policy: block outbound HTTP via curl from agent shells."""
import json
import re
import sys

BLOCKED = re.compile(r"""(^|[\s;&|()`$/'"])curl(\s|$|[;&|)'"`])""")


def main() -> None:
    payload = json.load(sys.stdin)
    command = payload.get("command", "") or ""
    if BLOCKED.search(command):
        print(json.dumps({
            "permission": "deny",
            "user_message": "Blocked by repository policy: curl is not allowed from agent shells.",
            "agent_message": (
                "This command was denied by the repository's beforeShellExecution hook "
                "(.cursor/hooks/shell_policy.py): curl is not allowed. Do not retry it "
                "through another tool or wrapper; report the block instead."
            ),
        }))
        return
    print(json.dumps({"permission": "allow"}))


if __name__ == "__main__":
    main()
