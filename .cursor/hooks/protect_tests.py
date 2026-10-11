#!/usr/bin/env python3
"""preToolUse policy for the Delete tool: nothing under tests/ may be deleted.

Relative paths are resolved against the workspace root (the first entry of
workspace_roots, else cwd, else this repository). Paths are canonicalised with
realpath, so "src/../tests/x" and symlinked directories into tests/ are
denied as well.
"""
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PATH_KEYS = ("path", "file_path", "target_file")


def deny(reason):
    user_message = "Blocked by repository policy: " + reason
    return {
        "permission": "deny",
        "user_message": user_message,
        "agent_message": user_message + " Do not work around this (no other tool, wrapper or "
                         "rewritten command); report it to the user.",
    }


def workspace_roots(payload):
    roots = [r for r in payload.get("workspace_roots") or [] if isinstance(r, str) and r]
    cwd = payload.get("cwd")
    if not roots and isinstance(cwd, str) and cwd:
        roots = [cwd]
    return roots or [REPO_ROOT]


def is_within(path, directory):
    return path == directory or path.startswith(directory.rstrip(os.sep) + os.sep)


def evaluate(payload):
    if not isinstance(payload, dict):
        return deny("the hook payload could not be read, so the delete cannot be verified.")
    tool_name = payload.get("tool_name")
    if tool_name is not None and tool_name != "Delete":
        return {"permission": "allow"}

    tool_input = payload.get("tool_input")
    if isinstance(tool_input, str):
        try:
            tool_input = json.loads(tool_input)
        except ValueError:
            tool_input = None
    if not isinstance(tool_input, dict):
        tool_input = {}
    paths = [tool_input[k] for k in PATH_KEYS if isinstance(tool_input.get(k), str) and tool_input[k]]
    if not paths:
        return deny("the Delete request has no path to check, so it cannot be verified.")

    roots = workspace_roots(payload)
    protected = {os.path.realpath(os.path.join(root, "tests")) for root in roots + [REPO_ROOT]}
    for path in paths:
        resolved = os.path.realpath(os.path.join(roots[0], os.path.expanduser(path)))
        if any(is_within(resolved, directory) for directory in protected):
            return deny(
                "deleting %s is not allowed because files under tests/ are protected; tests are "
                "never deleted to make CI pass, and flaky tests are quarantined through the "
                "ci-triage process instead." % path)
    return {"permission": "allow"}


def main():
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        payload = None
    print(json.dumps(evaluate(payload)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
