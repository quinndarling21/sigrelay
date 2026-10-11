#!/usr/bin/env python3
"""Convert clang-tidy console output to SARIF 2.1.0.

Usage: clang_tidy_to_sarif.py CLANG_TIDY_LOG OUTPUT_SARIF [--root DIR] [--tool-version V]

Each "file:line:col: warning|error: message [check]" diagnostic becomes one
SARIF result whose ruleId is the check name. "Error while processing FILE"
lines (clang-tidy could not analyse a file) are reported under the rule
clang-tidy-processing-error. Notes are left in the raw log.

Prints every finding and exits 1 if there is at least one, 0 otherwise.
"""
import argparse
import json
import os
import re
import sys

DIAGNOSTIC = re.compile(
    r"^(?P<file>[^\s:][^:]*):(?P<line>\d+):(?P<column>\d+): "
    r"(?P<level>warning|error): (?P<message>.*?) \[(?P<checks>[^\]]+)\]$"
)
PROCESSING_ERROR = re.compile(r"^Error while processing (?P<file>.+?)\.?$")


def relative_uri(path, root):
    absolute = os.path.abspath(path)
    rel = os.path.relpath(absolute, root)
    if rel.startswith(".."):
        return absolute.replace(os.sep, "/")
    return rel.replace(os.sep, "/")


def rule_id(checks):
    # WarningsAsErrors appends ",-warnings-as-errors" to the check name.
    names = [c for c in checks.split(",") if c and not c.startswith("-")]
    return names[0] if names else checks


def parse(lines, root):
    results = []
    seen = set()
    for raw in lines:
        line = raw.rstrip("\n")
        match = DIAGNOSTIC.match(line)
        if match:
            key = (match["file"], match["line"], match["column"], match["checks"], match["message"])
            if key in seen:
                continue
            seen.add(key)
            results.append({
                "ruleId": rule_id(match["checks"]),
                "level": match["level"],
                "message": {"text": match["message"]},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": relative_uri(match["file"], root),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": int(match["line"]),
                            "startColumn": int(match["column"]),
                        },
                    }
                }],
            })
            continue
        match = PROCESSING_ERROR.match(line)
        if match:
            results.append({
                "ruleId": "clang-tidy-processing-error",
                "level": "error",
                "message": {"text": line},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": relative_uri(match["file"], root),
                            "uriBaseId": "%SRCROOT%",
                        }
                    }
                }],
            })
    return results


def to_sarif(results, root, tool_version):
    driver = {
        "name": "clang-tidy",
        "informationUri": "https://clang.llvm.org/extra/clang-tidy/",
        "rules": [{"id": rid} for rid in sorted({r["ruleId"] for r in results})],
    }
    if tool_version:
        driver["version"] = tool_version
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": driver},
            "originalUriBaseIds": {
                "%SRCROOT%": {"uri": "file://" + root.replace(os.sep, "/").rstrip("/") + "/"}
            },
            "results": results,
        }],
    }


def describe(result):
    location = result["locations"][0]["physicalLocation"]
    where = location["artifactLocation"]["uri"]
    region = location.get("region")
    if region:
        where += ":%d:%d" % (region["startLine"], region["startColumn"])
    return "%s: %s: %s [%s]" % (where, result["level"], result["message"]["text"], result["ruleId"])


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("log")
    parser.add_argument("output")
    parser.add_argument("--root", default=os.getcwd())
    parser.add_argument("--tool-version", default="")
    args = parser.parse_args(argv)

    root = os.path.abspath(args.root)
    with open(args.log, encoding="utf-8", errors="replace") as handle:
        results = parse(handle, root)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(to_sarif(results, root, args.tool_version), handle, indent=2)
        handle.write("\n")

    for result in results:
        print(describe(result))
    print("clang-tidy: %d finding(s), SARIF written to %s" % (len(results), args.output))
    return 1 if results else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
