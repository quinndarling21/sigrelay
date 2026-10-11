#!/usr/bin/env python3
"""Convert cppcheck XML (--xml, version 2) output to SARIF 2.1.0.

Usage: cppcheck_xml_to_sarif.py CPPCHECK_XML OUTPUT_SARIF [--root DIR]

Cppcheck only gained --output-format=sarif in 2.16; Ubuntu 24.04 (the CI
runner and the agent environment) ships 2.13, so CI emits XML and converts it
here. Each <error> becomes one result whose ruleId is the cppcheck id; the
first <location> is the primary location.

Prints every finding and exits 1 if there is at least one, 0 otherwise, and 2
if the XML cannot be read.
"""
import argparse
import json
import os
import sys
import xml.etree.ElementTree as ET

LEVELS = {
    "error": "error",
    "warning": "warning",
    "style": "note",
    "performance": "note",
    "portability": "note",
    "information": "note",
}


def relative_uri(path, root):
    absolute = os.path.abspath(path)
    rel = os.path.relpath(absolute, root)
    if rel.startswith(".."):
        return absolute.replace(os.sep, "/")
    return rel.replace(os.sep, "/")


def parse(tree, root):
    version = ""
    node = tree.find("cppcheck")
    if node is not None:
        version = node.get("version", "")
    results = []
    for error in tree.iter("error"):
        result = {
            "ruleId": error.get("id", "unknown"),
            "level": LEVELS.get(error.get("severity", ""), "warning"),
            "message": {"text": error.get("msg", "")},
            "properties": {"severity": error.get("severity", "")},
        }
        if error.get("cwe"):
            result["properties"]["cwe"] = "CWE-" + error.get("cwe")
        locations = []
        for location in error.findall("location"):
            region = {"startLine": max(int(location.get("line", "1")), 1)}
            if int(location.get("column", "0")) > 0:
                region["startColumn"] = int(location.get("column"))
            locations.append({
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": relative_uri(location.get("file", ""), root),
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": region,
                },
                "message": {"text": location.get("info", "")},
            })
        if locations:
            result["locations"] = locations[:1]
            if len(locations) > 1:
                result["relatedLocations"] = locations[1:]
        results.append(result)
    return version, results


def to_sarif(version, results, root):
    driver = {
        "name": "cppcheck",
        "informationUri": "https://cppcheck.sourceforge.io/",
        "rules": [{"id": rid} for rid in sorted({r["ruleId"] for r in results})],
    }
    if version:
        driver["version"] = version
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
    where = "<no location>"
    if result.get("locations"):
        location = result["locations"][0]["physicalLocation"]
        where = "%s:%d" % (location["artifactLocation"]["uri"], location["region"]["startLine"])
        if "startColumn" in location["region"]:
            where += ":%d" % location["region"]["startColumn"]
    return "%s: %s: %s [%s]" % (
        where, result["properties"]["severity"], result["message"]["text"], result["ruleId"])


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("xml")
    parser.add_argument("output")
    parser.add_argument("--root", default=os.getcwd())
    args = parser.parse_args(argv)

    root = os.path.abspath(args.root)
    try:
        tree = ET.parse(args.xml).getroot()
    except (OSError, ET.ParseError) as exc:
        print("cannot read cppcheck XML %s: %s" % (args.xml, exc), file=sys.stderr)
        return 2
    version, results = parse(tree, root)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(to_sarif(version, results, root), handle, indent=2)
        handle.write("\n")

    for result in results:
        print(describe(result))
    print("cppcheck %s: %d finding(s), SARIF written to %s" % (version, len(results), args.output))
    return 1 if results else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
