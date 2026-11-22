#!/usr/bin/env python3
"""Summarize one s3-tests lane from its JUnit XML.

usage: s3-tests-summary.py LANE JUNIT_XML

Prints a Markdown summary: the counts, then every test that failed or
errored and every marked test that passed (an XPASS(strict), whose marker
has gone stale).  run-s3-tests.sh appends it to $GITHUB_STEP_SUMMARY, so
a CI run names the tests that broke on its summary page instead of in a
JUnit artifact one has to download.
"""

import os
import sys
import xml.etree.ElementTree as ElementTree

MAX_LISTED = 50


def first_line(text):
    return (text or "").strip().split("\n", 1)[0][:200].replace("|", "\\|")


def main():
    lane, path = sys.argv[1], sys.argv[2]
    if not os.path.exists(path):
        print(f"### s3-tests: {lane}\n\nNo results: {path} was not written.")
        return
    counts = {"passed": 0, "failed": 0, "error": 0, "xpassed": 0,
              "xfailed": 0, "skipped": 0}
    failed, xpassed = [], []
    for case in ElementTree.parse(path).getroot().iter("testcase"):
        name = case.get("name")
        outcome = "passed"
        for child in case:
            if child.tag in ("failure", "error"):
                message = child.get("message") or child.text
                if "XPASS(strict)" in (message or ""):
                    outcome = "xpassed"
                    xpassed.append((name, first_line(message)))
                else:
                    outcome = "failed" if child.tag == "failure" else "error"
                    failed.append((name, outcome, first_line(message)))
            elif child.tag == "skipped":
                outcome = ("xfailed" if child.get("type") == "pytest.xfail"
                           else "skipped")
        counts[outcome] += 1

    ok = not failed and not xpassed
    print(f"### s3-tests: {lane} {'passed' if ok else 'FAILED'}\n")
    print("| passed | failed | errors | unexpectedly passed "
          "| expected failures | skipped |")
    print("| --- | --- | --- | --- | --- | --- |")
    print(f"| {counts['passed']} | {counts['failed']} | {counts['error']} "
          f"| {counts['xpassed']} | {counts['xfailed']} "
          f"| {counts['skipped']} |")
    if failed:
        print("\n**Failed**\n\n| test | outcome | message |\n| --- | --- | --- |")
        for name, outcome, message in failed[:MAX_LISTED]:
            print(f"| `{name}` | {outcome} | {message} |")
        if len(failed) > MAX_LISTED:
            print(f"\n...and {len(failed) - MAX_LISTED} more.")
    if xpassed:
        print("\n**Passed although marked to fail**: the marker is stale and "
              "should go.\n\n| test | marker |\n| --- | --- |")
        for name, message in xpassed[:MAX_LISTED]:
            print(f"| `{name}` | {message.replace('[XPASS(strict)] ', '')} |")
        if len(xpassed) > MAX_LISTED:
            print(f"\n...and {len(xpassed) - MAX_LISTED} more.")
    print()


if __name__ == "__main__":
    main()
