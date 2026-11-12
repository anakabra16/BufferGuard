#!/usr/bin/env python3

import argparse
import csv
import json
from pathlib import Path


FIELDS = [
    "file",
    "line",
    "rule",
    "pattern",
    "severity",
    "description",
    "code",
]


def load_findings(json_path):
    with json_path.open("r", encoding="utf-8") as file:
        findings = json.load(file)

    if not isinstance(findings, list):
        raise ValueError("Expected a JSON list of findings.")

    return findings


def write_csv(findings, output_path):
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(findings)


def write_markdown(findings, output_path):
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file:
        file.write("# BufferGuard Security Scan Report\n\n")
        file.write(f"**Potential findings:** {len(findings)}\n\n")
        file.write(
            "> Pattern-based results require manual review. "
            "They do not prove exploitability.\n\n"
        )

        if not findings:
            file.write("No configured risky patterns were detected.\n")
            return

        file.write("| File | Line | Rule | Severity | Pattern |\n")
        file.write("|---|---:|---|---|---|\n")

        for finding in findings:
            file.write(
                f"| {finding['file']} | {finding['line']} "
                f"| {finding['rule']} | {finding['severity']} "
                f"| `{finding['pattern']}` |\n"
            )

        file.write("\n## Findings and Recommendations\n\n")

        for finding in findings:
            file.write(
                f"### {finding['rule']} — {finding['pattern']}\n\n"
            )
            file.write(f"- **Severity:** {finding['severity']}\n")
            file.write(f"- **Location:** `{finding['file']}:{finding['line']}`\n")
            file.write(f"- **Finding:** {finding['description']}\n")
            file.write(f"- **Code:** `{finding['code']}`\n")
            file.write(
                "- **Recommendation:** Review buffer capacity and "
                "input bounds; prefer bounded functions and validate "
                "input lengths.\n\n"
            )


def main():
    parser = argparse.ArgumentParser(
        description="Generate CSV and Markdown reports from BufferGuard JSON."
    )
    parser.add_argument(
        "input",
        help="JSON findings file produced by analyzer.py"
    )
    parser.add_argument(
        "--out",
        default="reports",
        help="Output directory (default: reports)"
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    output_dir = Path(args.out)

    try:
        findings = load_findings(input_path)
        csv_path = output_dir / "scan-results.csv"
        md_path = output_dir / "scan-report.md"

        write_csv(findings, csv_path)
        write_markdown(findings, md_path)

    except (OSError, json.JSONDecodeError, ValueError, KeyError) as error:
        parser.error(str(error))

    print(f"Findings loaded: {len(findings)}")
    print(f"CSV report: {csv_path}")
    print(f"Markdown report: {md_path}")


if __name__ == "__main__":
    main()
