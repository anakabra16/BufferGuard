
#!/usr/bin/env python3

import argparse
import json
import re
from pathlib import Path


RULES = {
    "gets": ("BG001", "Critical",
             "gets() does not limit input length."),
    "strcpy": ("BG002", "High",
               "strcpy() does not check destination capacity."),
    "strcat": ("BG003", "High",
               "strcat() does not check destination capacity."),
    "sprintf": ("BG004", "High",
                "sprintf() does not limit output to destination capacity."),
}


def mask_comments(source):
    """Mask comments and string/character contents while preserving positions."""
    result = list(source)
    i = 0
    state = "code"

    while i < len(source):
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""

        if state == "code":
            if ch == "/" and nxt == "/":
                result[i] = result[i + 1] = " "
                i += 2
                state = "line_comment"
                continue
            elif ch == "/" and nxt == "*":
                result[i] = result[i + 1] = " "
                i += 2
                state = "block_comment"
                continue
            elif ch == '"':
                result[i] = " "
                state = "string"
            elif ch == "'":
                result[i] = " "
                state = "character"

        elif state == "line_comment":
            if ch == "\n":
                state = "code"
            else:
                result[i] = " "

        elif state == "block_comment":
            if ch == "*" and nxt == "/":
                result[i] = result[i + 1] = " "
                i += 2
                state = "code"
                continue
            if ch != "\n":
                result[i] = " "

        elif state in ("string", "character"):
            quote = '"' if state == "string" else "'"

            if ch == "\\":
                result[i] = " "
                if i + 1 < len(source):
                    if source[i + 1] != "\n":
                        result[i + 1] = " "
                    i += 2
                    continue

            elif ch == quote:
                result[i] = " "
                state = "code"

            elif ch != "\n":
                result[i] = " "

        i += 1

    return "".join(result)


def find_call_end(masked, open_pos):
    """Find the closing parenthesis of a function call."""
    depth = 0

    for i in range(open_pos, len(masked)):
        if masked[i] == "(":
            depth += 1
        elif masked[i] == ")":
            depth -= 1
            if depth == 0:
                return i

    return None


def first_argument(arguments):
    """Extract the first argument, respecting nested parentheses."""
    depth = 0

    for i, ch in enumerate(arguments):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            return arguments[:i]

    return arguments


def analyze_file(path):
    findings = []

    try:
        source = path.read_text(
            encoding="utf-8",
            errors="replace"
        )
    except OSError as error:
        raise RuntimeError(f"Cannot read {path}: {error}") from error

    masked = mask_comments(source)

    # Detect BG001 through BG004.
    for function, details in RULES.items():
        rule_id, severity, description = details

        pattern = re.compile(r"\b" + function + r"\s*\(")

        for match in pattern.finditer(masked):
            line_number = masked.count("\n", 0, match.start()) + 1

            line_start = source.rfind("\n", 0, match.start()) + 1
            line_end = source.find("\n", match.start())

            if line_end == -1:
                line_end = len(source)

            findings.append({
                "file": str(path),
                "line": line_number,
                "rule": rule_id,
                "pattern": function,
                "severity": severity,
                "description": description,
                "code": source[line_start:line_end].strip()
            })

    # Detect BG005: unbounded scanf("%s").
    scanf_pattern = re.compile(r"\bscanf\s*\(")

    for match in scanf_pattern.finditer(masked):
        open_pos = masked.find("(", match.start())
        close_pos = find_call_end(masked, open_pos)

        if close_pos is None:
            continue

        arguments = source[open_pos + 1:close_pos]
        format_argument = first_argument(arguments).strip()

        format_match = re.match(
            r'"((?:\\.|[^"\\])*)"',
            format_argument,
            re.DOTALL
        )

        if not format_match:
            continue

        format_string = format_match.group(1)

        # Match %s conversions without a field width.
        unbounded = re.search(
            r"(?<!%)%(?:\*)?s",
            format_string
        )

        if not unbounded:
            continue

        line_number = masked.count("\n", 0, match.start()) + 1

        line_start = source.rfind("\n", 0, match.start()) + 1
        line_end = source.find("\n", match.start())

        if line_end == -1:
            line_end = len(source)

        findings.append({
            "file": str(path),
            "line": line_number,
            "rule": "BG005",
            "pattern": "scanf with %s",
            "severity": "Medium",
            "description": (
                "scanf() with an unbounded %s conversion may "
                "read more data than the destination can hold."
            ),
            "code": source[line_start:line_end].strip()
        })

    return sorted(findings, key=lambda item: item["line"])


def main():
    parser = argparse.ArgumentParser(
        description="BufferGuard: lightweight C source security scanner"
    )

    parser.add_argument(
        "source",
        help="C source file or directory to scan"
    )

    parser.add_argument(
        "--json",
        dest="json_path",
        help="Optional path to save findings as JSON"
    )

    args = parser.parse_args()
    source = Path(args.source)

    if not source.exists():
        parser.error(f"Path does not exist: {source}")

    if source.is_file():
        files = [source] if source.suffix == ".c" else []
    else:
        files = sorted(source.rglob("*.c"))

    if not files:
        parser.error("No .c source files found")

    all_findings = []

    print("\nBufferGuard — C Source Security Scan")
    print("=" * 42)

    for file_path in files:
        findings = analyze_file(file_path)
        all_findings.extend(findings)

        print(f"\nFile: {file_path}")

        if not findings:
            print("  No configured risky patterns detected.")
            continue

        for finding in findings:
            print(
                f"  [{finding['severity']}] "
                f"{finding['rule']} Line {finding['line']}: "
                f"{finding['pattern']}"
            )
            print(f"    {finding['description']}")
            print(f"    Code: {finding['code']}")

    print("\n" + "=" * 42)
    print(f"Files scanned: {len(files)}")
    print(f"Potential findings: {len(all_findings)}")
    print(
        "Note: Findings require manual review; "
        "they do not prove exploitability."
    )

    if args.json_path:
        output_path = Path(args.json_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        output_path.write_text(
            json.dumps(all_findings, indent=2),
            encoding="utf-8"
        )

        print(f"JSON report saved to: {output_path}")


if __name__ == "__main__":
    main()

