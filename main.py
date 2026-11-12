
#!/usr/bin/env python3

import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parent

BUILD_DIR = ROOT / "build"
REPORT_DIR = ROOT / "reports"
SAMPLES_DIR = ROOT / "samples"

VULNERABLE_SOURCE = SAMPLES_DIR / "vulnerable.c"
HARDENED_SOURCE = SAMPLES_DIR / "hardened.c"

VULNERABLE_BINARY = BUILD_DIR / "vulnerable"
HARDENED_BINARY = BUILD_DIR / "hardened"

PYTHON = sys.executable


def run_command(command, description):
    print(f"\n[+] {description}")

    try:
        result = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            check=False,
            timeout=60
        )

        if result.returncode != 0:
            print(f"[-] Failed: {description}")
            return False

        print(f"[+] Completed: {description}")
        return True

    except (OSError, subprocess.TimeoutExpired) as error:
        print(f"[-] Error: {error}")
        return False


def compile_programs():
    BUILD_DIR.mkdir(parents=True, exist_ok=True)

    if not VULNERABLE_SOURCE.is_file():
        print("[-] Missing vulnerable.c")
        return False

    if not HARDENED_SOURCE.is_file():
        print("[-] Missing hardened.c")
        return False

    vulnerable_command = [
        "gcc",
        "-Wall",
        "-Wextra",
        "-O0",
        "-g",
        "-fno-stack-protector",
        "-U_FORTIFY_SOURCE",
        "-no-pie",
        str(VULNERABLE_SOURCE),
        "-o",
        str(VULNERABLE_BINARY),
    ]

    hardened_command = [
        "gcc",
        "-Wall",
        "-Wextra",
        "-O2",
        "-g",
        "-fstack-protector-strong",
        "-D_FORTIFY_SOURCE=2",
        "-fPIE",
        "-pie",
        "-Wl,-z,relro,-z,now",
        "-Wl,-z,noexecstack",
        str(HARDENED_SOURCE),
        "-o",
        str(HARDENED_BINARY),
    ]

    if not run_command(
        vulnerable_command,
        "Compiling vulnerable baseline"
    ):
        return False

    if not run_command(
        hardened_command,
        "Compiling hardened program"
    ):
        return False

    return True


def run_analyzer():
    findings_path = REPORT_DIR / "latest-findings.json"

    return run_command(
        [
            PYTHON,
            str(ROOT / "src" / "analyzer.py"),
            str(SAMPLES_DIR),
            "--json",
            str(findings_path),
        ],
        "Scanning C source files"
    )


def generate_reports():
    findings_path = REPORT_DIR / "latest-findings.json"

    return run_command(
        [
            PYTHON,
            str(ROOT / "src" / "report.py"),
            str(findings_path),
            "--out",
            str(REPORT_DIR),
        ],
        "Generating CSV and Markdown reports"
    )


def run_security_checker():
    return run_command(
        [
            PYTHON,
            str(ROOT / "scripts" / "security_check.py"),
        ],
        "Checking binary security protections"
    )


def generate_summary():
    findings_path = REPORT_DIR / "latest-findings.json"
    security_path = REPORT_DIR / "security-check.json"

    if not findings_path.exists() or not security_path.exists():
        print("[-] Required reports are missing.")
        return False

    findings = json.loads(
        findings_path.read_text(encoding="utf-8")
    )

    security = json.loads(
        security_path.read_text(encoding="utf-8")
    )

    summary = {
        "project": "BufferGuard",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "source_files_scanned": 2,
        "potential_findings": len(findings),
        "rule_counts": {},
        "binary_security": security,
        "disclaimer": (
            "Pattern-based findings require manual review "
            "and do not prove exploitability."
        ),
    }

    for finding in findings:
        rule = finding["rule"]
        summary["rule_counts"][rule] = (
            summary["rule_counts"].get(rule, 0) + 1
        )

    output = REPORT_DIR / "master-summary.json"

    output.write_text(
        json.dumps(summary, indent=4),
        encoding="utf-8"
    )

    print("\n[+] Master summary generated:", output)
    return True


def main():
    print("\n" + "=" * 55)
    print("          BUFFERGUARD MASTER SCANNER")
    print("=" * 55)

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    stages = [
        ("Compilation", compile_programs),
        ("Source analysis", run_analyzer),
        ("Report generation", generate_reports),
        ("Binary security checks", run_security_checker),
        ("Master summary", generate_summary),
    ]

    successful = []

    for name, function in stages:
        print(f"\n{'-' * 55}")
        print(f"STAGE: {name}")
        print("-" * 55)

        if function():
            successful.append(name)
        else:
            print(f"\n[-] Pipeline stopped at: {name}")
            print("[!] Fix the error before running again.")
            return 1

    print("\n" + "=" * 55)
    print("          BUFFERGUARD EXECUTION COMPLETE")
    print("=" * 55)

    for stage in successful:
        print(f"[SUCCESS] {stage}")

    print("\nGenerated reports:")
    print("1. reports/latest-findings.json")
    print("2. reports/scan-results.csv")
    print("3. reports/scan-report.md")
    print("4. reports/security-check.json")
    print("5. reports/master-summary.json")

    print("\nBufferGuard analysis completed successfully.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
