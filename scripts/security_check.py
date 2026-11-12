
#!/usr/bin/env python3

import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

BINARIES = {
    "vulnerable": ROOT / "build" / "vulnerable",
    "hardened": ROOT / "build" / "hardened",
}

REPORT_DIR = ROOT / "reports"


def check_aslr():
    path = Path("/proc/sys/kernel/randomize_va_space")

    try:
        value = int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError) as error:
        return {
            "value": None,
            "status": "Unavailable",
            "error": str(error),
        }

    descriptions = {
        0: "Disabled",
        1: "Partial randomization",
        2: "Full randomization",
    }

    return {
        "value": value,
        "status": descriptions.get(value, "Unknown"),
    }


def clean_terminal_output(output):
    """Remove ANSI terminal formatting from Checksec output."""
    output = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", output)
    return output.strip()


def check_binary(name, binary_path):
    if not binary_path.is_file():
        return {
            "binary": str(binary_path),
            "status": "Missing",
            "checksec_output": None,
        }

    try:
        result = subprocess.run(
            ["checksec", "--file=" + str(binary_path)],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )

        return {
            "binary": str(binary_path),
            "status": "Success" if result.returncode == 0 else "Error",
            "return_code": result.returncode,
            "checksec_output": clean_terminal_output(result.stdout),
            "error": clean_terminal_output(result.stderr),
        }

    except (OSError, subprocess.TimeoutExpired) as error:
        return {
            "binary": str(binary_path),
            "status": "Error",
            "error": str(error),
        }


def main():
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    print("\nBufferGuard - Automated Security Checker")
    print("=" * 48)

    results = {
        "project": "BufferGuard",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "aslr": check_aslr(),
        "binaries": {},
    }

    print("\nChecking ASLR...")
    print("ASLR:", results["aslr"]["status"])

    for name, path in BINARIES.items():
        print(f"\nChecking {name} binary...")

        result = check_binary(name, path)
        results["binaries"][name] = result

        print("Status:", result["status"])

        if result.get("checksec_output"):
            print(result["checksec_output"])

        if result.get("error"):
            print("Error:", result["error"])

    output_path = REPORT_DIR / "security-check.json"

    output_path.write_text(
        json.dumps(results, indent=4),
        encoding="utf-8",
    )

    print("\n" + "=" * 48)
    print("Security comparison completed.")
    print("JSON report:", output_path)


if __name__ == "__main__":
    main()

