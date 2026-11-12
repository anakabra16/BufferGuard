
# BufferGuard — Buffer Overflow Detection & Mitigation Framework

A lightweight defensive cybersecurity project that scans C source code for potentially unsafe input-handling and string-manipulation patterns, runs automated tests, and generates security reports.

## Project Overview

BufferGuard demonstrates how simple static analysis can help identify code that deserves further security review.

The tool uses configurable pattern-matching rules to flag selected C functions associated with unsafe memory handling. It generates JSON, CSV, and Markdown reports to support review and documentation.

**Important:** A detected pattern is a potential finding, not proof of an exploitable vulnerability.

## Features

- Pattern-based C source-code scanning
- Detection rules for `gets()`, `strcpy()`, `strcat()`, `sprintf()`, and `scanf()` with `%s`
- Source file and line-number reporting
- JSON findings output
- CSV and Markdown report generation
- Automated unit tests
- Safe input-validation demonstration in C
- Documented limitations and mitigation recommendations

## Technologies

- Kali Linux
- C
- Python 3
- GCC
- Python `unittest`
- JSON and CSV

## Project Structure

```text
BufferGuard/
├── README.md
├── requirements.txt
├── src/
│   ├── analyzer.py
│   └── report.py
├── samples/
│   ├── vulnerable.c
│   └── hardened.c
├── tests/
│   ├── test_analyzer.py
│   └── test_cases.txt
├── reports/
├── screenshots/
└── docs/
    └── methodology.md
```

## Setup

Python 3 and GCC are required.

Check your environment:

```bash
python3 --version
gcc --version
```

No third-party Python packages are required for the current implementation.

## Usage

### 1. Scan the sample directory

```bash
python3 src/analyzer.py samples --json reports/scan-results.json
```

### 2. Scan a specific C source file

```bash
python3 src/analyzer.py samples/hardened.c --json reports/findings.json
```

### 3. Generate CSV and Markdown reports

After creating a JSON findings file:

```bash
python3 src/report.py reports/scan-results.json
```

The report generator creates:

- `reports/scan-results.csv`
- `reports/scan-report.md`

### 4. Run automated tests

```bash
python3 -m unittest discover -s tests -v
```

## Detection Rules

| Rule | Pattern | Initial Severity |
|---|---|---|
| BG001 | `gets()` | Critical |
| BG002 | `strcpy()` | High |
| BG003 | `strcat()` | High |
| BG004 | `sprintf()` | High |
| BG005 | `scanf()` with `%s` | Medium |

These are preliminary severity labels. Context, destination buffer size, input constraints, and program logic must be reviewed before determining whether a real vulnerability exists.

## Security Testing

The project includes controlled tests for:

- Normal input acceptance
- Oversized input rejection by the hardened example
- Detection of selected unsafe function patterns
- Source line-number reporting
- Automated test execution
- Security report generation

## Mitigation Recommendations

- Prefer bounded input handling such as `fgets()`.
- Validate input lengths and handle truncation.
- Verify destination buffer capacity before copying or concatenating strings.
- Enable compiler warnings and suitable hardening options.
- Use code review and additional static-analysis tools.

## Limitations

BufferGuard is an educational prototype that uses regular expressions rather than a full C parser.

It can miss unsafe code, match code that is safe in context, and misunderstand multiline expressions or comments. Its results are not proof of exploitability and do not replace professional static-analysis tools.

## Ethical Scope

All testing uses local educational sample programs. No unauthorized systems or third-party applications are targeted.

## Author

Ana Kabra

## Conclusion

BufferGuard demonstrates the fundamentals of defensive C source-code analysis, automated testing, input validation, and security report generation.
