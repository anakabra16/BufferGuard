# BufferGuard — Project Methodology

## 1. Project Objective

BufferGuard is a lightweight defensive security tool designed to identify potentially unsafe C input-handling and string-manipulation patterns.

The project demonstrates source-code analysis, controlled testing, and basic vulnerability mitigation reporting.

## 2. Problem Statement

Buffer overflows can occur when a program writes more data into a memory buffer than the buffer can accommodate.

Such issues can lead to program crashes, memory corruption, and potentially serious security vulnerabilities.

## 3. Proposed Solution

BufferGuard uses pattern-based static analysis to identify selected C functions that may require additional security review.

The tool generates structured findings and supports CSV and Markdown reports.

## 4. Technologies Used

- Kali Linux
- C programming language
- Python 3
- GCC compiler
- Python unittest framework
- JSON and CSV reporting

## 5. Detection Rules

| Rule ID | Pattern | Severity |
|---|---|---|
| BG001 | gets() | Critical |
| BG002 | strcpy() | High |
| BG003 | strcat() | High |
| BG004 | sprintf() | High |
| BG005 | scanf() with %s | Medium |

These severity levels are preliminary project classifications. A pattern match does not establish that a vulnerability is exploitable.

## 6. Testing Methodology

The project uses controlled test cases to verify that the analyzer detects selected patterns and records their source locations.

The test suite checks:
- Detection of strcpy()
- Detection of gets()
- Handling of bounded input examples
- Reporting of source line numbers

Normal and oversized input tests are also used to demonstrate input-length validation in the hardened C example.

## 7. Mitigation Approach

Recommended defensive practices include:

- Use bounded input functions such as fgets().
- Validate input lengths.
- Check destination buffer capacity before copying or concatenating data.
- Prefer safer APIs and compiler diagnostics.
- Enable appropriate compiler hardening options.
- Perform code review and additional static analysis.

## 8. Limitations

BufferGuard is a lightweight prototype that uses regular expressions rather than a full C parser.

It may miss unsafe patterns, produce false positives, and fail to understand whether a buffer is large enough for a particular operation.

Its findings must be reviewed manually and should not be treated as proof of exploitability or as a substitute for professional security tools.

## 9. Ethical Scope

All testing is performed on local sample programs created for educational purposes.

No unauthorized systems or third-party applications are targeted.

## 10. Conclusion

BufferGuard demonstrates the fundamentals of defensive source-code analysis, controlled testing, and security report generation.

It provides a starting point for learning how developers and security analysts identify and mitigate potentially unsafe memory-handling patterns in C programs.
