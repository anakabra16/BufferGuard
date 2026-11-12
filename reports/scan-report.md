# BufferGuard Security Scan Report

**Potential findings:** 1

> Pattern-based results require manual review. They do not prove exploitability.

| File | Line | Rule | Severity | Pattern |
|---|---:|---|---|---|
| /home/ana/BufferGuard-clean/samples/vulnerable.c | 17 | BG002 | High | `strcpy` |

## Findings and Recommendations

### BG002 — strcpy

- **Severity:** High
- **Location:** `/home/ana/BufferGuard-clean/samples/vulnerable.c:17`
- **Finding:** strcpy() does not check destination capacity.
- **Code:** `strcpy(buffer, input);`
- **Recommendation:** Review buffer capacity and input bounds; prefer bounded functions and validate input lengths.

