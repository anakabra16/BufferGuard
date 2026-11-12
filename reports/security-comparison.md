
# BufferGuard – Binary Security Comparison

## Vulnerable Baseline vs Hardened Build

| Protection | Vulnerable | Hardened |
|---|---|---|
| RELRO | Partial | Full |
| Stack Canary | Disabled | Enabled |
| NX | Enabled | Enabled |
| PIE | Disabled | Enabled |
| FORTIFY | Disabled | Enabled |

## Analysis

The baseline binary was compiled without stack protection,
PIE, or FORTIFY_SOURCE.

The hardened binary was compiled using:
- Stack Protector Strong
- FORTIFY_SOURCE=2
- Full RELRO
- Non-executable stack
- PIE

The Checksec results confirm that the hardened binary
has additional compiler and linker security protections.

NX was enabled in both builds.

## Conclusion

Compiler and linker hardening options improve the
security posture of C applications and help mitigate
the impact of certain memory-corruption vulnerabilities.

These protections do not eliminate all vulnerabilities.
Secure input handling and correct buffer management
remain necessary.
