
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(
    0,
    str(Path(__file__).resolve().parents[1] / "src")
)

from analyzer import analyze_file


class TestBufferGuard(unittest.TestCase):

    def scan_source(self, source):
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = Path(temp_dir) / "sample.c"
            file_path.write_text(source, encoding="utf-8")
            return analyze_file(file_path)

    def test_detects_gets(self):
        findings = self.scan_source(
            'void f(void) { gets(buffer); }'
        )
        self.assertTrue(any(f["rule"] == "BG001" for f in findings))

    def test_detects_strcpy(self):
        findings = self.scan_source(
            'void f(char *d, const char *s) { strcpy(d, s); }'
        )
        self.assertTrue(any(f["rule"] == "BG002" for f in findings))

    def test_detects_strcat(self):
        findings = self.scan_source(
            'void f(char *d, const char *s) { strcat(d, s); }'
        )
        self.assertTrue(any(f["rule"] == "BG003" for f in findings))

    def test_detects_sprintf(self):
        findings = self.scan_source(
            'void f(char *d, char *s) { sprintf(d, "%s", s); }'
        )
        self.assertTrue(any(f["rule"] == "BG004" for f in findings))

    def test_detects_scanf(self):
        findings = self.scan_source(
            'void f(void) { scanf("%s", buffer); }'
        )
        self.assertTrue(any(f["rule"] == "BG005" for f in findings))

    def test_clean_bounded_input(self):
        findings = self.scan_source(
            'void f(void) { char b[16]; fgets(b, sizeof(b), stdin); }'
        )
        self.assertEqual(findings, [])

    def test_reports_line_number(self):
        findings = self.scan_source(
            'void f(void) {\n    strcpy(dst, src);\n}'
        )
        self.assertEqual(findings[0]["line"], 2)

    def test_detects_multiple_patterns(self):
        findings = self.scan_source(
            'void f(char *d, char *s) {\n'
            '    strcpy(d, s);\n'
            '    strcat(d, s);\n'
            '    sprintf(d, "%s", s);\n'
            '}'
        )

        detected_rules = {f["rule"] for f in findings}

        self.assertTrue(
            {"BG002", "BG003", "BG004"}.issubset(detected_rules)
        )

    def test_clean_source(self):
        findings = self.scan_source(
            '#include <stdio.h>\n'
            'void f(void) {\n'
            '    int number = 10;\n'
            '    printf("%d", number);\n'
            '}'
        )
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)

