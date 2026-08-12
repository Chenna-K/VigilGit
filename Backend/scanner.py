import requests
import tempfile
import shutil
import re

HUNK_HEADER_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")



search_terms = {
    "hardcodes secrets": r"(?:api|secret|token|key|password)[\s]*[:=][\s]*['\"]?[\w-]+['\"]?",
    "sensitive data": r"(?:ssn|social security number|credit card number|ccn|cvv)[\s]*[:=][\s]*['\"]?[\d-]+['\"]?",
    "dangerous_functionalities": r"(?:eval|exec|subprocess|os\.system|pickle\.loads|input)[\s]*\(",
    "development side effects": r"(?:todo|deprecated|vulnerable|fix|completed|dev|removed|debug|test|temporary)[\s]*[:=][\s]*['\"]?[\w\s-]+['\"]?",
    "AWS ACCESS KEY ID": r"AKIA[A-Z0-9]{16}",
    "GOOGLE API KEY": r"AIza[0-9A-Za-z\-_]{35}",
    "Bearer Token": r"Bearer\s[0-9a-zA-Z\-\._~\+\/]+=*",
    "Password assignment": r"(?i)(password|passwd|pwd)\s*[:=]\s*(?:'[^']*'|\"[^\"]*\"|[^\s'\"]+)",
    "Random secret literal": r"['\"](?=.{16,})(?:(?!['\"]).)*['\"]",
    "Private Key": r"-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----",
    "SSH Key": r"ssh-(rsa|dss|ed25519) [A-Za-z0-9+/]+[=]{0,3}( [^\n\r]*)?",
}


def parse_diff(diff: str) -> dict:
    current_file = None
    old_line = 0
    new_line = 0
    added_lines = []

    for line in diff.splitlines():
        if line.startswith("+++ "):
            current_file = line[4:]
            continue

        if line.startswith("@@"):
            match = HUNK_HEADER_RE.match(line)
            if match:
                old_line = int(match.group(1))
                new_line = int(match.group(3))
            continue

        if line.startswith("+") and not line.startswith("+++"):
            added_lines.append((current_file, new_line, line[1:]))
            new_line += 1
            continue

        if line.startswith("-") and not line.startswith("---"):
            old_line += 1
            continue

        if line.startswith(" "):
            old_line += 1
            new_line += 1
            continue

    return {"added_lines": added_lines}



def scan_added_lines(added_lines: list) -> dict:
    """Scan the added lines

    for each added line:
    strip the leading +
    test it against every regex
    if a match occurs, save:
    file path
    line number
    matched text
    pattern name"""

    findings = []

    for file_path, line_number, line in added_lines:
        for pattern_name, regex in search_terms.items():
            if re.search(regex, line):
                findings.append({
                    "file_path": file_path,
                    "line_number": line_number,
                    "matched_text": line.strip(),
                    "pattern_name": pattern_name
                })

    return {"findings": findings}


def main():
    # Example diff string for testing
    example_diff = """diff --git a/example.py b/example.py
index 83db48f..b6fc4c3 100644
--- a/example.py
+++ b/example.py
@@ -1,4 +1,7 @@
+import os
+api_key = "AIza12345678901234567890123456789012345"
+aws_key = "AKIA1234567890ABCDE"
 def example_function():
     pass
+"tsmf*)xg(r+,h_iJ"
+"fkd5dDHVEN-kEkQ_"
+"XhRGWI(hw72@*iMf"
    # Parse the diff"""
    parsed_diff = parse_diff(example_diff)
    findings = scan_added_lines(parsed_diff["added_lines"])
    print(findings)
    
if __name__ == "__main__":
    main()