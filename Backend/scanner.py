
import re
from typing import List, Dict, Tuple, Any

class DiffScanner:
    DEFAULT_PATTERNS = {
        "AWS ACCESS KEY ID": r"AKIA[A-Z0-9]{16}",
        "GOOGLE API KEY": r"AIza[0-9A-Za-z\\-_]{35}",
        "Password assignment": r"(?i)(password|passwd|pwd)\\s*[:=]\\s*(?:'[^']*'|\"[^\"]*\"|[^\\s'\\\"]+)",
        "Random secret literal": r"['\"](?=.{16,})(?:(?!['\"]).)*['\"]",
        "Private Key": r"-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----",
        "SSH Key": r"ssh-(rsa|dss|ed25519) [A-Za-z0-9+/]+[=]{0,3}( [^\n\r]*)?",
    }
    
    def __init__(self, patterns: Dict[str, str] = None):
        self.patterns = patterns or self.DEFAULT_PATTERNS
        self.compiled = {name:re.compile(p) for name, p in self.patterns.items()}
        
    def parse_diff(self, diff: str) -> List[Tuple[str, int, str]]:
        """Parse a unified diff string and return a list of added lines with their file paths and line numbers."""
        current_file = None
        new_line_number = 0
        added_lines = []
        
        for line in diff.splitlines():
            if line.startswith("+++ "):
                current_file = line[4:]
                continue
            
            if line.startswith("@@"):
                parts = line.split()
                new_line_number = int(parts[2].split(',')[0][1:])
                continue
            
            if line.startswith("+") and not line.startswith("+++"):
                added_lines.append((current_file, new_line_number, line[1:]))
                new_line_number += 1
            elif not line.startswith("-"):
                new_line_number += 1
        
        return added_lines
    
    def find_secrets_in_text(self, text: str) -> List[Dict[str, Any]]:
        """Return matches for compiled patterns in a single line of text."""
        matches: List[Dict[str, Any]] = []
        for name, pattern in self.compiled.items():
            for m in pattern.finditer(text):
                matches.append({
                    "pattern_name": name,
                    "matched_text": m.group(0),
                    "start": m.start(),
                    "end": m.end(),
                })
        return matches

    def scan_added_lines(self, added_lines: List[Tuple[str, int, str]]) -> List[Dict[str, Any]]:
        """Scan added lines and return structured findings."""
        findings: List[Dict[str, Any]] = []
        for file_path, line_number, line in added_lines:
            for hit in self.find_secrets_in_text(line):
                findings.append({
                    "file_path": file_path,
                    "line_number": line_number,
                    "line": line.strip(),
                    "pattern_name": hit["pattern_name"],
                    "matched_text": hit["matched_text"],
                })
        return findings

    def scan_diff(self, diff: str) -> List[Dict[str, Any]]:
        """Convenience: parse a diff and return findings."""
        added = self.parse_diff(diff)
        return self.scan_added_lines(added)

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
    scanner = DiffScanner()
    parsed_diff = {"added_lines": scanner.parse_diff(example_diff)
    }
    findings = scanner.scan_added_lines(parsed_diff["added_lines"])
    print(findings)
    
if __name__ == "__main__":
    main()
    