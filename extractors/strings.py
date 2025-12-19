"""
Strings extractor
"""
import re
from typing import Any, Dict, List
import pefile

from exowin.extractors.base import BaseExtractor


class StringsExtractor(BaseExtractor):
    """Extract and categorize strings from PE file"""

    # Minimum string length
    MIN_STRING_LENGTH = 4

    # String patterns
    PATTERNS = {
        "urls": re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE),
        "ip_addresses": re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
        "emails": re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        "registry_keys": re.compile(r'HKEY_[A-Z_]+\\[^\s]+', re.IGNORECASE),
        "file_paths": re.compile(r'[A-Z]:\\(?:[^\s<>:"|?*\\]+\\)*[^\s<>:"|?*\\]*', re.IGNORECASE),
        "suspicious_keywords": re.compile(
            r'\b(cmd|powershell|exec|eval|shell|backdoor|keylog|inject|payload|exploit|'
            r'malware|virus|trojan|ransomware|encrypt|decrypt|persistence|privilege|'
            r'mimikatz|meterpreter|shellcode|rootkit)\b',
            re.IGNORECASE
        ),
    }

    def extract(self, pe: pefile.PE, filepath: str = None) -> Dict[str, Any]:
        """Extract strings from PE file"""
        raw_data = bytes(pe.__data__)

        # Extract ASCII strings
        ascii_strings = self._extract_ascii_strings(raw_data)

        # Extract Unicode strings
        unicode_strings = self._extract_unicode_strings(raw_data)

        # Combine and deduplicate
        all_strings = list(set(ascii_strings + unicode_strings))

        # Categorize strings
        categorized = self._categorize_strings(all_strings)

        return {
            "total_count": len(all_strings),
            "ascii_count": len(ascii_strings),
            "unicode_count": len(unicode_strings),
            "categorized": categorized,
            "all_strings": all_strings[:1000],  # Limit to first 1000 to avoid huge output
        }

    def _extract_ascii_strings(self, data: bytes) -> List[str]:
        """Extract ASCII strings"""
        # Pattern: printable ASCII characters
        pattern = b'[\x20-\x7E]{' + str(self.MIN_STRING_LENGTH).encode() + b',}'
        matches = re.findall(pattern, data)
        return [s.decode('ascii', errors='ignore') for s in matches]

    def _extract_unicode_strings(self, data: bytes) -> List[str]:
        """Extract Unicode strings (UTF-16LE)"""
        pattern = b'(?:[\x20-\x7E][\x00]){' + str(self.MIN_STRING_LENGTH).encode() + b',}'
        matches = re.findall(pattern, data)
        strings = []
        for s in matches:
            try:
                decoded = s.decode('utf-16le', errors='ignore')
                if len(decoded) >= self.MIN_STRING_LENGTH:
                    strings.append(decoded)
            except:
                pass
        return strings

    def _categorize_strings(self, strings: List[str]) -> Dict[str, List[str]]:
        """Categorize strings by type"""
        categorized = {
            "urls": [],
            "ip_addresses": [],
            "emails": [],
            "registry_keys": [],
            "file_paths": [],
            "suspicious_keywords": [],
        }

        for string in strings:
            for category, pattern in self.PATTERNS.items():
                matches = pattern.findall(string)
                if matches:
                    if isinstance(matches[0], tuple):
                        categorized[category].extend([m for m in matches if m])
                    else:
                        categorized[category].extend(matches)

        # Deduplicate
        for category in categorized:
            categorized[category] = list(set(categorized[category]))[:100]  # Limit to 100 per category

        return categorized
