"""
Main analyzer engine
"""
from pathlib import Path
from typing import Any, Dict, Optional
import pefile

from exowin.extractors import (
    FileInfoExtractor,
    HeadersExtractor,
    SectionsExtractor,
    ImportsExtractor,
    StringsExtractor,
    DisasmExtractor,
)


class ExoWinAnalyzer:
    """Main PE static analysis engine"""

    def __init__(self):
        self.extractors = {
            "file_info": FileInfoExtractor(),
            "headers": HeadersExtractor(),
            "sections": SectionsExtractor(),
            "imports": ImportsExtractor(),
            "strings": StringsExtractor(),
            "disasm": DisasmExtractor(),
        }

    def analyze_file(self, filepath: str, include_disasm: bool = False,
                     num_instructions: int = 40) -> Dict[str, Any]:
        """
        Analyze a PE file and extract all features

        Args:
            filepath: Path to PE file
            include_disasm: Whether to include disassembly
            num_instructions: Number of instructions to disassemble

        Returns:
            Dictionary with all extracted features
        """
        filepath = Path(filepath)

        if not filepath.exists():
            raise FileNotFoundError(f"File not found: {filepath}")

        # Load PE file
        try:
            pe = pefile.PE(str(filepath))
        except pefile.PEFormatError as e:
            raise ValueError(f"Invalid PE file: {e}")

        # Extract features
        results = {
            "file_info": self.extractors["file_info"].extract_safe(pe, str(filepath)),
            "headers": self.extractors["headers"].extract_safe(pe, str(filepath)),
            "sections": self.extractors["sections"].extract_safe(pe, str(filepath)),
            "imports": self.extractors["imports"].extract_safe(pe, str(filepath)),
            "strings": self.extractors["strings"].extract_safe(pe, str(filepath)),
        }

        # Optionally include disassembly
        if include_disasm:
            results["disasm"] = self.extractors["disasm"].extract(pe, str(filepath), num_instructions)

        # Add suspicious indicators summary
        results["suspicious_indicators"] = self._analyze_suspicious_indicators(results)

        # Close PE file
        pe.close()

        return results

    def _analyze_suspicious_indicators(self, results: Dict[str, Any]) -> list:
        """Analyze results for suspicious indicators"""
        indicators = []

        # Check file info
        file_info = results.get("file_info", {})
        if file_info.get("entropy", 0) > 7.0:
            indicators.append(f"High entropy ({file_info['entropy']}) - likely packed/encrypted")

        # Check sections
        sections = results.get("sections", {})
        for section in sections.get("sections", []):
            if section.get("suspicious"):
                for sus in section["suspicious"]:
                    indicators.append(f"Section {section['Name']}: {sus}")

        # Check suspicious APIs
        imports = results.get("imports", {})
        suspicious_apis = imports.get("suspicious_apis", {})
        if suspicious_apis:
            for category, apis in suspicious_apis.items():
                indicators.append(f"Suspicious {category} APIs: {', '.join(apis[:5])}")

        # Check strings
        strings = results.get("strings", {})
        categorized = strings.get("categorized", {})

        if categorized.get("urls"):
            indicators.append(f"Contains {len(categorized['urls'])} URLs")

        if categorized.get("ip_addresses"):
            indicators.append(f"Contains {len(categorized['ip_addresses'])} IP addresses")

        if categorized.get("suspicious_keywords"):
            keywords = categorized["suspicious_keywords"][:5]
            indicators.append(f"Suspicious keywords: {', '.join(keywords)}")

        # Check warnings
        headers = results.get("headers", {})
        warnings = headers.get("warnings", [])
        if warnings:
            indicators.append(f"PE parsing warnings: {len(warnings)} warnings")

        return indicators

    def quick_info(self, filepath: str) -> Dict[str, Any]:
        """Get quick file information without full analysis"""
        filepath = Path(filepath)
        pe = pefile.PE(str(filepath))

        file_info = self.extractors["file_info"].extract(pe, str(filepath))
        headers = self.extractors["headers"].extract(pe, str(filepath))

        pe.close()

        return {
            "file_info": file_info,
            "pe_type": headers.get("pe_type"),
            "machine": headers.get("file_header", {}).get("Machine"),
            "subsystem": headers.get("optional_header", {}).get("Subsystem"),
        }
