"""
PE Sections extractor
"""
import math
from collections import Counter
from typing import Any, Dict, List
import pefile

from exowin.extractors.base import BaseExtractor


class SectionsExtractor(BaseExtractor):
    """Extract PE sections information"""

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0

        p, lns = Counter(data), float(len(data))
        return -sum(count/lns * math.log(count/lns, 2) for count in p.values())

    def extract(self, pe: pefile.PE, filepath: str = None) -> Dict[str, Any]:
        """Extract sections information"""
        sections_list = []

        for section in pe.sections:
            # Get section name
            try:
                name = section.Name.decode('utf-8').rstrip('\x00')
            except:
                name = str(section.Name).rstrip('\x00')

            # Calculate entropy
            section_data = section.get_data()
            entropy = round(self.calculate_entropy(section_data), 2)

            # Section characteristics
            characteristics = self._get_section_characteristics(section.Characteristics)

            section_info = {
                "Name": name,
                "VirtualAddress": hex(section.VirtualAddress),
                "VirtualSize": section.Misc_VirtualSize,
                "RawSize": section.SizeOfRawData,
                "Entropy": entropy,
                "Characteristics": characteristics,
                "MD5": section.get_hash_md5(),
            }

            # Flag suspicious characteristics
            section_info["suspicious"] = self._is_suspicious_section(
                name, entropy, characteristics,
                section.Misc_VirtualSize, section.SizeOfRawData
            )

            sections_list.append(section_info)

        return {
            "count": len(sections_list),
            "sections": sections_list,
        }

    def _get_section_characteristics(self, characteristics: int) -> List[str]:
        """Get section characteristics as list of strings"""
        char_flags = {
            0x00000020: "CODE",
            0x00000040: "INITIALIZED_DATA",
            0x00000080: "UNINITIALIZED_DATA",
            0x02000000: "DISCARDABLE",
            0x04000000: "NOT_CACHED",
            0x08000000: "NOT_PAGED",
            0x10000000: "SHARED",
            0x20000000: "EXECUTE",
            0x40000000: "READ",
            0x80000000: "WRITE",
        }

        return [name for flag, name in char_flags.items() if characteristics & flag]

    def _is_suspicious_section(self, name: str, entropy: float,
                               characteristics: List[str], vsize: int, rsize: int) -> List[str]:
        """Check for suspicious section characteristics"""
        suspicious = []

        # High entropy
        if entropy > 7.0:
            suspicious.append(f"High entropy ({entropy}) - possibly packed/encrypted")

        # Writable and executable
        if "WRITE" in characteristics and "EXECUTE" in characteristics:
            suspicious.append("Writable and executable - code injection risk")

        # Size mismatch
        size_diff = abs(vsize - rsize)
        if size_diff > 0 and vsize > 0:
            ratio = size_diff / vsize
            if ratio > 0.5:
                suspicious.append(f"Large size mismatch (VirtualSize: {vsize}, RawSize: {rsize})")

        # Suspicious names
        suspicious_names = ['.packed', '.upx', '.aspack', '.adata', '.boom']
        if any(sus_name in name.lower() for sus_name in suspicious_names):
            suspicious.append(f"Suspicious section name: {name}")

        # Executable data sections (unusual)
        if name.lower() in ['.data', '.rdata', '.idata'] and "EXECUTE" in characteristics:
            suspicious.append(f"Unusual executable {name} section")

        return suspicious
