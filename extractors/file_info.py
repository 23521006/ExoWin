"""
File information and hash extractor
"""
import hashlib
import math
from collections import Counter
from pathlib import Path
from typing import Any, Dict
import pefile
try:
    import ppdeep
    PPDEEP_AVAILABLE = True
except ImportError:
    PPDEEP_AVAILABLE = False

from exowin.extractors.base import BaseExtractor


class FileInfoExtractor(BaseExtractor):
    """Extract file information including hashes and entropy"""

    def calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0

        p, lns = Counter(data), float(len(data))
        return -sum(count/lns * math.log(count/lns, 2) for count in p.values())

    def extract(self, pe: pefile.PE, filepath: str = None) -> Dict[str, Any]:
        """Extract file info and hashes"""
        raw = bytes(pe.__data__)

        info = {
            "filename": Path(filepath).name if filepath else "unknown",
            "filepath": filepath,
            "size": len(raw),
            "md5": hashlib.md5(raw).hexdigest(),
            "sha1": hashlib.sha1(raw).hexdigest(),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "entropy": round(self.calculate_entropy(raw), 2),
        }

        # Calculate imphash
        try:
            info["imphash"] = pe.get_imphash()
        except Exception:
            info["imphash"] = None

        # Calculate ssdeep if available
        if PPDEEP_AVAILABLE:
            try:
                info["ssdeep"] = ppdeep.hash(raw)
            except Exception:
                info["ssdeep"] = None
        else:
            info["ssdeep"] = None

        # Entropy interpretation
        if info["entropy"] > 7.0:
            info["entropy_interpretation"] = "High - Likely packed/encrypted"
        elif info["entropy"] > 6.0:
            info["entropy_interpretation"] = "Medium-High - Possibly packed"
        elif info["entropy"] > 5.0:
            info["entropy_interpretation"] = "Medium - Normal executable"
        else:
            info["entropy_interpretation"] = "Low - Unusual for executable"

        return info
