"""
Base extractor class for all feature extractors
"""
from abc import ABC, abstractmethod
from typing import Any, Dict
import pefile


class BaseExtractor(ABC):
    """Base class for all feature extractors"""

    def __init__(self):
        self.name = self.__class__.__name__

    @abstractmethod
    def extract(self, pe: pefile.PE, filepath: str = None) -> Dict[str, Any]:
        """
        Extract features from PE file

        Args:
            pe: pefile.PE object
            filepath: Optional path to the PE file

        Returns:
            Dictionary containing extracted features
        """
        pass

    def extract_safe(self, pe: pefile.PE, filepath: str = None) -> Dict[str, Any]:
        """
        Safely extract features, catching and logging any errors

        Args:
            pe: pefile.PE object
            filepath: Optional path to the PE file

        Returns:
            Dictionary containing extracted features or error info
        """
        try:
            return self.extract(pe, filepath)
        except Exception as e:
            return {
                "error": str(e),
                "extractor": self.name
            }

