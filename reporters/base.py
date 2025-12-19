"""
Base reporter class
"""
from abc import ABC, abstractmethod
from typing import Any, Dict


class BaseReporter(ABC):
    """Base class for all reporters"""

    def __init__(self):
        self.name = self.__class__.__name__

    @abstractmethod
    def generate(self, analysis_result: Dict[str, Any], output_path: str = None) -> str:
        """
        Generate report from analysis results

        Args:
            analysis_result: Dictionary containing analysis results
            output_path: Optional path to save report

        Returns:
            Report content as string
        """
        pass

