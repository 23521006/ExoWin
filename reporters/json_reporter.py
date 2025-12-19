"""
JSON reporter
"""
import json
from pathlib import Path
from typing import Any, Dict

from exowin.reporters.base import BaseReporter


class JSONReporter(BaseReporter):
    """Generate JSON reports"""

    def generate(self, analysis_result: Dict[str, Any], output_path: str = None) -> str:
        """Generate JSON report"""
        # Convert to JSON string
        json_str = json.dumps(analysis_result, indent=2, ensure_ascii=False)

        # Save to file if path provided
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(json_str)

        return json_str
