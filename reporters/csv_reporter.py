"""
CSV Reporter for ML feature extraction
"""
import csv
from pathlib import Path
from typing import Any, Dict, List, Optional

from exowin.reporters.base import BaseReporter


class CSVReporter(BaseReporter):
    """Generate CSV output for ML features"""

    def __init__(self):
        self.fieldnames = None

    def generate(self, data: Dict[str, Any], output_path: str = None) -> str:
        """
        Generate CSV from ML features data

        Args:
            data: Dictionary containing ML features (or list of feature dicts)
            output_path: Optional path to save CSV file

        Returns:
            CSV string
        """
        # Handle single record or list of records
        if isinstance(data, list):
            records = data
        else:
            records = [data]

        if not records:
            return ""

        # Get fieldnames from first record
        self.fieldnames = list(records[0].keys())

        # Generate CSV content
        output = self._generate_csv_string(records)

        # Save to file if path provided
        if output_path:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                f.write(output)

        return output

    def _generate_csv_string(self, records: List[Dict[str, Any]]) -> str:
        """Generate CSV string from records"""
        import io

        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=self.fieldnames)

        writer.writeheader()
        for record in records:
            writer.writerow(record)

        return output.getvalue()

    def append_to_file(self, data: Dict[str, Any], output_path: str,
                       write_header: bool = False) -> None:
        """
        Append a single record to existing CSV file

        Args:
            data: Dictionary containing ML features
            output_path: Path to CSV file
            write_header: Whether to write header row
        """
        file_exists = Path(output_path).exists()

        fieldnames = list(data.keys())

        with open(output_path, 'a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)

            # Write header if file is new or explicitly requested
            if write_header or not file_exists:
                writer.writeheader()

            writer.writerow(data)

    @staticmethod
    def generate_batch(records: List[Dict[str, Any]], output_path: str,
                       include_header: bool = True) -> None:
        """
        Generate CSV file from multiple records

        Args:
            records: List of feature dictionaries
            output_path: Path to save CSV file
            include_header: Whether to include header row
        """
        if not records:
            return

        fieldnames = list(records[0].keys())

        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)

            if include_header:
                writer.writeheader()

            writer.writerows(records)
