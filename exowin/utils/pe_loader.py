"""
Utility functions for PE file loading
"""
from pathlib import Path
import pefile


def load_pe(filepath: str) -> pefile.PE:
    """
    Load a PE file safely

    Args:
        filepath: Path to PE file

    Returns:
        pefile.PE object

    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If file is not a valid PE
    """
    filepath = Path(filepath)

    if not filepath.exists():
        raise FileNotFoundError(f"File not found: {filepath}")

    try:
        pe = pefile.PE(str(filepath))
        return pe
    except pefile.PEFormatError as e:
        raise ValueError(f"Invalid PE file: {e}")


def is_pe_file(filepath: str) -> bool:
    """
    Check if a file is a valid PE file

    Args:
        filepath: Path to check

    Returns:
        True if valid PE, False otherwise
    """
    try:
        pe = pefile.PE(filepath)
        pe.close()
        return True
    except:
        return False

