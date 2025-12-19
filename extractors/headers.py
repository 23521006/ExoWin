"""
PE Headers extractor
"""
import datetime
from typing import Any, Dict
import pefile

from exowin.extractors.base import BaseExtractor


class HeadersExtractor(BaseExtractor):
    """Extract PE header information"""

    def extract(self, pe: pefile.PE, filepath: str = None) -> Dict[str, Any]:
        """Extract PE headers information"""
        headers = {}

        # DOS Header
        headers["dos_header"] = {
            "e_magic": hex(pe.DOS_HEADER.e_magic),
            "e_lfanew": hex(pe.DOS_HEADER.e_lfanew),
        }

        # File Header (COFF)
        file_header = pe.FILE_HEADER
        headers["file_header"] = {
            "Machine": self._get_machine_type(file_header.Machine),
            "NumberOfSections": file_header.NumberOfSections,
            "TimeDateStamp": self._get_timestamp(file_header.TimeDateStamp),
            "TimeDateStamp_raw": file_header.TimeDateStamp,
            "PointerToSymbolTable": hex(file_header.PointerToSymbolTable),
            "NumberOfSymbols": file_header.NumberOfSymbols,
            "SizeOfOptionalHeader": file_header.SizeOfOptionalHeader,
            "Characteristics": self._get_characteristics(file_header.Characteristics),
        }

        # Optional Header
        opt_header = pe.OPTIONAL_HEADER
        headers["optional_header"] = {
            "Magic": self._get_magic_type(opt_header.Magic),
            "MajorLinkerVersion": opt_header.MajorLinkerVersion,
            "MinorLinkerVersion": opt_header.MinorLinkerVersion,
            "SizeOfCode": opt_header.SizeOfCode,
            "SizeOfInitializedData": opt_header.SizeOfInitializedData,
            "SizeOfUninitializedData": opt_header.SizeOfUninitializedData,
            "AddressOfEntryPoint": hex(opt_header.AddressOfEntryPoint),
            "BaseOfCode": hex(opt_header.BaseOfCode),
            "ImageBase": hex(opt_header.ImageBase),
            "SectionAlignment": hex(opt_header.SectionAlignment),
            "FileAlignment": hex(opt_header.FileAlignment),
            "MajorOperatingSystemVersion": opt_header.MajorOperatingSystemVersion,
            "MinorOperatingSystemVersion": opt_header.MinorOperatingSystemVersion,
            "MajorImageVersion": opt_header.MajorImageVersion,
            "MinorImageVersion": opt_header.MinorImageVersion,
            "MajorSubsystemVersion": opt_header.MajorSubsystemVersion,
            "MinorSubsystemVersion": opt_header.MinorSubsystemVersion,
            "SizeOfImage": opt_header.SizeOfImage,
            "SizeOfHeaders": opt_header.SizeOfHeaders,
            "CheckSum": hex(opt_header.CheckSum),
            "Subsystem": self._get_subsystem(opt_header.Subsystem),
            "DllCharacteristics": hex(opt_header.DllCharacteristics),
            "SizeOfStackReserve": opt_header.SizeOfStackReserve,
            "SizeOfStackCommit": opt_header.SizeOfStackCommit,
            "SizeOfHeapReserve": opt_header.SizeOfHeapReserve,
            "SizeOfHeapCommit": opt_header.SizeOfHeapCommit,
            "NumberOfRvaAndSizes": opt_header.NumberOfRvaAndSizes,
        }

        # PE Type
        headers["pe_type"] = self._get_pe_type(pe)

        # Warnings
        headers["warnings"] = pe.get_warnings()

        return headers

    def _get_machine_type(self, machine: int) -> str:
        """Get machine type string"""
        machine_types = {
            0x14c: "I386",
            0x8664: "AMD64",
            0x1c0: "ARM",
            0xaa64: "ARM64",
            0x1a2: "SH3",
            0x1a6: "SH4",
        }
        return machine_types.get(machine, f"Unknown (0x{machine:x})")

    def _get_timestamp(self, timestamp: int) -> str:
        """Convert timestamp to ISO format"""
        try:
            return datetime.datetime.utcfromtimestamp(timestamp).isoformat()
        except (ValueError, OSError):
            return "Invalid timestamp"

    def _get_characteristics(self, characteristics: int) -> list:
        """Get list of characteristics"""
        char_flags = {
            0x0001: "RELOCS_STRIPPED",
            0x0002: "EXECUTABLE_IMAGE",
            0x0004: "LINE_NUMS_STRIPPED",
            0x0008: "LOCAL_SYMS_STRIPPED",
            0x0010: "AGGRESSIVE_WS_TRIM",
            0x0020: "LARGE_ADDRESS_AWARE",
            0x0080: "BYTES_REVERSED_LO",
            0x0100: "32BIT_MACHINE",
            0x0200: "DEBUG_STRIPPED",
            0x0400: "REMOVABLE_RUN_FROM_SWAP",
            0x0800: "NET_RUN_FROM_SWAP",
            0x1000: "SYSTEM",
            0x2000: "DLL",
            0x4000: "UP_SYSTEM_ONLY",
            0x8000: "BYTES_REVERSED_HI",
        }

        return [name for flag, name in char_flags.items() if characteristics & flag]

    def _get_magic_type(self, magic: int) -> str:
        """Get PE magic type"""
        if magic == 0x10b:
            return "PE32"
        elif magic == 0x20b:
            return "PE32+"
        else:
            return f"Unknown (0x{magic:x})"

    def _get_subsystem(self, subsystem: int) -> str:
        """Get subsystem string"""
        subsystems = {
            1: "NATIVE",
            2: "WINDOWS_GUI",
            3: "WINDOWS_CUI",
            7: "POSIX_CUI",
            9: "WINDOWS_CE_GUI",
            10: "EFI_APPLICATION",
            11: "EFI_BOOT_SERVICE_DRIVER",
            12: "EFI_RUNTIME_DRIVER",
            13: "EFI_ROM",
            14: "XBOX",
        }
        return subsystems.get(subsystem, f"Unknown ({subsystem})")

    def _get_pe_type(self, pe: pefile.PE) -> str:
        """Determine PE type"""
        if pe.is_driver():
            return "Driver"
        elif pe.is_dll():
            return "DLL"
        elif pe.is_exe():
            return "EXE"
        else:
            return "Unknown"
