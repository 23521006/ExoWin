"""
Disassembly extractor
"""
from typing import Any, Dict, List
import pefile

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

from exowin.extractors.base import BaseExtractor


class DisasmExtractor(BaseExtractor):
    """Disassemble code from entry point"""

    def extract(self, pe: pefile.PE, filepath: str = None, num_instructions: int = 40) -> Dict[str, Any]:
        """Disassemble instructions from entry point"""
        if not CAPSTONE_AVAILABLE:
            return {
                "error": "Capstone not available. Install with: pip install capstone",
                "instructions": []
            }

        try:
            # Get entry point
            entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            entry_point_rva = entry_point

            # Get code from entry point
            code_data = pe.get_memory_mapped_image()[entry_point:entry_point + num_instructions * 15]

            # Determine architecture
            if pe.FILE_HEADER.Machine == 0x14c:  # IMAGE_FILE_MACHINE_I386
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            elif pe.FILE_HEADER.Machine == 0x8664:  # IMAGE_FILE_MACHINE_AMD64
                md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            else:
                return {
                    "error": f"Unsupported architecture: 0x{pe.FILE_HEADER.Machine:x}",
                    "instructions": []
                }

            # Disassemble
            instructions = []
            count = 0
            for insn in md.disasm(code_data, entry_point_rva):
                if count >= num_instructions:
                    break

                instructions.append({
                    "address": hex(insn.address),
                    "mnemonic": insn.mnemonic,
                    "operands": insn.op_str,
                    "bytes": insn.bytes.hex(),
                    "size": insn.size,
                })
                count += 1

            return {
                "entry_point": hex(entry_point),
                "instruction_count": len(instructions),
                "instructions": instructions,
            }

        except Exception as e:
            return {
                "error": f"Failed to disassemble: {str(e)}",
                "instructions": []
            }
