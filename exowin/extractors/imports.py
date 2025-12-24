"""
Imports/Exports extractor
"""
from typing import Any, Dict, List
import pefile

from exowin.extractors.base import BaseExtractor


class ImportsExtractor(BaseExtractor):
    """Extract imports and exports information"""

    # Suspicious APIs categorized by functionality
    SUSPICIOUS_APIS = {
        "process_injection": [
            "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
            "OpenProcess", "VirtualProtectEx", "SetThreadContext", "ResumeThread",
            "QueueUserAPC", "NtQueueApcThread", "RtlCreateUserThread"
        ],
        "keylogging": [
            "SetWindowsHookEx", "GetAsyncKeyState", "GetForegroundWindow",
            "GetKeyState", "AttachThreadInput"
        ],
        "anti_debugging": [
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
            "OutputDebugString", "FindWindow", "NtSetInformationThread"
        ],
        "network": [
            "InternetOpen", "InternetOpenUrl", "InternetReadFile", "URLDownloadToFile",
            "HttpSendRequest", "HttpOpenRequest", "InternetConnect", "send", "recv",
            "WSAStartup", "socket", "connect", "bind", "listen", "accept"
        ],
        "registry": [
            "RegSetValue", "RegSetValueEx", "RegCreateKey", "RegCreateKeyEx",
            "RegDeleteKey", "RegDeleteValue", "RegOpenKey", "RegOpenKeyEx"
        ],
        "file_operations": [
            "CreateFile", "WriteFile", "ReadFile", "DeleteFile", "CopyFile",
            "MoveFile", "FindFirstFile", "FindNextFile"
        ],
        "persistence": [
            "CreateService", "StartService", "OpenSCManager", "RegisterServiceCtrlHandler",
            "SetWindowsHookEx", "SHSetValue"
        ],
        "crypto": [
            "CryptAcquireContext", "CryptEncrypt", "CryptDecrypt", "CryptCreateHash",
            "CryptHashData", "CryptDeriveKey"
        ],
        "anti_vm": [
            "CreateToolhelp32Snapshot", "Process32First", "Process32Next"
        ]
    }

    def extract(self, pe: pefile.PE, filepath: str = None) -> Dict[str, Any]:
        """Extract imports and exports"""
        result = {
            "imports": self._extract_imports(pe),
            "exports": self._extract_exports(pe),
        }

        # Analyze suspicious APIs
        result["suspicious_apis"] = self._analyze_suspicious_apis(result["imports"])

        return result

    def _extract_imports(self, pe: pefile.PE) -> List[Dict[str, Any]]:
        """Extract import table"""
        imports = []

        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            return imports

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8') if isinstance(entry.dll, bytes) else str(entry.dll)

            functions = []
            for imp in entry.imports:
                if imp.name:
                    func_name = imp.name.decode('utf-8') if isinstance(imp.name, bytes) else str(imp.name)
                else:
                    func_name = f"Ordinal_{imp.ordinal}" if imp.ordinal else "Unknown"

                functions.append({
                    "name": func_name,
                    "address": hex(imp.address) if imp.address else None,
                    "ordinal": imp.ordinal if imp.ordinal else None,
                })

            imports.append({
                "dll": dll_name,
                "functions": functions,
                "function_count": len(functions),
            })

        return imports

    def _extract_exports(self, pe: pefile.PE) -> Dict[str, Any]:
        """Extract export table"""
        exports = {
            "functions": [],
            "count": 0,
        }

        if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            return exports

        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            func_name = exp.name.decode('utf-8') if exp.name and isinstance(exp.name, bytes) else str(exp.name) if exp.name else f"Ordinal_{exp.ordinal}"

            exports["functions"].append({
                "name": func_name,
                "address": hex(exp.address),
                "ordinal": exp.ordinal,
            })

        exports["count"] = len(exports["functions"])
        return exports

    def _analyze_suspicious_apis(self, imports: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Analyze imports for suspicious APIs"""
        found_suspicious = {}

        # Get all imported function names
        all_functions = []
        for dll_import in imports:
            for func in dll_import["functions"]:
                all_functions.append(func["name"])

        # Check against suspicious APIs
        for category, api_list in self.SUSPICIOUS_APIS.items():
            found = []
            for api in api_list:
                if api in all_functions:
                    found.append(api)

            if found:
                found_suspicious[category] = found

        return found_suspicious
