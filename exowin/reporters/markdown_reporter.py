"""
Markdown reporter - Detailed version matching JSON output
"""
from pathlib import Path
from typing import Any, Dict, List, Optional

from exowin.reporters.base import BaseReporter


class MarkdownReporter(BaseReporter):
    """Generate detailed Markdown reports"""

    def generate(self, analysis_result: Dict[str, Any], output_path: Optional[str] = None) -> str:
        """Generate detailed Markdown report"""
        md_lines = []

        # Title
        file_info = analysis_result.get("file_info", {})
        filename = file_info.get("filename", "Unknown")
        md_lines.append(f"# Malware Analysis Report: {filename}\n")

        # Table of Contents
        md_lines.append("## Table of Contents\n")
        md_lines.append("1. [File Information](#file-information)")
        md_lines.append("2. [Suspicious Indicators](#suspicious-indicators)")
        md_lines.append("3. [PE Headers](#pe-headers)")
        md_lines.append("4. [Sections](#sections)")
        md_lines.append("5. [Imports](#imports)")
        md_lines.append("6. [Exports](#exports)")
        md_lines.append("7. [Strings Analysis](#strings-analysis)")
        md_lines.append("")

        # File Information - Detailed
        md_lines.append("---\n")
        md_lines.append("## File Information\n")
        md_lines.append(f"| Property | Value |")
        md_lines.append("|----------|-------|")
        md_lines.append(f"| **Filename** | `{filename}` |")
        md_lines.append(f"| **Filepath** | `{file_info.get('filepath', 'N/A')}` |")
        md_lines.append(f"| **Size** | {file_info.get('size', 0):,} bytes |")
        md_lines.append(f"| **MD5** | `{file_info.get('md5', 'N/A')}` |")
        md_lines.append(f"| **SHA1** | `{file_info.get('sha1', 'N/A')}` |")
        md_lines.append(f"| **SHA256** | `{file_info.get('sha256', 'N/A')}` |")
        md_lines.append(f"| **Imphash** | `{file_info.get('imphash', 'N/A')}` |")
        if file_info.get('ssdeep'):
            md_lines.append(f"| **SSDeep** | `{file_info.get('ssdeep')}` |")
        md_lines.append(f"| **Entropy** | {file_info.get('entropy', 0)} |")
        md_lines.append(f"| **Entropy Interpretation** | {file_info.get('entropy_interpretation', 'N/A')} |")
        md_lines.append("")

        # Suspicious Indicators
        indicators = analysis_result.get("suspicious_indicators", [])
        md_lines.append("---\n")
        md_lines.append("## Suspicious Indicators\n")
        if indicators:
            for indicator in indicators:
                md_lines.append(f"- {indicator}")
        else:
            md_lines.append("- No suspicious indicators detected")
        md_lines.append("")

        # PE Headers - Detailed
        headers = analysis_result.get("headers", {})
        md_lines.append("---\n")
        md_lines.append("## PE Headers\n")

        # DOS Header
        dos_header = headers.get("dos_header", {})
        if dos_header:
            md_lines.append("### DOS Header\n")
            md_lines.append("| Field | Value |")
            md_lines.append("|-------|-------|")
            for key, value in dos_header.items():
                md_lines.append(f"| {key} | `{value}` |")
            md_lines.append("")

        # File Header
        file_header = headers.get("file_header", {})
        if file_header:
            md_lines.append("### File Header (COFF)\n")
            md_lines.append("| Field | Value |")
            md_lines.append("|-------|-------|")
            for key, value in file_header.items():
                if key == "Characteristics":
                    chars = ", ".join(value) if isinstance(value, list) else value
                    md_lines.append(f"| {key} | {chars} |")
                else:
                    md_lines.append(f"| {key} | `{value}` |")
            md_lines.append("")

        # Optional Header
        opt_header = headers.get("optional_header", {})
        if opt_header:
            md_lines.append("### Optional Header\n")
            md_lines.append("| Field | Value |")
            md_lines.append("|-------|-------|")
            for key, value in opt_header.items():
                md_lines.append(f"| {key} | `{value}` |")
            md_lines.append("")

        # PE Type
        md_lines.append(f"**PE Type**: `{headers.get('pe_type', 'Unknown')}`\n")

        # Warnings
        warnings = headers.get("warnings", [])
        if warnings:
            md_lines.append("### PE Parsing Warnings\n")
            for warning in warnings:
                md_lines.append(f"- {warning}")
            md_lines.append("")

        # Sections - Detailed
        sections = analysis_result.get("sections", {})
        md_lines.append("---\n")
        md_lines.append("## Sections\n")
        md_lines.append(f"**Total Sections**: {sections.get('count', 0)}\n")

        if sections.get("sections"):
            md_lines.append("| Name | Virtual Address | Virtual Size | Raw Size | Entropy | MD5 | Characteristics |")
            md_lines.append("|------|-----------------|--------------|----------|---------|-----|-----------------|")
            for section in sections["sections"]:
                name = section.get("Name", "")
                vaddr = section.get("VirtualAddress", "0x0")
                vsize = section.get("VirtualSize", 0)
                rsize = section.get("RawSize", 0)
                entropy = section.get("Entropy", 0)
                md5 = section.get("MD5", "N/A")[:16] + "..." if len(section.get("MD5", "")) > 16 else section.get("MD5", "N/A")
                chars = ", ".join(section.get("Characteristics", []))
                md_lines.append(f"| {name} | `{vaddr}` | {vsize:,} | {rsize:,} | {entropy:.2f} | `{md5}` | {chars} |")
            md_lines.append("")

            # Section Details
            md_lines.append("### Section Details\n")
            for section in sections["sections"]:
                name = section.get("Name", "Unknown")
                md_lines.append(f"#### {name}\n")
                md_lines.append(f"- **Virtual Address**: `{section.get('VirtualAddress', 'N/A')}`")
                md_lines.append(f"- **Virtual Size**: {section.get('VirtualSize', 0):,} bytes")
                md_lines.append(f"- **Raw Size**: {section.get('RawSize', 0):,} bytes")
                md_lines.append(f"- **Entropy**: {section.get('Entropy', 0):.4f}")
                md_lines.append(f"- **MD5**: `{section.get('MD5', 'N/A')}`")
                md_lines.append(f"- **Characteristics**: {', '.join(section.get('Characteristics', []))}")
                suspicious = section.get("suspicious", [])
                if suspicious:
                    md_lines.append(f"- **Suspicious**: {', '.join(suspicious)}")
                md_lines.append("")

        # Imports - Detailed
        imports = analysis_result.get("imports", {})
        md_lines.append("---\n")
        md_lines.append("## Imports\n")

        # Suspicious APIs first
        suspicious_apis = imports.get("suspicious_apis", {})
        if suspicious_apis:
            md_lines.append("### Suspicious APIs\n")
            for category, apis in suspicious_apis.items():
                md_lines.append(f"#### {category.replace('_', ' ').title()}")
                for api in apis:
                    md_lines.append(f"- `{api}`")
                md_lines.append("")

        # All Imports by DLL
        import_list = imports.get("imports", [])
        if import_list:
            md_lines.append("### Import Table\n")
            for dll_import in import_list:
                dll_name = dll_import.get("dll", "Unknown")
                func_count = dll_import.get("function_count", len(dll_import.get("functions", [])))
                md_lines.append(f"#### {dll_name} ({func_count} functions)\n")

                functions = dll_import.get("functions", [])
                if functions:
                    md_lines.append("| Function | Address | Ordinal |")
                    md_lines.append("|----------|---------|---------|")
                    for func in functions:
                        fname = func.get("name", "N/A")
                        faddr = func.get("address", "N/A")
                        fordinal = func.get("ordinal", "N/A")
                        ordinal_str = str(fordinal) if fordinal is not None else "-"
                        md_lines.append(f"| `{fname}` | `{faddr}` | {ordinal_str} |")
                    md_lines.append("")

        # Exports
        exports = imports.get("exports", {})
        md_lines.append("---\n")
        md_lines.append("## Exports\n")
        export_count = exports.get("count", 0)
        md_lines.append(f"**Total Exports**: {export_count}\n")

        export_functions = exports.get("functions", [])
        if export_functions:
            md_lines.append("| Function | Address | Ordinal |")
            md_lines.append("|----------|---------|---------|")
            for func in export_functions:
                if isinstance(func, dict):
                    fname = func.get("name", "N/A")
                    faddr = func.get("address", "N/A")
                    fordinal = func.get("ordinal", "N/A")
                else:
                    fname = str(func)
                    faddr = "N/A"
                    fordinal = "N/A"
                md_lines.append(f"| `{fname}` | `{faddr}` | {fordinal} |")
            md_lines.append("")
        else:
            md_lines.append("*No exports found*\n")

        # Strings Analysis - Detailed
        strings = analysis_result.get("strings", {})
        md_lines.append("---\n")
        md_lines.append("## Strings Analysis\n")

        # String Statistics
        md_lines.append("### Statistics\n")
        md_lines.append(f"| Metric | Count |")
        md_lines.append("|--------|-------|")
        md_lines.append(f"| Total Strings | {strings.get('total_count', 0)} |")
        md_lines.append(f"| ASCII Strings | {strings.get('ascii_count', 0)} |")
        md_lines.append(f"| Unicode Strings | {strings.get('unicode_count', 0)} |")
        md_lines.append("")

        # Categorized Strings
        categorized = strings.get("categorized", {})

        if categorized.get("urls"):
            md_lines.append("### URLs Found\n")
            for url in categorized["urls"]:
                md_lines.append(f"- `{url}`")
            md_lines.append("")

        if categorized.get("ip_addresses"):
            md_lines.append("### IP Addresses\n")
            for ip in categorized["ip_addresses"]:
                md_lines.append(f"- `{ip}`")
            md_lines.append("")

        if categorized.get("emails"):
            md_lines.append("### Email Addresses\n")
            for email in categorized["emails"]:
                md_lines.append(f"- `{email}`")
            md_lines.append("")

        if categorized.get("registry_keys"):
            md_lines.append("### Registry Keys\n")
            for key in categorized["registry_keys"]:
                md_lines.append(f"- `{key}`")
            md_lines.append("")

        if categorized.get("file_paths"):
            md_lines.append("### File Paths\n")
            for path in categorized["file_paths"]:
                md_lines.append(f"- `{path}`")
            md_lines.append("")

        if categorized.get("suspicious_keywords"):
            md_lines.append("### Suspicious Keywords\n")
            for keyword in categorized["suspicious_keywords"]:
                md_lines.append(f"- `{keyword}`")
            md_lines.append("")

        # All Strings
        all_strings = strings.get("all_strings", [])
        if all_strings:
            md_lines.append("### All Extracted Strings\n")
            md_lines.append("<details>")
            md_lines.append("<summary>Click to expand ({} strings)</summary>\n".format(len(all_strings)))
            md_lines.append("```")
            for s in all_strings:
                # Escape markdown special characters
                escaped = str(s).replace("|", "\\|").replace("`", "\\`")
                md_lines.append(escaped)
            md_lines.append("```")
            md_lines.append("</details>")
            md_lines.append("")

        # Footer
        md_lines.append("---\n")
        md_lines.append("*Generated by ExoWin v1.0.0*")

        # Generate report
        md_content = "\n".join(md_lines)

        # Save to file if path provided
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(md_content)

        return md_content
