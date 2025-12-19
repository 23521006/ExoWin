"""
Console reporter for terminal output
"""
from typing import Any, Dict
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from exowin.reporters.base import BaseReporter


class ConsoleReporter(BaseReporter):
    """Generate colored console output using Rich"""

    def __init__(self):
        super().__init__()
        self.console = Console()

    def generate(self, analysis_result: Dict[str, Any], output_path: str = None) -> str:
        """Generate console output"""
        # File Information
        self._print_file_info(analysis_result.get("file_info", {}))

        # PE Information
        self._print_pe_info(analysis_result.get("headers", {}))

        # Suspicious Indicators
        indicators = analysis_result.get("suspicious_indicators", [])
        if indicators:
            self._print_suspicious_indicators(indicators)

        # Sections
        sections = analysis_result.get("sections", {})
        if sections.get("sections"):
            self._print_sections(sections)

        # Suspicious APIs
        imports = analysis_result.get("imports", {})
        suspicious_apis = imports.get("suspicious_apis", {})
        if suspicious_apis:
            self._print_suspicious_apis(suspicious_apis)

        # Strings
        strings = analysis_result.get("strings", {})
        if strings.get("categorized"):
            self._print_strings(strings)

        return "Console output generated"

    def _print_file_info(self, file_info: Dict[str, Any]):
        """Print file information"""
        entropy = file_info.get("entropy", 0)

        # Choose color based on entropy
        if entropy > 7.0:
            entropy_color = "red"
        elif entropy > 6.0:
            entropy_color = "yellow"
        else:
            entropy_color = "green"

        info_text = f"""[bold]Filename:[/bold] {file_info.get("filename", "Unknown")}
    [bold]Size:[/bold] {file_info.get("size", 0):,} bytes
    [bold]MD5:[/bold] {file_info.get("md5", "N/A")}
    [bold]SHA256:[/bold] {file_info.get("sha256", "N/A")}
    [bold]Entropy:[/bold] [{entropy_color}]{entropy}[/{entropy_color}] - {file_info.get("entropy_interpretation", "")}"""

        if file_info.get("imphash"):
            info_text += f"\n[bold]Imphash:[/bold] {file_info.get('imphash')}"

        panel = Panel(
            info_text,
            title="File Information",
            border_style="blue",
            box=box.ROUNDED
        )
        self.console.print(panel)
        self.console.print()

    def _print_pe_info(self, headers: Dict[str, Any]):
        """Print PE information"""
        file_header = headers.get("file_header", {})
        opt_header = headers.get("optional_header", {})

        info_text = f"""[bold]Type:[/bold] {headers.get("pe_type", "Unknown")}
[bold]Machine:[/bold] {file_header.get("Machine", "Unknown")}
[bold]Subsystem:[/bold] {opt_header.get("Subsystem", "Unknown")}
[bold]Timestamp:[/bold] {file_header.get("TimeDateStamp", "Unknown")}
[bold]Entry Point:[/bold] {opt_header.get("AddressOfEntryPoint", "N/A")}
[bold]Image Base:[/bold] {opt_header.get("ImageBase", "N/A")}"""

        panel = Panel(
            info_text,
            title="PE Information",
            border_style="cyan",
            box=box.ROUNDED
        )
        self.console.print(panel)
        self.console.print()

    def _print_suspicious_indicators(self, indicators: list):
        """Print suspicious indicators"""
        text = "\n".join([f"WARNING: {ind}" for ind in indicators])

        panel = Panel(
            text,
            title="Suspicious Indicators",
            border_style="red",
            box=box.ROUNDED
        )
        self.console.print(panel)
        self.console.print()

    def _print_sections(self, sections: Dict[str, Any]):
        """Print sections table"""
        table = Table(title="Sections", box=box.ROUNDED)

        table.add_column("Name", style="cyan")
        table.add_column("Virtual Size", justify="right")
        table.add_column("Raw Size", justify="right")
        table.add_column("Entropy", justify="right")
        table.add_column("Characteristics", style="dim")

        for section in sections.get("sections", []):
            entropy = section.get("Entropy", 0)

            # Color entropy based on value
            if entropy > 7.0:
                entropy_str = f"[red]{entropy}[/red]"
            elif entropy > 6.0:
                entropy_str = f"[yellow]{entropy}[/yellow]"
            else:
                entropy_str = f"[green]{entropy}[/green]"

            chars = ", ".join(section.get("Characteristics", []))[:40]

            table.add_row(
                section.get("Name", ""),
                f"{section.get('VirtualSize', 0):,}",
                f"{section.get('RawSize', 0):,}",
                entropy_str,
                chars
            )

        self.console.print(table)
        self.console.print()

    def _print_suspicious_apis(self, suspicious_apis: Dict[str, list]):
        """Print suspicious APIs"""
        for category, apis in suspicious_apis.items():
            title = category.replace('_', ' ').title()
            api_list = ", ".join(apis[:10])

            panel = Panel(
                api_list,
                title=f"{title}",
                border_style="yellow",
                box=box.ROUNDED
            )
            self.console.print(panel)

        self.console.print()

    def _print_strings(self, strings: Dict[str, Any]):
        """Print strings analysis"""
        categorized = strings.get("categorized", {})

        if categorized.get("urls"):
            urls = "\n".join(categorized["urls"][:10])
            panel = Panel(
                urls,
                title=f"URLs ({len(categorized['urls'])} found)",
                border_style="blue",
                box=box.ROUNDED
            )
            self.console.print(panel)

        if categorized.get("ip_addresses"):
            ips = "\n".join(categorized["ip_addresses"][:10])
            panel = Panel(
                ips,
                title=f"IP Addresses ({len(categorized['ip_addresses'])} found)",
                border_style="cyan",
                box=box.ROUNDED
            )
            self.console.print(panel)

        if categorized.get("suspicious_keywords"):
            keywords = ", ".join(categorized["suspicious_keywords"][:20])
            panel = Panel(
                keywords,
                title="Suspicious Keywords",
                border_style="red",
                box=box.ROUNDED
            )
            self.console.print(panel)

        self.console.print()
