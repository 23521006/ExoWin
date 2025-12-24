"""
CLI interface for ExoWin
"""
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console

from exowin.analyzer import ExoWinAnalyzer
from exowin.reporters import (
    JSONReporter,
    HTMLReporter,
    MarkdownReporter,
    ConsoleReporter,
    CSVReporter,
)
from exowin.extractors import MLFeaturesExtractor

app = typer.Typer(
    name="exowin",
    help="ExoWin - CLI tool for static analysis and feature extraction from PE files",
    add_completion=False,
)

console = Console()

# Initialize analyzer and reporters
analyzer = ExoWinAnalyzer()
reporters = {
    "json": JSONReporter(),
    "html": HTMLReporter(),
    "markdown": MarkdownReporter(),
    "console": ConsoleReporter(),
    "csv": CSVReporter(),
}

# ML Feature extractor
ml_extractor = MLFeaturesExtractor()


@app.command()
def gui():
    """
    Launch the graphical user interface
    """
    try:
        from exowin.gui import main as gui_main
        console.print("[blue]Launching GUI...[/blue]")
        gui_main()
    except ImportError as e:
        console.print(f"[red]Error launching GUI: {e}[/red]")
        console.print("[yellow]Make sure tkinter is installed[/yellow]")
        raise typer.Exit(1)


@app.command()
def analyze(
    filepath: Path = typer.Argument(..., help="Path to PE file to analyze"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file path"),
    format: str = typer.Option("console", "--format", "-f", help="Output format: console, json, html, markdown"),
    disasm: bool = typer.Option(False, "--disasm", "-d", help="Include disassembly"),
    num_instructions: int = typer.Option(40, "--num-instructions", "-n", help="Number of instructions to disassemble"),
):
    """
    Analyze PE file and generate full report
    """
    try:
        console.print(f"[blue]Analyzing file: {filepath}[/blue]")

        # Analyze file
        result = analyzer.analyze_file(
            str(filepath),
            include_disasm=disasm,
            num_instructions=num_instructions
        )

        # Generate report
        if format not in reporters:
            console.print(f"[red]Invalid format: {format}[/red]")
            console.print(f"[yellow]Valid formats: {', '.join(reporters.keys())}[/yellow]")
            raise typer.Exit(1)

        reporter = reporters[format]
        output_str = str(output) if output else None
        reporter.generate(result, output_str)

        if output:
            console.print(f"[green]Report saved: {output}[/green]")

    except FileNotFoundError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def info(
    filepath: Path = typer.Argument(..., help="Path to PE file"),
):
    """
    Display basic information about PE file
    """
    try:
        console.print(f"[blue]Getting file info: {filepath}[/blue]")

        result = analyzer.quick_info(str(filepath))

        # Display using console reporter
        console_reporter = ConsoleReporter()
        console_reporter._print_file_info(result["file_info"])

        console.print(f"[bold]Type:[/bold] {result['pe_type']}")
        console.print(f"[bold]Machine:[/bold] {result['machine']}")
        console.print(f"[bold]Subsystem:[/bold] {result['subsystem']}")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def sections(
    filepath: Path = typer.Argument(..., help="Path to PE file"),
):
    """
    Display sections information from PE file
    """
    try:
        import pefile

        console.print(f"[blue]Analyzing sections: {filepath}[/blue]")

        pe = pefile.PE(str(filepath))
        sections_extractor = analyzer.extractors["sections"]
        sections_data = sections_extractor.extract(pe, str(filepath))

        # Display using console reporter
        console_reporter = ConsoleReporter()
        console_reporter._print_sections(sections_data)

        pe.close()

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def imports(
    filepath: Path = typer.Argument(..., help="Path to PE file"),
    show_all: bool = typer.Option(False, "--all", "-a", help="Show all imports"),
):
    """
    Display imports and detect suspicious APIs
    """
    try:
        import pefile

        console.print(f"[blue]Analyzing imports: {filepath}[/blue]")

        pe = pefile.PE(str(filepath))
        imports_extractor = analyzer.extractors["imports"]
        imports_data = imports_extractor.extract(pe, str(filepath))

        # Display suspicious APIs
        suspicious_apis = imports_data.get("suspicious_apis", {})
        if suspicious_apis:
            console_reporter = ConsoleReporter()
            console_reporter._print_suspicious_apis(suspicious_apis)
        else:
            console.print("[green]No suspicious APIs detected[/green]")

        # Display all imports if requested
        if show_all:
            from rich.table import Table

            table = Table(title="All Imports")
            table.add_column("DLL", style="cyan")
            table.add_column("Functions", justify="right")

            for dll_import in imports_data.get("imports", []):
                table.add_row(
                    dll_import["dll"],
                    str(dll_import["function_count"])
                )

            console.print(table)

        pe.close()

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def strings(
    filepath: Path = typer.Argument(..., help="Path to PE file"),
):
    """
    Extract and categorize strings from PE file
    """
    try:
        import pefile

        console.print(f"[blue]Extracting strings: {filepath}[/blue]")

        pe = pefile.PE(str(filepath))
        strings_extractor = analyzer.extractors["strings"]
        strings_data = strings_extractor.extract(pe, str(filepath))

        # Display using console reporter
        console_reporter = ConsoleReporter()
        console_reporter._print_strings(strings_data)

        console.print(f"[bold]Total strings:[/bold] {strings_data.get('total_count', 0)}")

        pe.close()

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def disasm(
    filepath: Path = typer.Argument(..., help="Path to PE file"),
    num_instructions: int = typer.Option(40, "--num", "-n", help="Number of instructions"),
):
    """
    Disassemble code from entry point
    """
    try:
        import pefile

        console.print(f"[blue]Disassembling: {filepath}[/blue]")

        pe = pefile.PE(str(filepath))
        disasm_extractor = analyzer.extractors["disasm"]
        disasm_data = disasm_extractor.extract(pe, str(filepath), num_instructions)

        if "error" in disasm_data:
            console.print(f"[red]{disasm_data['error']}[/red]")
        else:
            from rich.table import Table

            table = Table(title=f"Disassembly from {disasm_data['entry_point']}")
            table.add_column("Address", style="cyan")
            table.add_column("Mnemonic", style="yellow")
            table.add_column("Operands", style="green")
            table.add_column("Bytes", style="dim")

            for insn in disasm_data["instructions"]:
                table.add_row(
                    insn["address"],
                    insn["mnemonic"],
                    insn["operands"],
                    insn["bytes"]
                )

            console.print(table)

        pe.close()

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def batch(
    input_dir: Path = typer.Argument(..., help="Directory containing PE files"),
    output_dir: Path = typer.Argument(..., help="Output directory for reports"),
    format: str = typer.Option("json", "--format", "-f", help="Output format: json, html, markdown"),
    pattern: str = typer.Option("*.exe", "--pattern", "-p", help="File pattern to search"),
):
    """
    Batch analyze multiple PE files in directory
    """
    try:
        if not input_dir.exists():
            console.print(f"[red]Directory not found: {input_dir}[/red]")
            raise typer.Exit(1)

        # Create output directory
        output_dir.mkdir(parents=True, exist_ok=True)

        # Find all PE files
        files = list(input_dir.glob(pattern))

        if not files:
            console.print(f"[yellow]No files found with pattern: {pattern}[/yellow]")
            raise typer.Exit(0)

        console.print(f"[blue]Found {len(files)} files[/blue]")

        # Analyze each file
        success_count = 0
        failed_count = 0

        for file in files:
            try:
                console.print(f"[cyan]Analyzing: {file.name}[/cyan]")

                result = analyzer.analyze_file(str(file))

                # Generate report
                output_filename = file.stem + f"_report.{format}"
                output_path = output_dir / output_filename

                reporter = reporters.get(format, JSONReporter())
                reporter.generate(result, str(output_path))

                success_count += 1
                console.print(f"[green]Saved: {output_path}[/green]")

            except Exception as e:
                failed_count += 1
                console.print(f"[red]Error analyzing {file.name}: {e}[/red]")

        console.print(f"\n[bold]Results:[/bold]")
        console.print(f"[green]Success: {success_count}[/green]")
        console.print(f"[red]Failed: {failed_count}[/red]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def compare(
    file1: Path = typer.Argument(..., help="First PE file"),
    file2: Path = typer.Argument(..., help="Second PE file"),
):
    """
    Compare two PE files
    """
    try:
        console.print(f"[blue]Comparing {file1.name} and {file2.name}[/blue]\n")

        # Analyze both files
        result1 = analyzer.analyze_file(str(file1))
        result2 = analyzer.analyze_file(str(file2))

        # Compare file info
        from rich.table import Table

        table = Table(title="File Information Comparison")
        table.add_column("Property", style="cyan")
        table.add_column(file1.name, style="yellow")
        table.add_column(file2.name, style="green")

        file_info_keys = ["size", "md5", "sha256", "entropy", "imphash"]
        for key in file_info_keys:
            val1 = result1["file_info"].get(key, "N/A")
            val2 = result2["file_info"].get(key, "N/A")

            # Highlight if different
            style1 = "red" if val1 != val2 else ""
            style2 = "red" if val1 != val2 else ""

            table.add_row(
                key.upper(),
                f"[{style1}]{val1}[/{style1}]" if style1 else str(val1),
                f"[{style2}]{val2}[/{style2}]" if style2 else str(val2)
            )

        console.print(table)

        # Compare sections
        sections1 = {s["Name"]: s for s in result1["sections"]["sections"]}
        sections2 = {s["Name"]: s for s in result2["sections"]["sections"]}

        all_sections = set(sections1.keys()) | set(sections2.keys())

        table = Table(title="Sections Comparison")
        table.add_column("Section", style="cyan")
        table.add_column(f"{file1.name} Entropy", justify="right")
        table.add_column(f"{file2.name} Entropy", justify="right")
        table.add_column("Status", style="yellow")

        for section_name in sorted(all_sections):
            s1 = sections1.get(section_name)
            s2 = sections2.get(section_name)

            if s1 and s2:
                entropy1 = s1["Entropy"]
                entropy2 = s2["Entropy"]
                diff = abs(entropy1 - entropy2)
                status = "Similar" if diff < 0.5 else "Different"
                table.add_row(section_name, str(entropy1), str(entropy2), status)
            elif s1:
                table.add_row(section_name, str(s1["Entropy"]), "N/A", "Only in file1")
            else:
                table.add_row(section_name, "N/A", str(s2["Entropy"]), "Only in file2")

        console.print(table)

        # Compare suspicious indicators
        ind1 = set(result1.get("suspicious_indicators", []))
        ind2 = set(result2.get("suspicious_indicators", []))

        common = ind1 & ind2
        only1 = ind1 - ind2
        only2 = ind2 - ind1

        if common or only1 or only2:
            console.print("\n[bold]Suspicious Indicators:[/bold]")

            if common:
                console.print(f"[yellow]Common ({len(common)}):[/yellow]")
                for ind in common:
                    console.print(f"  - {ind}")

            if only1:
                console.print(f"\n[red]Only in {file1.name} ({len(only1)}):[/red]")
                for ind in only1:
                    console.print(f"  - {ind}")

            if only2:
                console.print(f"\n[green]Only in {file2.name} ({len(only2)}):[/green]")
                for ind in only2:
                    console.print(f"  - {ind}")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def extract_features(
    filepath: Path = typer.Argument(..., help="Path to PE file"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output CSV file path"),
    label: Optional[str] = typer.Option(None, "--label", "-l", help="Label for the sample (e.g., 'malware', 'benign')"),
    append: bool = typer.Option(False, "--append", "-a", help="Append to existing CSV file"),
):
    """
    Extract ML features from PE file and save to CSV
    """
    try:
        import pefile

        console.print(f"[blue]Extracting ML features: {filepath}[/blue]")

        pe = pefile.PE(str(filepath))
        features = ml_extractor.extract(pe, str(filepath))

        # Add metadata
        features["filename"] = filepath.name
        if label:
            features["label"] = label

        pe.close()

        # Output
        if output:
            csv_reporter = CSVReporter()
            if append and output.exists():
                csv_reporter.append_to_file(features, str(output), write_header=False)
                console.print(f"[green]Features appended to: {output}[/green]")
            else:
                csv_reporter.generate(features, str(output))
                console.print(f"[green]Features saved to: {output}[/green]")
        else:
            # Display features in console
            from rich.table import Table

            table = Table(title="ML Features")
            table.add_column("Feature", style="cyan")
            table.add_column("Value", style="green")

            for key, value in features.items():
                table.add_row(str(key), str(value))

            console.print(table)

        console.print(f"[bold]Total features:[/bold] {len(features)}")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def batch_extract(
    input_dir: Path = typer.Argument(..., help="Directory containing PE files"),
    output: Path = typer.Argument(..., help="Output CSV file path"),
    pattern: str = typer.Option("*.exe", "--pattern", "-p", help="File pattern to search"),
    label: Optional[str] = typer.Option(None, "--label", "-l", help="Label for all samples"),
    recursive: bool = typer.Option(False, "--recursive", "-r", help="Search recursively"),
):
    """
    Batch extract ML features from multiple PE files to single CSV
    """
    try:
        import pefile

        if not input_dir.exists():
            console.print(f"[red]Directory not found: {input_dir}[/red]")
            raise typer.Exit(1)

        # Find all PE files
        if recursive:
            files = list(input_dir.rglob(pattern))
        else:
            files = list(input_dir.glob(pattern))

        if not files:
            console.print(f"[yellow]No files found with pattern: {pattern}[/yellow]")
            raise typer.Exit(0)

        console.print(f"[blue]Found {len(files)} files[/blue]")

        # Extract features from each file
        all_features = []
        success_count = 0
        failed_count = 0

        for file in files:
            try:
                console.print(f"[cyan]Processing: {file.name}[/cyan]")

                pe = pefile.PE(str(file))
                features = ml_extractor.extract(pe, str(file))

                # Add metadata
                features["filename"] = file.name
                features["filepath"] = str(file)
                if label:
                    features["label"] = label

                pe.close()

                all_features.append(features)
                success_count += 1

            except Exception as e:
                failed_count += 1
                console.print(f"[red]Error processing {file.name}: {e}[/red]")

        # Save all features to CSV
        if all_features:
            CSVReporter.generate_batch(all_features, str(output))
            console.print(f"\n[green]Features saved to: {output}[/green]")

        console.print(f"\n[bold]Results:[/bold]")
        console.print(f"[green]Success: {success_count}[/green]")
        console.print(f"[red]Failed: {failed_count}[/red]")
        console.print(f"[bold]Total features per sample:[/bold] {len(all_features[0]) if all_features else 0}")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def list_features():
    """
    List all available ML features
    """
    feature_names = ml_extractor.get_feature_names()

    from rich.table import Table

    table = Table(title="Available ML Features")
    table.add_column("#", style="dim", justify="right")
    table.add_column("Feature Name", style="cyan")
    table.add_column("Category", style="yellow")

    for i, name in enumerate(feature_names, 1):
        # Determine category based on prefix
        if name.startswith("file_"):
            category = "File"
        elif name.startswith("dos_"):
            category = "DOS Header"
        elif name.startswith("fh_"):
            category = "File Header"
        elif name.startswith("oh_"):
            category = "Optional Header"
        elif name.startswith("sec_"):
            category = "Sections"
        elif name.startswith("imp_"):
            category = "Imports"
        elif name.startswith("exp_"):
            category = "Exports"
        elif name.startswith("res_"):
            category = "Resources"
        elif name.startswith("dd_"):
            category = "Data Directory"
        elif name.startswith("is_"):
            category = "PE Type"
        else:
            category = "Other"

        table.add_row(str(i), name, category)

    console.print(table)
    console.print(f"\n[bold]Total features:[/bold] {len(feature_names)}")


@app.command()
def version():
    """
    Display ExoWin version
    """
    from exowin import __version__
    console.print(f"[bold blue]ExoWin v{__version__}[/bold blue]")
    console.print("ExoWin - Static analysis tool for PE files")

if __name__ == "__main__":
    app()
