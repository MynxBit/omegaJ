"""
Interactive OmegaJ CLI.

Features:
- Colorful, menu-driven UI
- Run all phases (0-5) or a specific phase
- Auto-resolve prerequisites (e.g., ensure Phase 1 file before Phase 2)
- Keeps existing sections unless overwrite is requested
"""

from pathlib import Path
from typing import Optional, List
import os
import shutil
import fnmatch

from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich import box

from .utils.env_loader import load_env_all
from .pipelines import (
	create_analysis_file,
	append_phase0_section,
	append_die_analysis,
	run_phase3_pestudio,
	run_phase3_fallback,
	phase4_analyze_file,
	analyze_phase5_from_report,
)
from .utils.analysis_file import analysis_path_for_sample, has_phase_section


console = Console()


def ensure_phase1_exists(sample_path: str) -> str:
	"""Ensure MD5-named analysis file exists and return its path."""
	report_path = analysis_path_for_sample(sample_path)
	if not Path(report_path).exists():
		create_analysis_file(sample_path)
	return str(report_path)


def run_phase0(sample_path: str, overwrite: bool) -> None:
	ensure_phase1_exists(sample_path)
	append_phase0_section(sample_path, overwrite=overwrite)


def run_phase1(sample_path: str) -> None:
	create_analysis_file(sample_path)


def run_phase2(sample_path: str, overwrite: bool) -> None:
	report_path = ensure_phase1_exists(sample_path)
	append_die_analysis(sample_path, report_path, overwrite=overwrite)


def run_phase3(sample_path: str, overwrite: bool) -> None:
	report_path = ensure_phase1_exists(sample_path)
	ok = run_phase3_pestudio(sample_path, report_path, overwrite=overwrite)
	if not ok:
		run_phase3_fallback(sample_path, report_path, overwrite=overwrite)


def run_phase4(sample_path: str, overwrite: bool) -> Optional[str]:
	ensure_phase1_exists(sample_path)
	# Analyze the binary directly for strings/IOCs and append readable text section
	return phase4_analyze_file(sample_path, append_to_report=True, overwrite=overwrite)


def run_phase5(sample_path: str) -> Optional[Path]:
	# Phase 5 should be last; it builds MAR+S from the MD5 report and generates a Groq report
	return analyze_phase5_from_report(sample_path)


def show_header() -> None:
	console.print(Panel.fit("[bold cyan]OmegaJ - Interactive Analyzer[/bold cyan]", box=box.ROUNDED))


def _normalize_path(raw_path: str) -> str:
	# Strip surrounding parentheses/quotes from copied defaults
	s = raw_path.strip()
	if (s.startswith("(") and s.endswith(")")) or (s.startswith("[") and s.endswith("]")):
		s = s[1:-1]
	if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
		s = s[1:-1]
	# Expand env vars and user home
	s = os.path.expandvars(os.path.expanduser(s))
	return s


def pick_sample_path() -> str:
	while True:
		raw = Prompt.ask("Enter sample path")
		path = _normalize_path(raw)
		if Path(path).exists():
			return path
		console.print(f"[yellow]Path not found:[/yellow] {path}")


def pick_menu() -> str:
	table = Table(title="Select Action", box=box.SIMPLE_HEAVY)
	table.add_column("No.", justify="right", style="bold white")
	table.add_column("Action", style="bold green")
	table.add_row("1", "Auto Analysis (Phases 0 → 5)")
	table.add_row("2", "Phase 0 – VT Precheck")
	table.add_row("3", "Phase 1 – Create/Ensure Analysis File")
	table.add_row("4", "Phase 2 – DIE Analysis")
	table.add_row("5", "Phase 3 – PE Analysis (PEStudio / Fallback)")
	table.add_row("6", "Phase 4 – IOC Extraction (strings)")
	table.add_row("7", "Phase 5 – MAR+S Report via Groq")
	table.add_row("8", "Clean generated artifacts")
	table.add_row("9", "Exit")
	console.print(table)
	choice = Prompt.ask("Enter choice [1-9]", choices=[str(i) for i in range(1, 10)], default="1")
	return choice


def maybe_overwrite() -> bool:
	return Confirm.ask("Overwrite existing sections if present?", default=False)


def run_auto(sample_path: str, overwrite: bool) -> None:
	console.rule("[bold]Running Auto Analysis[/bold]")
	# 0
	run_phase0(sample_path, overwrite)
	console.print("[green]✓ Phase 0 done[/green]")
	# 1
	run_phase1(sample_path)
	console.print("[green]✓ Phase 1 done[/green]")
	# 2
	run_phase2(sample_path, overwrite)
	console.print("[green]✓ Phase 2 done[/green]")
	# 3
	run_phase3(sample_path, overwrite)
	console.print("[green]✓ Phase 3 done[/green]")
	# 4
	run_phase4(sample_path, overwrite)
	console.print("[green]✓ Phase 4 done[/green]")
	# 5
	report = run_phase5(sample_path)
	console.print(f"[green]✓ Phase 5 done[/green] → [bold]{report}[/bold]")


# Cleaning support (in-CLI)
GENERATED_DIRS: List[str] = [
	"phase3_temp",
	"phase4_output",
	"phase5_output",
	"phase5_reports",
]

GENERATED_FILE_PATTERNS: List[str] = [
	"*_analysis.txt",
	"*_report.txt",
	"notepad_analysis_phase1.txt",
]


def _find_matching_files(base: Path, patterns: List[str]) -> List[Path]:
	matches: List[Path] = []
	for root, _dirs, files in os.walk(base):
		for name in files:
			for pat in patterns:
				if fnmatch.fnmatch(name, pat):
					matches.append(Path(root) / name)
					break
	return matches


def run_clean() -> None:
	base = Path.cwd()
	files = _find_matching_files(base, GENERATED_FILE_PATTERNS)
	dirs = [base / d for d in GENERATED_DIRS if (base / d).exists()]
	panel = Table(title="Artifacts to remove", box=box.SIMPLE)
	panel.add_column("Type", style="cyan", justify="right")
	panel.add_column("Path", style="magenta")
	for d in dirs:
		panel.add_row("dir", str(d))
	for f in files:
		panel.add_row("file", str(f))
	console.print(panel)
	if not dirs and not files:
		console.print("[green]Nothing to clean.[/green]")
		return
	if not Confirm.ask("Proceed with deletion?", default=False):
		console.print("[yellow]Cancelled.[/yellow]")
		return
	for d in dirs:
		try:
			shutil.rmtree(d, ignore_errors=True)
			console.print(f"[green]Removed dir:[/green] {d}")
		except Exception as exc:
			console.print(f"[red]Failed dir:[/red] {d} ({exc})")
	for f in files:
		try:
			Path(f).unlink(missing_ok=True)  # type: ignore[arg-type]
			console.print(f"[green]Removed file:[/green] {f}")
		except Exception as exc:
			console.print(f"[red]Failed file:[/red] {f} ({exc})")


def main() -> None:
	# Load environment early
	try:
		load_env_all(debug=False)
	except Exception:
		load_dotenv(); load_dotenv(Path(__file__).with_name('.env'))

	show_header()
	sample_path = pick_sample_path()

	while True:
		choice = pick_menu()
		if choice == "8":
			run_clean()
			continue
		if choice == "9":
			console.print("Goodbye!")
			return
		ow = maybe_overwrite()
		if choice == "1":
			run_auto(sample_path, ow)
		elif choice == "2":
			run_phase0(sample_path, ow)
		elif choice == "3":
			run_phase1(sample_path)
		elif choice == "4":
			run_phase2(sample_path, ow)
		elif choice == "5":
			run_phase3(sample_path, ow)
		elif choice == "6":
			run_phase4(sample_path, ow)
		elif choice == "7":
			# Guard: phase 5 should be last. If earlier sections missing, inform and offer auto.
			report_path = analysis_path_for_sample(sample_path)
			p4_present = has_phase_section(report_path, "PHASE4_IOC") if Path(report_path).exists() else False
			if not p4_present:
				console.print("[yellow]Phase 5 requires earlier phases. Running Auto Analysis instead.[/yellow]")
				run_auto(sample_path, ow)
			else:
				report = run_phase5(sample_path)
				console.print(f"[green]Phase 5 report:[/green] [bold]{report}[/bold]")


if __name__ == "__main__":
	main()


