import argparse
import fnmatch
import os
import shutil
from pathlib import Path
from typing import List


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


def find_matching_files(base: Path, patterns: List[str]) -> List[Path]:
	matches: List[Path] = []
	for root, _dirs, files in os.walk(base):
		for name in files:
			for pat in patterns:
				if fnmatch.fnmatch(name, pat):
					matches.append(Path(root) / name)
					break
	return matches


def remove_paths(paths: List[Path], dry_run: bool) -> None:
	for p in paths:
		if not p.exists():
			continue
		if dry_run:
			print(f"[dry-run] Would remove: {p}")  # noqa: T201
			continue
		try:
			if p.is_dir():
				shutil.rmtree(p, ignore_errors=True)
			else:
				p.unlink(missing_ok=True)  # type: ignore[arg-type]
			print(f"Removed: {p}")  # noqa: T201
		except Exception as exc:
			print(f"[warn] Failed to remove {p}: {exc}")  # noqa: T201


def main() -> None:
	parser = argparse.ArgumentParser(description="Clean generated OmegaJ artifacts")
	parser.add_argument("--dry-run", action="store_true", help="List what would be removed without deleting")
	parser.add_argument("--yes", action="store_true", help="Proceed without confirmation")
	args = parser.parse_args()

	base = Path.cwd()
	print(f"Cleaning under: {base}")  # noqa: T201

	# Collect targets
	file_targets = find_matching_files(base, GENERATED_FILE_PATTERNS)
	dir_targets = [base / d for d in GENERATED_DIRS if (base / d).exists()]

	print("Files to remove:")  # noqa: T201
	for f in file_targets:
		print(f" - {f}")  # noqa: T201
	print("Dirs to remove:")  # noqa: T201
	for d in dir_targets:
		print(f" - {d}")  # noqa: T201

	if not args.yes and not args.dry_run:
		print("Use --yes to confirm deletion or --dry-run to preview.")  # noqa: T201
		return

	# Execute removals
	remove_paths(dir_targets, args.dry_run)
	remove_paths(file_targets, args.dry_run)

	print("Done.")  # noqa: T201


if __name__ == "__main__":
	main()


