# Phase 2 – Detect It Easy (DIE) Analysis

Purpose:
- Locate and run the Detect It Easy (DIE) console to gather quick file technology info.
- Append results to the Phase 1 analysis file.

What it does:
- Auto-discovers `diec.exe`/`die.exe` in PATH, common locations, Program Files, or a bounded C:\ scan.
- Tries JSON output first; falls back to textual output.
- Appends a titled section with DIE results or a clear failure reason.

How it works:
- `utils/detect_die.py` encapsulates discovery and invocation.
- `pipelines/phase2_die_analysis/runner.py` calls it and writes into the report file.

Inputs:
- `sample_path` (string) – the file to analyze
- `output_file` (string) – Phase 1 report path

Outputs:
- Appended text in the Phase 1 report.

Operational notes:
- If DIE isn’t found, the section records a helpful message and continues.
- Discovery prints friendly console messages so users see what’s happening.
