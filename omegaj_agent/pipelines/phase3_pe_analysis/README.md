# Phase 3 – PE Analysis (PEStudio-first, Python fallback)

Purpose:
- Perform deeper static analysis of PE files (sections, imports, overlay, signature, VT link).
- Prefer a headless PEStudio CLI when available; otherwise use a Python fallback.

What it does:
- Attempts to locate PEStudio professional CLI `pestudiox.exe` and export XML headlessly.
- Parses the XML into a readable section appended to the Phase 1 report.
- If the CLI is not present, uses a Python-only analysis (pefile-based) covering core fields.

How it works:
- `pestudio_runner.py` attempts CLI discovery and export; returns None when CLI is unavailable.
- `fallback_pe_analysis.py` uses `pefile`, custom entropy, and simple heuristics; always safe.

Inputs:
- `sample_path` (string), `output_file` (string)

Outputs:
- Appended text in the Phase 1 report.

Operational notes:
- Current default is Python fallback unless `pestudiox.exe` is found.
- A TODO tracks optional integration of alternative CLI backends (e.g., pestudio-cli).
