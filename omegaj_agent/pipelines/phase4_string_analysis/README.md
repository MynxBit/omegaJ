# Phase 4 – IOC String Analysis

Purpose:
- Extract and score IOCs from text artifacts (e.g., Phase 1 report, tool outputs).

What it does:
- Controlled regex-based extraction of emails, URLs, IPs, file paths, suspicious commands/files, and registry keys.
- Dedupes and assigns a simple risk score per IOC type.
- Produces a categorized JSON file for downstream processing.

How it works:
- `omegaJ_phase4.py` reads a text file, applies configurable regex patterns, and writes JSON.

Inputs:
- Path to a text file (commonly the Phase 1 report).

Outputs:
- JSON file in `phase4_output/` named `<input>_phase4.json`.

Operational notes:
- Patterns are in-code but can be externalized later (see TODO).
- Extend with decoders (Base64/URL) as needed before matching.
