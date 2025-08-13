# Phase 1 – Analysis File Bootstrap

Purpose:
- Initialize a human-readable analysis report for the sample.
- Record metadata: sample name, path, timestamps.
- Create a stable target file that subsequent phases can append to.

What it does:
- Creates `<sample_name>_analysis_phase1.txt` in the current working directory.
- Writes basic headers and a separator line for readability.

How it works:
- Accepts the sample path.
- Derives `sample_name` from filename.
- Writes a simple header block and returns the output file path.

Inputs:
- `sample_path` (string)

Outputs:
- Path to the created analysis file (string)

Operational notes:
- Phase 1 is idempotent: re-running overwrites the same file.
- Downstream phases append; they do not overwrite.
