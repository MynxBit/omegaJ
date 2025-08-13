# OmegaJ - Deferred Tasks

- [ ] Phase 3 (PEStudio CLI): Enable headless XML export when `pestudiox.exe` (professional CLI) is available
  - Detect `pestudiox.exe` in PATH and Program Files (already implemented)
  - If found, run headless export and append parsed XML to the phase1 report
  - Otherwise keep using Python fallback (current default)
  - Optional: support alternative CLI backends (e.g., pestudio-cli) if `pestudiox.exe` is not present
  - Fix Phase 3 when only `pestudio.exe` (GUI) is installed: detect absence of CLI and guide install or provide clearer fallback messaging

- [ ] Phase 4: Externalize regex patterns into a config file and add Base64/URL decoding prepass

- [ ] Orchestrator: Add `--verbose` flag to control discovery logs for DIE/PEStudio

## Phase 5 – MAR+S (Static-only, Groq-optimized)

- [ ] Define MAR+S schema (static-only) and document in `pipelines/phase5_groq_integration/README.md`:
  - title, inferred_utility, final_verdict, hashes, static_analysis, iocs, behaviors, threat_feed_matches, total_risk_score
  - JSON-only, no local file writes unless explicitly requested
- [ ] Add a builder that creates MAR+S from current artifacts entirely in memory:
  - Inputs: MD5 report file (`<md5>_analysis.txt`) + optional Phase 4 JSON + optional PE metadata
  - Parse phase sections: PHASE2_DIE, PHASE3_PE/PHASE3_PE_FALLBACK, PHASE4_IOC
  - Aggregate hashes (MD5/SHA256) and metadata; include compile timestamp if available
  - Aggregate IOCs and behaviors; compute weighted risk score
- [ ] Update `omegaJ_phase5_groq.py` with a `build_mar_plus_static(...)` function returning dict
- [ ] Add `send_marps_to_groq(marps: dict)` that prompts Groq with MAR+S (no local save unless `--save-report`)
- [ ] CLI wiring (stage 5):
  - `--marps` flag to send MAR+S directly to Groq without saving intermediary files
  - `--save-report` optional flag to persist Groq text output; default is in-memory only
- [ ] Ensure Phase 5 can consume only the MD5 report (no Phase 4 JSON) by extracting IOCs from PHASE4_IOC section when present; otherwise run Phase 4 on-the-fly
- [ ] Add unit-style smoke tests for MAR+S building with partial sections present (DIE-only, fallback-only, etc.)
