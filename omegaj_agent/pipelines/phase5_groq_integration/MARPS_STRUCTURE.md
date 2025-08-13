# MAR+S (Malware Analysis Report Plus – Static-only)

Purpose: single, Groq-ready, static-only report object built from OmegaJ phases without dynamic execution.

Version: v1.0 (static-only)

## Top-level fields
- `title` (string): "YYYYMMDD_FILENAME_VERDICT_FAMILY_vX.Y"
- `inferred_utility` (string): human-friendly one-paragraph purpose of the file
- `final_verdict` (string enum): Malware | Suspicious | Benign
- `hashes` (object):
  - `md5` (string)
  - `sha256` (string)
  - `imphash` (string, optional)
  - `file_size` (integer, bytes)
  - `compile_timestamp` (string, optional, ISO8601)
- `metadata` (object):
  - `file_name` (string)
  - `file_type` (string)
  - `platform` (string, optional)
  - `artifact_version` (string, optional)
- `static_analysis` (object):
  - `imports` (array of strings or DLL->func formatted strings)
  - `sections` (array of objects: name, entropy, flags)
  - `headers` (object, optional)
  - `overlay` (object, optional)
  - `signing` (object, optional)
- `iocs` (array of objects): `{ type, value, score, threat_feed_match? }`
- `behaviors` (array of strings): e.g., persistence, network_activity, execution_vector, file_execution
- `threat_feed_matches` (array of objects): `{ type, value, source }`
- `total_risk_score` (integer)
- `marps_version` (string): e.g., "1.0-static"

## Minimal example
```json
{
  "title": "20250813_notepad.exe_Suspicious_None_v1.0",
  "inferred_utility": "Windows GUI editor that may drop auxiliary components.",
  "final_verdict": "Suspicious",
  "hashes": {
    "md5": "7d02feb3b0deb79d6d61b2f89fe7f1d6",
    "sha256": "...",
    "file_size": 257024
  },
  "metadata": {
    "file_name": "notepad.exe",
    "file_type": "PE32+"
  },
  "static_analysis": {
    "imports": ["USER32.dll->MessageBoxW, CreateWindowExW"],
    "sections": [{ "name": ".text", "entropy": 6.23, "flags": ["EXECUTE"] }]
  },
  "iocs": [
    { "type": "file_path", "value": "C:\\Windows\\System32\\notepad.exe", "score": 1 }
  ],
  "behaviors": ["file_execution"],
  "threat_feed_matches": [],
  "total_risk_score": 6,
  "marps_version": "1.0-static"
}
```

Notes:
- Strictly static; do not include sandbox or runtime claims.
- Optimized for direct prompting: pass this JSON as-is to Groq with an instruction to render a MAR-style narrative.
