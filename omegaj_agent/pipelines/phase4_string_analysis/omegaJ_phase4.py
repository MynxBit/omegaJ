"""
Phase 4: Controlled String Analysis & IOC Extraction
- Extracts emails, URLs, IPs, file paths
- Flags suspicious commands (powershell, cmd, exe, dll, bat)
- Registry key detection (offline parsing optional)
- Outputs categorized JSON
- Config-driven regex patterns for easy extension
"""

import re
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from omegaj_agent.utils.analysis_file import (
    analysis_path_for_sample,
    ensure_report_for_sample,
    has_phase_section,
    write_phase_section,
    upsert_status_flag,
)

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Default regex patterns (can be extended via external config)
REGEX_PATTERNS: Dict[str, str] = {
	"email": r"[\w\.-]+@[\w\.-]+\.\w+",
	"url": r"https?://[^\s'\"<>]+",
	"ip": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
	"file_path": r"[A-Za-z]:\\[^\s'\"<>]+",
	"suspicious_command": r"(?i)\b(powershell|cmd|wscript|mshta|explorer|regedit)\b",
	"suspicious_file": r"(?i)\b\w+\.(exe|dll|bat|cmd|vbs|js)\b",
	"registry_key": r"(?i)HKEY(?:_LOCAL_MACHINE|_CURRENT_USER)\\[^\s]+",
}


def load_file_content(file_path: str) -> str:
    """Read content of text file; if binary, extract ASCII and UTF-16LE strings."""
    try:
        # Try text first
        with open(file_path, "r", encoding="utf-8", errors="strict") as f:
            return f.read()
    except Exception:
        try:
            data = Path(file_path).read_bytes()
        except Exception as e:
            logging.error(f"Failed to read file {file_path}: {e}")
            return ""
        # ASCII strings
        ascii_parts = []
        buf = []
        for b in data:
            if 32 <= b <= 126:
                buf.append(chr(b))
                continue
            if len(buf) >= 5:
                ascii_parts.append("".join(buf))
            buf = []
        if len(buf) >= 5:
            ascii_parts.append("".join(buf))
        # UTF-16LE strings
        utf16_parts = []
        try:
            text16 = data.decode("utf-16le", errors="ignore")
            for token in text16.split("\x00"):
                if len(token) >= 5:
                    utf16_parts.append(token)
        except Exception:
            pass
        combined = "\n".join(ascii_parts + utf16_parts)
        return combined


def extract_iocs(content: str, patterns: Optional[Dict[str, str]] = None) -> List[Dict[str, str]]:
	"""Extract IOCs using regex patterns."""
	results: List[Dict[str, str]] = []
	patterns = patterns or REGEX_PATTERNS

	for category, pattern in patterns.items():
		try:
			matches = re.findall(pattern, content)
			for match in set(matches):  # remove duplicates
				value = match if isinstance(match, str) else match[0]
				low = value.lower()
				# Exclude tool/report URLs such as VirusTotal from IOC extraction
				if category == "url" and ("virustotal.com/api" in low or "virustotal.com/gui" in low):
					continue
				results.append({"type": category, "value": value})
		except re.error as e:
			logging.error(f"Regex error for category {category}: {e}")

	return results


def categorize_and_score(iocs: List[Dict[str, str]]) -> List[Dict[str, Any]]:
	"""Assign risk score based on category."""
	scored: List[Dict[str, Any]] = []
	for item in iocs:
		score = 1  # default low
		if item["type"] in ["suspicious_command", "suspicious_file", "registry_key"]:
			score = 10
		elif item["type"] in ["url", "ip", "email"]:
			score = 5
		scored.append({**item, "score": score})
	return scored


def save_json_output(iocs: List[Dict[str, Any]], output_path: str) -> None:
	"""Save JSON output of extracted IOCs."""
	try:
		with open(output_path, "w", encoding="utf-8") as f:
			json.dump(iocs, f, indent=4)
		logging.info(f"JSON output saved to {output_path}")
	except Exception as e:
		logging.error(f"Failed to save JSON output: {e}")


def analyze_file(file_path: str, output_dir: str = "phase4_output", patterns: Optional[Dict[str, str]] = None, append_to_report: bool = True, overwrite: bool = False) -> str:
    """Analyze a text file and optionally append a Phase 4 section into the MD5-named report."""
    logging.info(f"Analyzing {file_path}")
    content = load_file_content(file_path)
    if not content:
        logging.warning(f"No content extracted from {file_path}")
        return ""

    iocs = extract_iocs(content, patterns)
    scored_iocs = categorize_and_score(iocs)

    # Save JSON sidecar for tooling, but do not dump JSON into report
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    output_file_path = str(Path(output_dir) / (Path(file_path).stem + "_phase4.json"))
    save_json_output(scored_iocs, output_file_path)

    if append_to_report:
        # Treat file_path as the sample report when it ends with _analysis.txt; else derive by sample
        if file_path.endswith("_analysis.txt"):
            report_path = Path(file_path)
        else:
            report_path = analysis_path_for_sample(file_path)
            ensure_report_for_sample(file_path)
        phase_tag = "PHASE4_IOC"
        if not (has_phase_section(report_path, phase_tag) and not overwrite):
            # Render readable text: group by type and list values
            grouped: Dict[str, List[Dict[str, Any]]] = {}
            for item in scored_iocs:
                grouped.setdefault(item["type"], []).append(item)
            lines: List[str] = ["=== IOC Extraction (Phase 4) ==="]
            for t in sorted(grouped.keys()):
                lines.append(f">>> {t} ({len(grouped[t])})")
                for obj in sorted({x["value"] for x in grouped[t]}):
                    lines.append(f"- {obj}")
            write_phase_section(report_path, phase_tag, "\n".join(lines), overwrite=overwrite)
            upsert_status_flag(report_path, "phase4", "done")
        else:
            logging.info("Phase 4 already present in report; skipping (use overwrite to replace).")

    return output_file_path


def analyze_multiple_files(file_list: List[str], output_dir: str = "phase4_output", patterns: Optional[Dict[str, str]] = None) -> List[str]:
	"""Batch analyze multiple files."""
	outputs: List[str] = []
	for file_path in file_list:
		result = analyze_file(file_path, output_dir, patterns)
		if result:
			outputs.append(result)
	return outputs


if __name__ == "__main__":
	# Example usage
	files = ["sample1.txt", "sample2.txt"]
	analyze_multiple_files(files)
