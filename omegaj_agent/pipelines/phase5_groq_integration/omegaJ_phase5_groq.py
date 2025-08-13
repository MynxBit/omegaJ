"""
Phase 5 + Groq Integration: Static Analysis Reporting
- Input: Phase 4 JSON output (categorized IOCs)
- Enrichment: Threat feed correlation, behavioral inference, risk scoring
- Output: Static-only malware analysis report generated via Groq
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from omegaj_agent.utils.groq_client import complete_chat
from omegaj_agent.utils.analysis_file import (
	analysis_path_for_sample,
	ensure_report_for_sample,
	has_phase_section,
	write_phase_section,
	upsert_status_flag,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Simulated threat feed for demonstration (can be replaced by real feeds)
THREAT_FEED = {
	"url": ["http://malicious.site/payload.exe", "https://evil.com/c2"],
	"ip": ["192.168.100.200", "10.10.10.50"],
	"email": ["attacker@example.com"],
	"hash": ["C5C3F991F78CEEB0B86C17248F325496"],
}

SCORE_WEIGHTS = {
	"email": 5,
	"url": 5,
	"ip": 5,
	"file_path": 1,
	"suspicious_command": 10,
	"suspicious_file": 10,
	"registry_key": 10,
	"threat_feed_match": 15,
}


def load_phase4_json(file_path: str) -> List[Dict[str, Any]]:
	try:
		with open(file_path, "r", encoding="utf-8") as f:
			return json.load(f)
	except Exception as e:
		logging.error(f"Failed to load Phase 4 JSON {file_path}: {e}")
		return []


def correlate_with_threat_feed(iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
	for item in iocs:
		feed_key = item["type"].lower()
		value = str(item.get("value", ""))
		match = value in THREAT_FEED.get(feed_key, [])
		item["threat_feed_match"] = match
	return iocs


def behavioral_inference(iocs: List[Dict[str, Any]]) -> List[str]:
	behaviors = set()
	for item in iocs:
		t = str(item.get("type", "")).lower()
		v = str(item.get("value", "")).lower()
		if t == "registry_key" or ("run" in v or "autorun" in v):
			behaviors.add("persistence")
		if t in ["url", "ip"] or "c2" in v:
			behaviors.add("network_activity")
		if t == "suspicious_command" or "powershell" in v or "cmd" in v:
			behaviors.add("execution_vector")
		if t == "suspicious_file" or v.endswith((".exe", ".dll", ".bat", ".cmd")):
			behaviors.add("file_execution")
	return sorted(list(behaviors))


def assign_risk_score(iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
	total_score = 0
	for item in iocs:
		score = SCORE_WEIGHTS.get(str(item.get("type", "")), 1)
		if item.get("threat_feed_match"):
			score += SCORE_WEIGHTS.get("threat_feed_match", 10)
		item["score"] = score
		total_score += score
	return {"total_score": total_score, "iocs": iocs}


def render_prompt(iocs: List[Dict[str, Any]], behaviors: List[str], file_name: str) -> str:
	return (
		"You are a senior malware analyst. Given the following static indicators, write a MAR+-compatible "
		"report. Only use static evidence; do not assume dynamic execution. Include: executive summary, "
		"family hypotheses (if any), behavioral assessment, IOCs table, and recommended next steps.\n\n"
		f"File: {file_name}\n"
		f"Behaviors: {behaviors}\n"
		f"IOCs: {json.dumps(iocs, indent=2)}\n"
	)


def generate_static_report_with_groq(iocs: List[Dict[str, Any]], behaviors: List[str], file_name: str, output_dir: str = "phase5_reports") -> Optional[Path]:
	Path(output_dir).mkdir(parents=True, exist_ok=True)
	prompt = render_prompt(iocs, behaviors, file_name)
	text = complete_chat(prompt) or "Groq enrichment unavailable (no API key or request failed)."
	output_file = Path(output_dir) / (Path(file_name).stem + "_static_report.txt")
	output_file.write_text(text, encoding="utf-8")
	logging.info(f"Static analysis report generated: {output_file}")
	return output_file


def analyze_phase5_groq(phase4_json_path: str, sample_path: Optional[str] = None, overwrite: bool = False) -> Optional[Path]:
	iocs = load_phase4_json(phase4_json_path)
	if not iocs:
		logging.warning(f"No IOCs loaded from {phase4_json_path}")
		return None

	iocs = correlate_with_threat_feed(iocs)
	behaviors = behavioral_inference(iocs)
	scored = assign_risk_score(iocs)

	# Generate report via Groq
	report_file = generate_static_report_with_groq(scored["iocs"], behaviors, Path(phase4_json_path).name)

	# Optionally append to MD5 report
	if sample_path:
		report_path = analysis_path_for_sample(sample_path)
		ensure_report_for_sample(sample_path)
		phase_tag = "PHASE5_GROQ"
		body = (f"Behaviors: {behaviors}\n\n" + (report_file.read_text(encoding="utf-8") if report_file else "(no report)"))
		if not (has_phase_section(report_path, phase_tag) and not overwrite):
			write_phase_section(report_path, phase_tag, body, overwrite=overwrite)
			upsert_status_flag(report_path, "phase5", "done")
	return report_file


def analyze_multiple_phase5_groq(files_list: List[str]) -> None:
	for file_json in files_list:
		analyze_phase5_groq(file_json)


# === New: Build MAR+S from MD5 report (no JSON requirement) ===

def _read_section(text: str, tag: str) -> str:
	start = f"=== [{tag}] ==="
	end = f"=== [END {tag}] ==="
	s = text.find(start)
	if s == -1:
		return ""
	e = text.find(end, s + len(start))
	if e == -1:
		return text[s + len(start):]
	return text[s + len(start):e]


def _parse_phase0_summary(block: str) -> Tuple[str, int, int]:
	"""Return (verdict, confidence, engines_flagged) from Phase0 rendered text."""
	verdict, conf, flagged = "Unknown", 0, 0
	for line in block.splitlines():
		line = line.strip()
		if line.lower().startswith("overall verdict:"):
			# Overall verdict: Benign | Confidence: 0% | Engines flagged: 0
			try:
				parts = [p.strip() for p in line.split("|")]
				verdict = parts[0].split(":", 1)[1].strip()
				conf = int(parts[1].split(":", 1)[1].strip().rstrip("%"))
				flagged = int(parts[2].split(":", 1)[1].strip())
			except Exception:
				pass
			break
	return verdict, conf, flagged


def _parse_phase3_sections_and_imports(block: str) -> Tuple[List[Dict[str, Any]], List[str]]:
	sections: List[Dict[str, Any]] = []
	imports: List[str] = []
	mode = None
	for raw in block.splitlines():
		line = raw.strip()
		if line.startswith(">>> Sections"):
			mode = "sections"; continue
		if line.startswith(">>> Imports"):
			mode = "imports"; continue
		if not line:
			continue
		if mode == "sections":
			# .text | Entropy: 6.23 | Flags: EXECUTE | ...
			try:
				name = line.split("|", 1)[0].strip()
				ent_s = line.split("Entropy:", 1)[1].split("|", 1)[0].strip()
				entropy = float(ent_s)
				flags_s = line.split("Flags:", 1)[1].split("|", 1)[0].strip()
				flags = [f.strip() for f in flags_s.split(",") if f.strip()]
				sections.append({"name": name, "entropy": entropy, "flags": flags})
			except Exception:
				continue
		elif mode == "imports":
			imports.append(line)
	return sections, imports


def build_marps_from_md5_report(sample_path: str) -> Dict[str, Any]:
	report_path = analysis_path_for_sample(sample_path)
	text = report_path.read_text(encoding="utf-8", errors="ignore") if report_path.exists() else ""
	from pathlib import Path as _Path
	# Hashes
	import hashlib, os
	sha256 = hashlib.sha256(_Path(sample_path).read_bytes()).hexdigest() if _Path(sample_path).exists() else ""
	md5 = report_path.stem.replace("_analysis", "")
	file_size = os.path.getsize(sample_path) if _Path(sample_path).exists() else 0

	# Phase 0
	p0 = _read_section(text, "PHASE0_VT")
	verdict, conf, flagged = _parse_phase0_summary(p0)

	# Phase 3 (PEStudio or fallback)
	p3 = _read_section(text, "PHASE3_PE") or _read_section(text, "PHASE3_PE_FALLBACK")
	sections, imports = _parse_phase3_sections_and_imports(p3)

	# Phase 4 IOCs: prefer existing JSON sidecar if present
	phase4_json = _Path("phase4_output") / (report_path.stem + "_phase4.json")
	iocs: List[Dict[str, Any]] = []
	if phase4_json.exists():
		try:
			iocs = json.loads(phase4_json.read_text(encoding="utf-8"))
		except Exception:
			pass

	behaviors = behavioral_inference(list(iocs))
	scored = assign_risk_score(list(iocs))

	marps: Dict[str, Any] = {
		"title": f"{md5}_{_Path(sample_path).name}_{verdict}_v1.0",
		"inferred_utility": "",
		"final_verdict": verdict or "Unknown",
		"hashes": {
			"md5": md5,
			"sha256": sha256,
			"file_size": file_size,
		},
		"metadata": {
			"file_name": _Path(sample_path).name,
			"file_type": "",
		},
		"static_analysis": {
			"imports": imports,
			"sections": sections,
		},
		"iocs": scored["iocs"],
		"behaviors": behaviors,
		"threat_feed_matches": [x for x in scored["iocs"] if x.get("threat_feed_match")],
		"total_risk_score": scored["total_score"],
		"marps_version": "1.0-static",
	}
	return marps


def generate_report_from_marps(marps: Dict[str, Any], output_dir: str = "phase5_reports") -> Optional[Path]:
	Path(output_dir).mkdir(parents=True, exist_ok=True)
	prompt = (
		"You are a senior malware analyst. Convert the following MAR+S JSON into a readable, static-only "
		"malware analysis report with sections: Executive Summary, Hashes & Metadata, Static Analysis "
		"(imports/sections), IOCs (table), Behaviors, Threat Feed Matches, Risk Score, Recommendations.\n\n"
		f"MARPS JSON:\n{json.dumps(marps, indent=2)}\n"
	)
	text = complete_chat(prompt) or "Groq enrichment unavailable (no API key or request failed)."
	md5 = marps.get("hashes", {}).get("md5", "report")
	outfile = Path(output_dir) / f"{md5}_report.txt"
	outfile.write_text(text, encoding="utf-8")
	return outfile


def analyze_phase5_from_report(sample_path: str) -> Optional[Path]:
	marps = build_marps_from_md5_report(sample_path)
	# Generate Groq report (no JSON sidecar output)
	return generate_report_from_marps(marps)
