import os
import re
import time
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional

import requests
from omegaj_agent.utils.env_loader import load_env_all

from omegaj_agent.utils.analysis_file import (
	analysis_path_for_sample,
	ensure_report_for_sample,
	has_phase_section,
	write_phase_section,
	upsert_status_flag,
)

TRUSTED_WEIGHTS: Dict[str, float] = {
	"bitdefender": 1.2,
	"kaspersky": 1.1,
	"eset": 1.1,
	"microsoft": 1.0,
	"symantec": 1.0,
	"avast": 0.9,
	"mcafee": 0.9,
}

# Common engine name normalization from VT keys
ENGINE_SYNONYMS: Dict[str, str] = {
	"bitdefender": "bitdefender",
	"bitdefender falx": "bitdefender",
	"kaspersky": "kaspersky",
	"eset-nod32": "eset",
	"eset": "eset",
	"microsoft": "microsoft",
	"microsoft defender": "microsoft",
	"symantec": "symantec",
	"broadcom": "symantec",
	"avast": "avast",
	"mcafee": "mcafee",
}

URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
EMAIL_RE = re.compile(r"[\w\.-]+@[\w\.-]+\.\w+")

VT_URL = "https://www.virustotal.com/api/v3/files/{}"

# Local output formatting
SECTION_SEPARATOR = "=" * 50


def _sha256_of_file(file_path: str) -> str:
	sha = hashlib.sha256()
	with open(file_path, "rb") as f:
		for chunk in iter(lambda: f.read(8192), b""):
			sha.update(chunk)
	return sha.hexdigest()


def _get_vt(file_hash: str, api_key: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
	headers = {"x-apikey": api_key}
	try:
		resp = requests.get(VT_URL.format(file_hash), headers=headers, timeout=20)
		if resp.status_code == 200:
			return resp.json(), None
		if resp.status_code == 404:
			return None, "not_found"
		if resp.status_code == 429:
			return None, "rate_limited"
		return None, f"http_{resp.status_code}"
	except requests.RequestException as e:
		return None, f"exception:{e}"


def _normalize_engine(name: str) -> Optional[str]:
	k = name.strip().lower()
	return ENGINE_SYNONYMS.get(k)


def _extract_family(label: Optional[str]) -> Optional[str]:
	if not label:
		return None
	# Keep simple alnum plus separators
	label = re.sub(r"[^A-Za-z0-9._-]", "", label)
	return label or None


def _extract_iocs_from_json(data: Dict[str, Any]) -> Dict[str, List[str]]:
	blob = json.dumps(data, ensure_ascii=False)
	urls = list(sorted(set(URL_RE.findall(blob))))
	ips = list(sorted(set(IP_RE.findall(blob))))
	emails = list(sorted(set(EMAIL_RE.findall(blob))))
	return {"urls": urls, "ips": ips, "emails": emails}


def _confidence_and_consensus(eng_results: List[Tuple[str, str, Optional[str], float]]) -> Tuple[int, Dict[str, Any]]:
	# eng_results: (engine_key, verdict, family, weight)
	total_weight = sum(w for _, _, _, w in eng_results)
	flag_weight = sum(w for _, v, __, w in eng_results if v in ("malicious", "suspicious"))
	confidence = int(round((flag_weight / total_weight) * 100)) if total_weight else 0
	families: List[str] = [f for _, v, f, _ in eng_results if v in ("malicious", "suspicious") and f]
	most, ratio = None, 0.0
	if families:
		from collections import Counter
		cnt = Counter(families)
		most, c = cnt.most_common(1)[0]
		ratio = c / max(1, len(families))
	return confidence, {"most_common_family": most, "agreement_ratio": round(ratio, 2)}


def build_phase0_json(sample_path: str) -> Dict[str, Any]:
	# Load environment from root and package .env to be robust regardless of caller
	try:
		load_env_all(debug=True)
	except Exception:
		pass
	api_key = os.getenv("VT_API_KEY", "")
	md5_path = analysis_path_for_sample(sample_path)
	file_md5 = md5_path.name.split("_analysis.txt")[0]
	sha256 = _sha256_of_file(sample_path)
	if not api_key:
		return {
			"file_hash": {"md5": file_md5, "sha256": sha256},
			"error": "VT_API_KEY missing",
		}
	data, err = _get_vt(sha256, api_key)
	if err == "not_found":
		data, err = _get_vt(file_md5, api_key)
	result: Dict[str, Any] = {"file_hash": {"md5": file_md5, "sha256": sha256}}
	if not data:
		result["error"] = err or "unknown"
		result["note"] = "Ensure VT_API_KEY is present in .env and valid; this message includes the last error code."
		return result
	attrs = data.get("data", {}).get("attributes", {})
	last_ts = attrs.get("last_analysis_date")
	scan_date = None
	if isinstance(last_ts, int):
		scan_date = datetime.fromtimestamp(last_ts, tz=timezone.utc).isoformat()
	results = attrs.get("last_analysis_results", {}) or {}
	eng_list: List[Tuple[str, str, Optional[str], float]] = []
	trusted_dump: Dict[str, Any] = {}
	for eng_name, info in results.items():
		canon = _normalize_engine(eng_name)
		if not canon or canon not in TRUSTED_WEIGHTS:
			continue
		verdict = (info.get("category") or "unknown").lower()
		family = _extract_family(info.get("result"))
		weight = TRUSTED_WEIGHTS[canon]
		eng_list.append((canon, verdict, family, weight))
		trusted_dump[eng_name] = {"verdict": verdict.title(), "family": family, "weight": weight}
	confidence, fam = _confidence_and_consensus(eng_list)
	total_flagged = sum(1 for _, v, __, _ in eng_list if v in ("malicious", "suspicious"))
	verdict = "Malware" if confidence >= 60 and total_flagged >= 2 else ("Suspicious" if confidence >= 25 else "Benign")
	iocs = _extract_iocs_from_json(attrs)
	result.update({
		"scan_date": scan_date,
		"overall_verdict": verdict,
		"confidence_score": confidence,
		"total_engines_flagged": total_flagged,
		"family_consensus": fam,
		"trusted_engines": trusted_dump,
		"reported_iocs": iocs,
	})
	return result


def _render_phase0_text(payload: Dict[str, Any]) -> str:
	"""Render VT payload into a concise, human-readable text block."""
	lines: List[str] = [SECTION_SEPARATOR, "=== VirusTotal Precheck ==="]
	file_hash = payload.get("file_hash", {})
	lines.append(f"MD5: {file_hash.get('md5','')} | SHA256: {file_hash.get('sha256','')}")
	if "error" in payload:
		lines.append(f"Status: ERROR - {payload.get('error')}")
		if payload.get("note"):
			lines.append(f"Note: {payload['note']}")
		lines.append(SECTION_SEPARATOR)
		return "\n".join(lines)
	lines.append(f"Scan date: {payload.get('scan_date')}")
	lines.append(f"Overall verdict: {payload.get('overall_verdict')} | Confidence: {payload.get('confidence_score')}% | Engines flagged: {payload.get('total_engines_flagged')}")
	# Trusted engines summary
	trusted = payload.get("trusted_engines", {}) or {}
	if trusted:
		lines.append("\n>>> Trusted engines (canonical):")
		for eng_name, info in sorted(trusted.items()):
			ver = info.get("verdict", "")
			fam = info.get("family") or "-"
			lines.append(f"- {eng_name}: {ver} | Family: {fam}")
	# IOC counts summary only (avoid dumping huge lists)
	iocs = payload.get("reported_iocs", {}) or {}
	if any(iocs.get(k) for k in ("urls","ips","emails")):
		lines.append("\n>>> IOC summary:")
		lines.append(f"URLs: {len(iocs.get('urls', []))} | IPs: {len(iocs.get('ips', []))} | Emails: {len(iocs.get('emails', []))}")
	lines.append(SECTION_SEPARATOR)
	return "\n".join(lines)


def append_phase0_section(sample_path: str, overwrite: bool = False) -> Optional[Path]:
	report_path = analysis_path_for_sample(sample_path)
	ensure_report_for_sample(sample_path)
	phase_tag = "PHASE0_VT"
	if has_phase_section(report_path, phase_tag) and not overwrite:
		print("[omegaJ] Phase 0 already present in report. Use overwrite to replace.")
		return report_path
	payload = build_phase0_json(sample_path)
	body_text = _render_phase0_text(payload)
	write_phase_section(report_path, phase_tag, body_text, overwrite=overwrite)
	upsert_status_flag(report_path, "phase0", "done")
	return report_path
