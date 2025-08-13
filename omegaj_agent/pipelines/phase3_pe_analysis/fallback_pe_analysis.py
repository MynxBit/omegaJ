"""
Pipeline 3 Fallback: Python PE analysis + VirusTotal API check.
"""

from pathlib import Path
from typing import List
import requests
import pefile
from .config import FILE_ENCODING, VT_API_KEY, SECTION_SEPARATOR
from omegaj_agent.utils.analysis_file import (
    analysis_path_for_sample,
    ensure_report_for_sample,
    has_phase_section,
    write_phase_section,
    upsert_status_flag,
)
from .utils import compute_sha256, calculate_entropy, mark_suspicious_section, filter_suspicious_strings

VT_URL = "https://www.virustotal.com/api/v3/files/{}"


def vt_check(hash_sha256: str) -> str:
	"""Query VT API if key exists and return formatted status."""
	if not VT_API_KEY:
		return "VirusTotal API key not provided; skipping VT check."
	headers = {"x-apikey": VT_API_KEY}
	try:
		response = requests.get(VT_URL.format(hash_sha256), headers=headers, timeout=20)
		if response.status_code == 200:
			data = response.json() or {}
			link = data.get("data", {}).get("links", {}).get("self", "")
			return f"Found on VirusTotal: {link}"
		elif response.status_code == 404:
			return "Not found on VirusTotal."
		else:
			return f"VT query failed: HTTP {response.status_code}"
	except requests.RequestException as e:
		return f"VT query exception: {str(e)}"


def python_pe_analysis(sample_path: str) -> str:
	"""Perform Python-based PE analysis and return formatted string."""
	output: List[str] = [SECTION_SEPARATOR, "=== Python Fallback PE Analysis ==="]
	try:
		pe = pefile.PE(sample_path)
	except pefile.PEFormatError:
		return "[!] Not a valid PE file."

	# Metadata
	output.append(">>> Metadata:")
	try:
		output.append(f"Timestamp: {pe.FILE_HEADER.TimeDateStamp}")
		output.append(f"Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
	except Exception:
		output.append("[!] Failed to extract basic metadata.")

	# Sections
	output.append("\n>>> Sections:")
	for sec in pe.sections:
		name = sec.Name.decode(errors="ignore").rstrip("\x00")
		entropy = calculate_entropy(sec.get_data())
		flags: List[str] = []
		if getattr(sec, "IMAGE_SCN_MEM_EXECUTE", 0):
			flags.append("EXECUTE")
		if getattr(sec, "IMAGE_SCN_MEM_WRITE", 0):
			flags.append("WRITE")
		note = mark_suspicious_section(entropy, flags)
		output.append(f"{name} | Entropy: {entropy:.2f} | Flags: {','.join(flags)} | {note}")

	# Imports
	output.append("\n>>> Imports:")
	try:
		if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
			for entry in pe.DIRECTORY_ENTRY_IMPORT:
				funcs = [imp.name.decode(errors="ignore") if imp.name else "" for imp in entry.imports]
				output.append(f"{entry.dll.decode(errors='ignore')} -> {', '.join(funcs)}")
	except Exception:
		output.append("[!] Failed to parse imports.")

	# Overlay
	output.append("\n>>> Overlay:")
	try:
		overlay_offset = pe.get_overlay_data_start_offset()
		overlay_size = len(pe.__data__[overlay_offset:]) if overlay_offset else 0
		overlay_data = pe.__data__[overlay_offset:] if overlay_offset else b""
		overlay_entropy = calculate_entropy(overlay_data)
		output.append(f"Size: {overlay_size} | Entropy: {overlay_entropy:.2f}")
	except Exception:
		output.append("[!] Failed to extract overlay info.")

	# Strings
	output.append("\n>>> Suspicious Strings:")
	try:
		raw_data = pe.__data__
		strings = [s.decode(errors="ignore") for s in raw_data.split(b"\x00") if len(s) > 4]
		suspicious = filter_suspicious_strings(strings)
		for s in suspicious:
			output.append(s)
	except Exception:
		output.append("[!] Failed to extract strings.")

	# VirusTotal check
	hash_sha256 = compute_sha256(sample_path)
	output.append("\n>>> VirusTotal Check:")
	output.append(vt_check(hash_sha256))

	output.append(SECTION_SEPARATOR)
	return "\n".join(output)


def run_phase3_fallback(sample_path: str, output_file: str = "", overwrite: bool = False) -> None:
    """Run fallback PE analysis and append to file, with section control."""
    report_path = analysis_path_for_sample(sample_path) if not output_file else Path(output_file)
    ensure_report_for_sample(sample_path)
    phase_tag = "PHASE3_PE_FALLBACK"
    if has_phase_section(report_path, phase_tag) and not overwrite:
        print("[omegaJ] Phase 3 fallback already present in report. Use overwrite to replace.")
        return
    parsed_text = python_pe_analysis(sample_path)
    write_phase_section(report_path, phase_tag, parsed_text, overwrite=overwrite)
    upsert_status_flag(report_path, "phase3_fallback", "done")
