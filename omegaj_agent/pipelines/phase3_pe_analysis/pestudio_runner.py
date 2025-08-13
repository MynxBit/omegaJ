"""
Pipeline 3: PEStudio-based PE Analysis including VirusTotal.
"""

import os
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from shutil import which
from typing import Optional, List
from .config import PESTUDIO_PATHS, SECTION_SEPARATOR, FILE_ENCODING, TEMP_DIR
from omegaj_agent.utils.analysis_file import (
	analysis_path_for_sample,
	ensure_report_for_sample,
	has_phase_section,
	write_phase_section,
	upsert_status_flag,
)
from .utils import mark_suspicious_section, filter_suspicious_strings


def _search_program_files_for(names: List[str]) -> Optional[str]:
	roots = [
		"C:\\Program Files",
		"C:\\Program Files (x86)",
	]
	for root in roots:
		if not os.path.exists(root):
			continue
		for dirpath, dirnames, filenames in os.walk(root):
			lower_files = {fn.lower(): fn for fn in filenames}
			for nm in names:
				if nm.lower() in lower_files:
					return os.path.join(dirpath, lower_files[nm.lower()])
	return None


def _search_c_drive_for(names: List[str], max_dirs: int = 6000, max_seconds: float = 12.0) -> Optional[str]:
	import time
	start_ts = time.time()
	visited = 0
	root = "C:\\"
	skip_dirs = {
		"C:\\Windows\\WinSxS",
		"C:\\Windows\\servicing",
		"C:\\Windows\\SoftwareDistribution",
		"C:\\Windows\\System32\\DriverStore",
		"C:\\$Recycle.Bin",
		"C:\\System Volume Information",
	}
	try:
		for dirpath, dirnames, filenames in os.walk(root):
			visited += 1
			if visited > max_dirs or (time.time() - start_ts) > max_seconds:
				break
			if any(dirpath.startswith(sd) for sd in skip_dirs):
				dirnames[:] = []
				continue
			lower_files = {fn.lower(): fn for fn in filenames}
			for nm in names:
				if nm.lower() in lower_files:
					return os.path.join(dirpath, lower_files[nm.lower()])
	except Exception:
		return None
	return None


def find_pestudio() -> Optional[str]:
	"""Locate pestudio.exe automatically by checking known paths, PATH, then scanning Program Files and C:."""
	print("[omegaJ] Auto-detecting PEStudio CLI...")
	for path in PESTUDIO_PATHS:
		if os.path.exists(path):
			print(f"[omegaJ] PEStudio found at common path: {path}")
			return path
	path = which("pestudio.exe")
	if path:
		print(f"[omegaJ] PEStudio found via PATH: {path}")
		return path
	print("[omegaJ] Scanning Program Files for PEStudio (portable installs)...")
	pf = _search_program_files_for(["pestudio.exe"])
	if pf:
		print(f"[omegaJ] PEStudio found under Program Files: {pf}")
		return pf
	print("[omegaJ] Scanning C:\\ (bounded) for PEStudio...")
	return _search_c_drive_for(["pestudio.exe"])


def find_pestudio_cli() -> Optional[str]:
	"""Locate professional CLI binary 'pestudiox.exe'."""
	print("[omegaJ] Checking for PEStudio CLI (pestudiox.exe)...")
	# Common guesses
	common = [
		"C:\\Program Files\\PEStudio\\pestudiox.exe",
		"C:\\Program Files (x86)\\PEStudio\\pestudiox.exe",
	]
	for p in common:
		if os.path.exists(p):
			print(f"[omegaJ] PEStudio CLI found at common path: {p}")
			return p
	path = which("pestudiox.exe")
	if path:
		print(f"[omegaJ] PEStudio CLI found via PATH: {path}")
		return path
	pf = _search_program_files_for(["pestudiox.exe"])
	if pf:
		print(f"[omegaJ] PEStudio CLI found under Program Files: {pf}")
		return pf
	return _search_c_drive_for(["pestudiox.exe"])


def run_pestudio(sample_path: str):
	"""Run PEStudio CLI and return path to XML output or None.

	If the professional CLI 'pestudiox.exe' is available, attempt a headless XML
	report export. Otherwise, return None so the Python fallback can run.
	"""
	cli = find_pestudio_cli()
	if not cli:
		print("[omegaJ] PEStudio CLI not found; using Python fallback.")
		return None

	xml_output = (TEMP_DIR / f"{Path(sample_path).stem}_pestudio.xml").resolve()

	# Try a couple of likely syntaxes used by CLI builds
	trial_commands = [
		[cli, "-report", "xml", "-out", str(xml_output), sample_path],
		[cli, "-xml", str(xml_output), sample_path],
	]

	for cmd in trial_commands:
		try:
			print("[omegaJ] Running PEStudio CLI:", " ".join(cmd))
			proc = subprocess.run(
				cmd,
				check=False,
				capture_output=True,
				text=True,
				timeout=60,
			)
			if xml_output.exists() and xml_output.stat().st_size > 0:
				return xml_output
		except Exception:
			continue

	return None


def parse_pestudio_xml(xml_file: Path) -> str:
	"""Parse PEStudio XML and return formatted string for append."""
	try:
		tree = ET.parse(xml_file)
		root = tree.getroot()
	except ET.ParseError:
		return "[!] Failed to parse PEStudio XML."

	output = [SECTION_SEPARATOR, "=== PEStudio Deep Static Analysis ==="]

	metadata = root.find("Properties")
	if metadata is not None:
		output.append(">>> Metadata:")
		for prop in metadata.findall("Property"):
			name = prop.get("Name")
			value = prop.get("Value")
			output.append(f"{name}: {value}")

	sections = root.find("Sections")
	if sections is not None:
		output.append("\n>>> Sections:")
		for sec in sections.findall("Section"):
			sec_name = sec.get("Name")
			try:
				ent = float(sec.get("Entropy", "0"))
			except ValueError:
				ent = 0.0
			flags = sec.get("Characteristics", "").split(",")
			note = mark_suspicious_section(ent, flags)
			output.append(f"{sec_name} | Entropy: {ent:.2f} | Flags: {sec.get('Characteristics')} | {note}")

	imports = root.find("Imports")
	if imports is not None:
		output.append("\n>>> Imports (DLL -> Functions):")
		for imp in imports.findall("Import"):
			dll_name = imp.get("DLL")
			funcs = [f.get("Name") for f in imp.findall("Function")]
			output.append(f"{dll_name} -> {', '.join(funcs)}")

	overlay = root.find("Overlay")
	if overlay is not None:
		output.append("\n>>> Overlay:")
		size = overlay.get("Size", "0")
		entropy = overlay.get("Entropy", "0")
		output.append(f"Size: {size} | Entropy: {entropy}")

	resources = root.find("Resources")
	if resources is not None:
		output.append("\n>>> Resources:")
		for res in resources.findall("Resource"):
			output.append(f"{res.get('Type')} | Size: {res.get('Size')} | Entropy: {res.get('Entropy')}")

	strings_node = root.find("Strings")
	if strings_node is not None:
		output.append("\n>>> Suspicious Strings:")
		all_strings = [s.text or "" for s in strings_node.findall("String")]
		suspicious = filter_suspicious_strings(all_strings)
		for s in suspicious:
			output.append(s)

	signature = root.find("Signature")
	if signature is not None:
		output.append("\n>>> Digital Signature:")
		for s in signature.findall("Property"):
			output.append(f"{s.get('Name')}: {s.get('Value')}")

	vt = root.find("VirusTotal")
	if vt is not None:
		output.append("\n>>> VirusTotal Check:")
		output.append(f"Status: {vt.get('Status', 'Unknown')}")
		link = vt.get("Link")
		if link:
			output.append(f"Link: {link}")

	output.append(SECTION_SEPARATOR)
	return "\n".join(output)


def run_phase3_pestudio(sample_path: str, output_file: str = "", overwrite: bool = False) -> bool:
	"""Run PEStudio phase and append results. Return True if PEStudio CLI was used."""
	report_path = analysis_path_for_sample(sample_path) if not output_file else Path(output_file)
	ensure_report_for_sample(sample_path)
	phase_tag = "PHASE3_PE"
	if has_phase_section(report_path, phase_tag) and not overwrite:
		print("[omegaJ] Phase 3 already present in report. Use overwrite to replace.")
		return True
	xml_file = run_pestudio(sample_path)
	if xml_file:
		parsed_text = parse_pestudio_xml(xml_file)
		write_phase_section(report_path, phase_tag, parsed_text, overwrite=overwrite)
		upsert_status_flag(report_path, "phase3", "done")
		return True
	return False
