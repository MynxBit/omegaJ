"""
Helper functions for Phase 3 PE Analysis.
"""

import re
from typing import List
from .config import ENTROPY_HIGH


def compute_sha256(file_path: str) -> str:
	"""Compute SHA256 hash of the file."""
	import hashlib
	hash_sha256 = hashlib.sha256()
	with open(file_path, "rb") as f:
		for chunk in iter(lambda: f.read(4096), b""):
			hash_sha256.update(chunk)
	return hash_sha256.hexdigest()


def calculate_entropy(data: bytes) -> float:
	"""Compute Shannon entropy of a byte array."""
	import math
	if not data:
		return 0.0
	freq = [0] * 256
	for b in data:
		freq[b] += 1
	entropy = 0.0
	for f in freq:
		if f:
			p = f / len(data)
			entropy -= p * math.log2(p)
	return entropy


def filter_suspicious_strings(strings: List[str]) -> List[str]:
	"""Return only strings with URLs, IPs, paths, or suspicious keywords."""
	suspicious_patterns = [
		r"powershell", r"cmd\.exe", r"\/c", r"http[s]?://", r"\\[A-Za-z0-9\\]+",
		r"\.exe", r"\.dll", r"hkey_(local_machine|current_user)", r"reg(add|delete)",
	]
	filtered: List[str] = []
	for s in strings:
		low = s.lower()
		# Exclude VirusTotal API links from suspicious strings
		if "virustotal.com/api/v3/files/" in low:
			continue
		if any(re.search(pat, s, re.IGNORECASE) for pat in suspicious_patterns):
			filtered.append(s)
	return filtered


def mark_suspicious_section(entropy: float, flags: List[str]) -> str:
	"""Return a note if section is suspicious."""
	notes: List[str] = []
	if entropy > ENTROPY_HIGH:
		notes.append(f"[!] High entropy ({entropy:.2f})")
	if "EXECUTE" in flags and "WRITE" in flags:
		notes.append("[!] Executable + Writable")
	return "; ".join(notes) if notes else ""
