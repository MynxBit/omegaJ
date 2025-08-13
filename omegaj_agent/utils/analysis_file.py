import hashlib
from pathlib import Path
from typing import Tuple, Optional

STATUS_START = "--- STATUS START ---"
STATUS_END = "--- STATUS END ---"


def compute_md5(file_path: str) -> str:
	sha = hashlib.md5()
	p = Path(file_path)
	with p.open("rb") as f:
		for chunk in iter(lambda: f.read(8192), b""):
			sha.update(chunk)
	return sha.hexdigest()


def analysis_path_for_sample(sample_path: str) -> Path:
	file_md5 = compute_md5(sample_path)
	return Path(f"{file_md5}_analysis.txt")


def _find_section_range(text: str, start_tag: str, end_tag: str) -> Tuple[int, int]:
	start_idx = text.find(start_tag)
	if start_idx == -1:
		return -1, -1
	end_idx = text.find(end_tag, start_idx + len(start_tag))
	if end_idx == -1:
		return -1, -1
	end_idx += len(end_tag)
	return start_idx, end_idx


def ensure_file_exists(path: Path) -> None:
	if not path.exists():
		path.write_text("", encoding="utf-8")


def has_phase_section(report_path: Path, phase_tag: str) -> bool:
	if not report_path.exists():
		return False
	text = report_path.read_text(encoding="utf-8", errors="ignore")
	start = f"=== [{phase_tag}] ==="
	return start in text


def write_phase_section(report_path: Path, phase_tag: str, body: str, overwrite: bool = False) -> None:
	start_marker = f"=== [{phase_tag}] ==="
	end_marker = f"=== [END {phase_tag}] ==="
	section = f"\n{start_marker}\n{body}\n{end_marker}\n"
	if not report_path.exists():
		report_path.write_text(section, encoding="utf-8")
		return
	text = report_path.read_text(encoding="utf-8", errors="ignore")
	if start_marker in text and end_marker in text:
		if not overwrite:
			# keep existing
			return
		# replace existing
		s, e = _find_section_range(text, start_marker, end_marker)
		if s != -1 and e != -1:
			new_text = text[:s] + section + text[e:]
			report_path.write_text(new_text, encoding="utf-8")
			return
	# append
	report_path.write_text(text + section, encoding="utf-8")


def upsert_status_flag(report_path: Path, phase_key: str, value: str = "done") -> None:
	ensure_file_exists(report_path)
	text = report_path.read_text(encoding="utf-8", errors="ignore")
	status_block = f"{STATUS_START}\n{phase_key}={value}\n{STATUS_END}\n"
	if STATUS_START not in text or STATUS_END not in text:
		new_text = status_block + text
		report_path.write_text(new_text, encoding="utf-8")
		return
	# update existing: simple line-based replace or append if missing
	start, end = _find_section_range(text, STATUS_START, STATUS_END)
	if start == -1:
		report_path.write_text(status_block + text, encoding="utf-8")
		return
	block = text[start:end]
	lines = block.splitlines()
	found = False
	for i, line in enumerate(lines):
		if line.startswith(f"{phase_key}="):
			lines[i] = f"{phase_key}={value}"
			found = True
			break
	if not found:
		lines.insert(-1, f"{phase_key}={value}")
	new_block = "\n".join(lines)
	new_text = text[:start] + new_block + text[end:]
	report_path.write_text(new_text, encoding="utf-8")


def ensure_report_for_sample(sample_path: str, header_text: Optional[str] = None) -> Path:
	path = analysis_path_for_sample(sample_path)
	if not path.exists():
		Path(path).write_text(header_text or "", encoding="utf-8")
	return path
