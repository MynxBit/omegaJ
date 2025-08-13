import json
import os
import shutil
import subprocess
from typing import Any, Dict, Optional, List


def _search_program_files_for(names: List[str]) -> Optional[str]:
	# Search within Program Files locations only
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
	# Walk C:\ with caps to avoid long hangs
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


def locate_die_cli() -> Optional[str]:
	candidates = [
		"diec",
		"diec.exe",
		"die",
		"die.exe",
	]
	print("[omegaJ] Auto-detecting Detect It Easy (DIE) CLI...")
	for name in candidates:
		path = shutil.which(name)
		if path:
			print(f"[omegaJ] DIE found via PATH: {path}")
			return path

	common_windows_paths = [
		r"C:\\Program Files\\Detect It Easy\\diec.exe",
		r"C:\\Program Files (x86)\\Detect It Easy\\diec.exe",
	]
	for p in common_windows_paths:
		if os.path.exists(p):
			print(f"[omegaJ] DIE found at common path: {p}")
			return p

	# Program Files recursive search
	print("[omegaJ] Scanning Program Files for DIE (portable installs)...")
	pf = _search_program_files_for(["diec.exe", "die.exe"])
	if pf:
		print(f"[omegaJ] DIE found under Program Files: {pf}")
		return pf

	# C: drive bounded search fallback
	print("[omegaJ] Scanning C:\\ (bounded) for DIE...")
	return _search_c_drive_for(["diec.exe", "die.exe"])


def _run_die_json(die_path: str, target_path: str) -> Dict[str, Any]:
	last_exception: Optional[str] = None
	commands = [
		[die_path, "-j", target_path],
		[die_path, target_path, "-arch", "all", "-showarch", "-showall"],
	]
	for cmd in commands:
		try:
			proc = subprocess.run(
				cmd,
				check=False,
				capture_output=True,
				text=True,
				timeout=60,
			)
			stdout = (proc.stdout or "").strip()
			stderr = (proc.stderr or "").strip()
			if stdout:
				try:
					parsed = json.loads(stdout)
					return {
						"ok": True,
						"tool": die_path,
						"returncode": proc.returncode,
						"result": parsed,
						"stderr": stderr,
					}
				except json.JSONDecodeError:
					return {
						"ok": True,
						"tool": die_path,
						"returncode": proc.returncode,
						"result_raw": stdout,
						"stderr": stderr,
					}
			else:
				return {
					"ok": proc.returncode == 0,
					"tool": die_path,
					"returncode": proc.returncode,
					"result_raw": stdout,
					"stderr": stderr,
				}
		except Exception as exc:
			last_exception = str(exc)
			continue
	return {"ok": False, "tool": die_path, "error": "Failed to run DIE", "exception": last_exception}


def find_and_run_die(target_path: str) -> Dict[str, Any]:
	file_exists = os.path.exists(target_path)
	die_cli = locate_die_cli()
	if not die_cli:
		return {
			"ok": False,
			"found": False,
			"error": "Detect It Easy CLI not found in PATH",
			"file_exists": file_exists,
		}
	if not file_exists:
		return {
			"ok": False,
			"found": True,
			"die": die_cli,
			"error": "Target path not found",
			"file_exists": False,
		}
	return _run_die_json(die_cli, target_path)


def run_die(sample_path: str) -> str:
	result = find_and_run_die(sample_path)
	if result.get("ok"):
		if "result_raw" in result:
			return str(result["result_raw"])  # non-JSON textual output
		return json.dumps(result.get("result", {}), indent=2)
	raise RuntimeError("DIE failed: " + str(result))
