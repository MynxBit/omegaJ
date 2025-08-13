import json
from typing import Dict, Any

from omegaj_agent.utils.detect_die import find_and_run_die
from omegaj_agent.utils.analysis_file import (
	analysis_path_for_sample,
	ensure_report_for_sample,
	has_phase_section,
	write_phase_section,
	upsert_status_flag,
)
from pathlib import Path


def append_die_analysis(sample_path: str, output_file: str = "", overwrite: bool = False) -> None:
	report_path = analysis_path_for_sample(sample_path) if not output_file else Path(output_file)
	ensure_report_for_sample(sample_path)
	phase_tag = "PHASE2_DIE"
	if has_phase_section(report_path, phase_tag) and not overwrite:
		print("[omegaJ] Phase 2 already present in report. Use overwrite to replace.")
		return
	result = find_and_run_die(sample_path)
	body_lines = ["=== Detect It Easy (DIE) Results ==="]
	if result.get("ok"):
		tool = result.get("tool", "diec")
		ret = result.get("returncode")
		stderr = result.get("stderr") or ""
		def _summarize(parsed: Dict[str, Any]) -> None:
			# Render key details from parsed JSON without dumping raw JSON
			detects = parsed.get("detects") or []
			for d in detects[:10]:
				ft = d.get("filetype", "?")
				vals = d.get("values") or []
				body_lines.append(f"- {ft}: {len(vals)} markers")
				for v in vals[:5]:
					type_ = v.get("type") or "Marker"
					name = v.get("name") or ""
					ver = v.get("version") or ""
					info = v.get("info") or ""
					parts = [p for p in [type_, name, ver] if p]
					line = " / ".join(parts)
					if info:
						line += f" [{info}]"
					body_lines.append(f"    • {line}")
			body_lines.append(f"Tool: {tool} | Return code: {ret}")
			if stderr:
				body_lines.append(f"Stderr: {stderr[:200]}")
		if "result" in result:
			body_lines.append("Summary:")
			_summarize(result["result"])
		elif "result_raw" in result:
			# Try to parse raw as JSON; if that fails, include a short preview only
			try:
				parsed = json.loads(str(result["result_raw"]))
				body_lines.append("Summary:")
				_summarize(parsed)
			except Exception:
				preview = str(result["result_raw"]).splitlines()
				body_lines.append("Raw output (truncated):")
				for line in preview[:20]:
					body_lines.append(line)
	else:
		body_lines.append("DIE run failed:")
		# Keep failure as compact JSON string to retain context
		body_lines.append(json.dumps(result, indent=2))
	write_phase_section(report_path, phase_tag, "\n".join(body_lines), overwrite=overwrite)
	upsert_status_flag(report_path, "phase2", "done")
