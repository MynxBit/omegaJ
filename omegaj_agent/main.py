import argparse
from dotenv import load_dotenv
from pathlib import Path
from omegaj_agent.utils.env_loader import load_env_all
from pipelines import (
    append_phase0_section,
    create_analysis_file,
    append_die_analysis,
    run_phase3_pestudio,
    run_phase3_fallback,
    phase4_analyze_file,
    analyze_phase5_groq,
)


def main() -> None:
	# Load env from project root and local package folder explicitly (debug off here)
	try:
		load_env_all(debug=False)
	except Exception:
		load_dotenv(); load_dotenv(Path(__file__).with_name('.env'))
	parser = argparse.ArgumentParser(description="OmegaJ Phase 1 Agent Bot")
	parser.add_argument("--file", required=True, help="Path to the sample file")
	parser.add_argument("--stage", type=int, default=0, help="Specific pipeline stage to run (0 = all)")
	parser.add_argument("--overwrite", action="store_true", help="Overwrite existing phase sections if present")
	parser.add_argument("--phase4-json", help="Path to Phase 4 JSON (for stage 5)")
	parser.add_argument("--precheck", action="store_true", help="Run Phase 0 VT precheck before the requested stage")
	args = parser.parse_args()

	if args.precheck or args.stage in (0, 1):
		# Prepend Phase 0 when requested or in full run
		try:
			append_phase0_section(args.file, overwrite=args.overwrite)
		except Exception:
			pass

	if args.stage in (0, 1):
		output_file = create_analysis_file(args.file)
		print(f"[+] Created/ensured analysis file: {output_file}")
	else:
		from omegaj_agent.utils.analysis_file import analysis_path_for_sample
		output_file = str(analysis_path_for_sample(args.file))

	if args.stage in (0, 2):
		# Ensure Phase 1 exists before appending
		from pathlib import Path
		if not Path(output_file).exists():
			create_analysis_file(args.file)
		append_die_analysis(args.file, output_file, overwrite=args.overwrite)
		print(f"[+] DIE analysis appended to {output_file}")

	if args.stage in (0, 3):
		from pathlib import Path
		if not Path(output_file).exists():
			create_analysis_file(args.file)
		ok = run_phase3_pestudio(args.file, output_file, overwrite=args.overwrite)
		if ok:
			print(f"[+] PEStudio analysis appended to {output_file}")
		else:
			run_phase3_fallback(args.file, output_file, overwrite=args.overwrite)
			print(f"[+] Python fallback PE analysis appended to {output_file}")

	if args.stage in (0, 4):
		from pathlib import Path
		if not Path(output_file).exists():
			create_analysis_file(args.file)
		# Analyze the binary/sample directly for IOC extraction (ASCII/UTF-16 strings),
		# not the report file to avoid picking up tool links such as VirusTotal URLs.
		json_out = phase4_analyze_file(args.file, append_to_report=True, overwrite=args.overwrite)
		if json_out:
			print(f"[+] Phase 4 IOC JSON saved: {json_out}")

	if args.stage in (0, 5):
		from pathlib import Path
		if not Path(output_file).exists():
			create_analysis_file(args.file)
		# Prefer building MARPS directly from MD5 report when no JSON provided
		if args.phase4_json:
			phase4_json_path = args.phase4_json
			report_path = analyze_phase5_groq(phase4_json_path, sample_path=args.file, overwrite=args.overwrite)
		else:
			from pipelines import analyze_phase5_from_report
			report_path = analyze_phase5_from_report(args.file)
		if report_path:
			print(f"[+] Phase 5 Groq report: {report_path}")

	# Stage 3 (Groq) removed per current scope


if __name__ == "__main__":
	main()
