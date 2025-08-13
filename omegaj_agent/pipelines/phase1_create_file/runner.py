import os
from datetime import datetime
from omegaj_agent.utils.analysis_file import analysis_path_for_sample, upsert_status_flag


def create_analysis_file(sample_path: str) -> str:
	out_path = analysis_path_for_sample(sample_path)
	if not os.path.exists(out_path):
		with open(out_path, "w", encoding="utf-8") as f:
			sample_name, _ = os.path.splitext(os.path.basename(sample_path))
			f.write(f"Sample Name: {sample_name}\n")
			f.write(f"File Path: {sample_path}\n")
			f.write(f"Analysis Start: {datetime.now()}\n")
			f.write("=" * 50 + "\n")
	# mark status
	upsert_status_flag(out_path, "phase1", "done")
	return str(out_path)
