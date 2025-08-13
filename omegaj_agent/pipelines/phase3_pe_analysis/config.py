"""
Phase 3 configuration constants.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Thresholds
ENTROPY_HIGH = 7.5  # Sections with entropy > 7.5 considered suspicious
SECTION_WX_FLAGS = ("EXECUTE", "WRITE")  # Sections with both write+execute flags

# Common PEStudio install paths
PESTUDIO_PATHS = [
	r"C:\\Program Files\\PEStudio\\pestudio.exe",
	r"C:\\Program Files (x86)\\PEStudio\\pestudio.exe",
]

# Ensure environment is loaded; if VT key is missing, try loading local .env files
VT_API_KEY = os.getenv("VT_API_KEY", "")
if not VT_API_KEY:
	# Try loading .env from project root and omegaj_agent folder
	project_root = Path(__file__).resolve().parents[3]
	agent_root = Path(__file__).resolve().parents[2]
	for env_path in [project_root / ".env", agent_root / ".env"]:
		if env_path.exists():
			load_dotenv(dotenv_path=env_path, override=False)
			VT_API_KEY = os.getenv("VT_API_KEY", "")
			if VT_API_KEY:
				break

# Output formatting
SECTION_SEPARATOR = "=" * 50

# Default output encoding
FILE_ENCODING = "utf-8"

# Temporary folder for PEStudio XML outputs
TEMP_DIR = Path("phase3_temp")
TEMP_DIR.mkdir(exist_ok=True)
