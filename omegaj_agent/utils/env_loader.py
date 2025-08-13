from pathlib import Path
from typing import Dict, Any
import os
from dotenv import load_dotenv
import re


def load_env_all(debug: bool = False) -> Dict[str, Any]:
	"""Load .env from repository root and from `omegaj_agent/.env` explicitly.

	Returns a dict with paths checked and whether VT_API_KEY is present after load.
	"""
	checked: Dict[str, Any] = {}

	# Root .env (D:\\omegaJ\\.env if present)
	root_env = Path.cwd() / ".env"
	checked["root_env_path"] = str(root_env.resolve())
	checked["root_env_exists"] = root_env.exists()
	load_dotenv(dotenv_path=root_env, override=True)

	# Package .env (D:\\omegaJ\\omegaj_agent\\.env)
	package_env = Path(__file__).resolve().parents[1] / ".env"
	checked["package_env_path"] = str(package_env)
	checked["package_env_exists"] = package_env.exists()
	load_dotenv(dotenv_path=package_env, override=True)

	checked["VT_API_KEY_present"] = bool(os.getenv("VT_API_KEY"))
	# Manual fallback parse if still not present (handles odd encodings/BOM)
	if (not checked["VT_API_KEY_present"]) and package_env.exists():
		for enc in ("utf-8-sig", "utf-8", "utf-16", "utf-16-le", "utf-16-be"):
			try:
				text = package_env.read_text(encoding=enc, errors="ignore")
			except Exception:
				continue
			m = re.search(r"^\s*VT_API_KEY\s*=\s*([^\r\n#]+)", text, flags=re.MULTILINE)
			if m:
				raw = m.group(1).strip().strip('"').strip("'")
				if raw:
					os.environ["VT_API_KEY"] = raw
					checked["VT_API_KEY_present"] = True
					break

	if debug:
		print("[env] root:", checked["root_env_path"], "exists?", checked["root_env_exists"])  # noqa: T201
		print("[env] package:", checked["package_env_path"], "exists?", checked["package_env_exists"])  # noqa: T201
		print("[env] VT_API_KEY present?", checked["VT_API_KEY_present"])  # noqa: T201

	return checked


