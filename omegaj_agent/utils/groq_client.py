import os
from typing import Any, Optional

try:
	from groq import Groq
except Exception:  # pragma: no cover - optional dependency at scaffold time
	Groq = None  # type: ignore


def get_groq_client() -> Optional[Any]:
	api_key = os.getenv("GROQ_API_KEY")
	if not api_key or Groq is None:
		return None
	return Groq(api_key=api_key)


def complete_chat(prompt: str, model: str = "llama-3.3-70b-versatile") -> Optional[str]:
	client = get_groq_client()
	if client is None:
		return None
	try:
		resp = client.chat.completions.create(
			model=model,
			messages=[{"role": "user", "content": prompt}],
			temperature=0.3,
			top_p=1,
			max_completion_tokens=1024,
			stream=False,
		)
		choice = getattr(resp, "choices", [None])[0]
		if not choice:
			return ""
		return getattr(getattr(choice, "message", {}), "content", "")
	except Exception:
		return None
