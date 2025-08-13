# Phase 4 LogicTeach

Pseudocode:

```
function analyze_file(file_path):
    content = safe_read_text(file_path)
    if empty(content):
        return

    iocs = []
    for category, pattern in REGEX_PATTERNS:
        matches = regex_findall(pattern, content)
        for unique match in matches:
            iocs.append({ type: category, value: match })

    for item in iocs:
        item.score = score_by_type(item.type)

    write_json(output_path(file_path), iocs)
```

Scoring model:
- 10 = suspicious_command | suspicious_file | registry_key
- 5 = url | ip | email
- 1 = file_path

Resilience:
- Ignore regex errors; log and continue
- Ignore decode errors; skip problematic sequences
