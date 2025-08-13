# Phase 1 LogicTeach

Pseudocode:

```
function create_analysis_file(sample_path):
    sample_name = basename_without_ext(sample_path)
    out_file = f"{sample_name}_analysis_phase1.txt"

    with open(out_file, 'w', encoding='utf-8') as f:
        f.write(f"Sample Name: {sample_name}\n")
        f.write(f"File Path: {sample_path}\n")
        f.write(f"Analysis Start: {now()}\n")
        f.write('=' * 50 + '\n')

    return out_file
```

Details:
- Uses standard library only.
- Creates parent directories if needed (handled by OS CWD).
- The separator makes subsequent appended sections easy to spot.
