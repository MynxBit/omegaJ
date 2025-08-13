# Phase 2 LogicTeach

Pseudocode:

```
function append_die_analysis(sample_path, output_file):
    result = find_and_run_die(sample_path)

    open output_file append as f:
        write "\n=== Detect It Easy Analysis ===\n"
        if result.ok:
            if result.result exists:
                write json_pretty(result.result)
            else if result.result_raw exists:
                write result.result_raw
        else:
            write "DIE run failed: " + json_pretty(result)
        write "\n" + '=' * 50 + "\n"
```

Discovery strategy:
- Try PATH -> common locations -> Program Files recursive -> bounded C:\ walk.
- Prefer `diec.exe` (console), then `die.exe`.

Error handling:
- All exceptions are caught and converted to a failure dict; the pipeline continues.
