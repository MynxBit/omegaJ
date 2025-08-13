# Phase 3 LogicTeach

Pseudocode (CLI-first):

```
function run_phase3(sample_path, output_file):
    cli = find_pestudio_cli()
    if cli:
        xml = run_cli_export(cli, sample_path)
        if xml:
            text = parse_pestudio_xml(xml)
            append_to_report(output_file, text)
            return True
    # fallback
    text = python_pe_analysis(sample_path)
    append_to_report(output_file, text)
    return False
```

Key pieces:
- `find_pestudio_cli()`: locates `pestudiox.exe` in PATH/Program Files/C:.
- `run_cli_export()`: executes headless export and returns XML path.
- `python_pe_analysis()`: uses `pefile`, entropy, imports, overlay, strings, VT query.

Error handling:
- CLI errors do not fail the pipeline; fallback runs automatically.
