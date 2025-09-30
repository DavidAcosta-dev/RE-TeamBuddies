# Field Truth Reconstruction Stubs

This directory is populated automatically by `scripts/generate_field_truth_stubs.py`.
Each generated C file captures the crate/slot metadata recorded by
`FieldTruthTracer.py` and scaffolds a function skeleton so the decompilation work
can start directly from trace evidence.

## Workflow

1. Run the field-truth pipeline to produce logs in `exports/field_truth_logs/`.
2. Execute:

   ```powershell
   .\.venv\Scripts\python.exe scripts\generate_field_truth_stubs.py
   ```

   Use `--overwrite` if you want to regenerate existing stubs or
   `--max-per-log N` to limit how many functions are emitted per trace file.
3. Flesh out the generated stubs with reconstructed logic, preserving the header
   comment so the evidence trail remains intact.

Generated stubs include the original address, reference count, and the log file
that surfaced the candidate symbol, allowing quick cross-referencing while the
full decompilation proceeds.
