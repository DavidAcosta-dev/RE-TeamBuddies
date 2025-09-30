#!/usr/bin/env python3
"""End-to-end automation pipeline for PSYQ field-truth tracing.

This script chains together the existing data-prep utilities, generates the
headless Ghidra job description, emits runnable commands, optionally executes
those commands, and finally summarizes any resulting log files.

Example usage (PowerShell or cmd):

    python scripts/field_truth_pipeline.py \
        --project-path ghidra_proj/TBProject \
        --project-name TBProject \
        --program SCES_019.23 \
        --script-path ghidra_scripts/FieldTruthTracer.py \
        --ghidra-headless ghidra_11.4.2_PUBLIC/support/analyzeHeadless.bat \
        --limit 5 \
        --execute

By default the pipeline runs all steps except the heavy headless execution,
which requires the ``--execute`` flag. Use ``--dry-run`` to preview all commands
without executing them.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Sequence

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REFRESH_SCRIPTS = (
    "scripts/join_crate_weapon_projectile.py",
    "scripts/prepare_field_truth_sheet.py",
)
DEFAULT_JOB_JSON = Path("exports/ghidra_field_truth_job.json")
DEFAULT_COMMANDS_PATH = Path("exports/ghidra_headless_commands.ps1")
DEFAULT_LOG_DIR = Path("exports/field_truth_logs")


@dataclass
class StepResult:
    name: str
    status: str
    details: str = ""


def _as_path(value: str | Path) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = REPO_ROOT / path
    return path


def run_command(label: str, cmd: Sequence[str], *, env: Dict[str, str] | None = None, dry_run: bool = False) -> StepResult:
    display = " ".join(cmd)
    print(f"\n[{label}] $ {display}")
    if dry_run:
        return StepResult(label, "DRY-RUN", display)
    try:
        subprocess.run(cmd, check=True, env=env)
        return StepResult(label, "OK", display)
    except subprocess.CalledProcessError as exc:
        return StepResult(label, "FAIL", f"exit={exc.returncode}")


def run_python_script(script: str | Path, args: Sequence[str], *, dry_run: bool = False) -> StepResult:
    script_path = _as_path(script)
    if not script_path.exists():
        return StepResult(script_path.name, "SKIP", "missing script")
    cmd = [sys.executable, str(script_path), *args]
    return run_command(script_path.name, cmd, dry_run=dry_run)


def refresh_exports(scripts: Iterable[str | Path], *, dry_run: bool = False) -> List[StepResult]:
    results: List[StepResult] = []
    for script in scripts:
        results.append(run_python_script(script, [], dry_run=dry_run))
    return results


def generate_job(*, project_path: Path, script_path: Path, headless_path: Path, priorities: Sequence[str], limit: int | None, extra: Sequence[str], dry_run: bool) -> StepResult:
    args: List[str] = [
        "--project",
        str(project_path),
        "--script",
        str(script_path),
        "--headless",
        str(headless_path),
    ]
    if priorities:
        args.extend(["--priorities", *priorities])
    if limit is not None:
        args.extend(["--limit", str(limit)])
    if extra:
        args.extend(["--extra", *extra])
    return run_python_script("scripts/generate_ghidra_field_truth_job.py", args, dry_run=dry_run)


def emit_headless_commands(*, project_name: str, program: str, shell: str, limit: int | None, dry_run: bool) -> StepResult:
    args: List[str] = [
        "--project-name",
        project_name,
        "--program-pattern",
        program,
        "--shell",
        shell,
    ]
    if limit is not None:
        args.extend(["--limit", str(limit)])
    return run_python_script("scripts/emit_ghidra_headless_commands.py", args, dry_run=dry_run)


def execute_headless(commands_path: Path, *, dry_run: bool, execute: bool, limit: int | None) -> List[StepResult]:
    results: List[StepResult] = []
    if not execute:
        results.append(StepResult("headless", "SKIP", "use --execute to run Ghidra"))
        return results
    if not commands_path.exists():
        results.append(StepResult("headless", "SKIP", "command file missing"))
        return results
    shell = shutil.which("pwsh") or shutil.which("powershell")
    if shell is None:
        results.append(StepResult("headless", "SKIP", "PowerShell not found"))
        return results
    lines = [line.strip() for line in commands_path.read_text(encoding="utf-8").splitlines()]
    payload = [line for line in lines if line and not line.startswith("#")]
    if limit is not None:
        payload = payload[:limit]
    for index, line in enumerate(payload, start=1):
        label = f"headless[{index}]"
        cmd = [shell, "-NoLogo", "-NoProfile", "-Command", line]
        results.append(run_command(label, cmd, dry_run=dry_run))
    if not payload:
        results.append(StepResult("headless", "SKIP", "no commands to run"))
    return results


def summarize_logs(job_path: Path, log_dir: Path, *, limit: int | None) -> List[StepResult]:
    if not job_path.exists():
        return [StepResult("summary", "SKIP", "job JSON missing")]
    targets = json.loads(job_path.read_text(encoding="utf-8")).get("targets", [])
    if limit is not None:
        targets = targets[:limit]
    summaries: List[str] = []
    summary_rows: List[Dict[str, object]] = []
    for target in targets:
        log_name = f"crate{target['crate_index']}_slot{target['slot']}_focus{target.get('focus_score', 0)}.log"
        log_path = log_dir / log_name
        row: Dict[str, object] = {
            "crate_index": target.get("crate_index"),
            "crate_label": target.get("crate_label"),
            "slot": target.get("slot"),
            "priority": target.get("priority"),
            "focus_score": target.get("focus_score"),
            "focus_hint": target.get("focus_hint"),
            "domains": ",".join(target.get("domains", [])),
            "log_name": log_name,
        }
        if not log_path.exists():
            summaries.append(f"missing log: {log_name}")
            row["matches"] = ""
            row["fallback_count"] = ""
            row["fallback_scanned_functions"] = ""
            row["fallback_scanned_symbols"] = ""
            row["fallback_scanned_instructions"] = ""
            row["fallback_reference_total"] = ""
            row["fallback_memory_blocks"] = ""
            summary_rows.append(row)
            continue
        log_info = _parse_log(log_path)
        summaries.append(
            f"crate {target['crate_index']:02d} slot {target['slot']:02d}: matches={log_info['matches']} fallback={log_info['fallback_count']}"
        )
        row.update(log_info)
        summary_rows.append(row)
    if not summaries:
        return [StepResult("summary", "SKIP", "no targets to summarize")]
    summary_note = ""
    if summary_rows:
        summary_path = log_dir.parent / "field_truth_summary.csv"
        fieldnames = [
            "crate_index",
            "crate_label",
            "slot",
            "priority",
            "focus_score",
            "focus_hint",
            "domains",
            "matches",
            "fallback_count",
            "fallback_scanned_functions",
            "fallback_scanned_symbols",
            "fallback_scanned_instructions",
            "fallback_reference_total",
            "fallback_memory_blocks",
            "log_name",
        ]
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        with summary_path.open("w", newline="", encoding="utf-8") as fp:
            writer = csv.DictWriter(fp, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(summary_rows)
        rel_summary = summary_path.relative_to(REPO_ROOT)
        summary_note = f"\nWrote {rel_summary}"
    return [StepResult("summary", "OK", "\n" + "\n".join(summaries) + summary_note)]


def _parse_log(path: Path) -> Dict[str, int]:
    metrics = {
        "matches": 0,
        "fallback_count": 0,
        "fallback_scanned_functions": 0,
        "fallback_scanned_symbols": 0,
        "fallback_scanned_instructions": 0,
        "fallback_reference_total": 0,
        "fallback_memory_blocks": 0,
    }
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("matches="):
            metrics["matches"] = int(line.split("=", 1)[1] or 0)
        elif line.startswith("fallback_count="):
            metrics["fallback_count"] = int(line.split("=", 1)[1] or 0)
        elif line.startswith("fallback_scanned_functions="):
            metrics["fallback_scanned_functions"] = int(line.split("=", 1)[1] or 0)
        elif line.startswith("fallback_scanned_symbols="):
            metrics["fallback_scanned_symbols"] = int(line.split("=", 1)[1] or 0)
        elif line.startswith("fallback_scanned_instructions="):
            metrics["fallback_scanned_instructions"] = int(line.split("=", 1)[1] or 0)
        elif line.startswith("fallback_reference_total="):
            metrics["fallback_reference_total"] = int(line.split("=", 1)[1] or 0)
        elif line.startswith("fallback_memory_blocks="):
            metrics["fallback_memory_blocks"] = int(line.split("=", 1)[1] or 0)
    return metrics


def print_report(results: Iterable[StepResult]) -> None:
    print("\n=== Pipeline Summary ===")
    for result in results:
        detail = f" :: {result.details}" if result.details else ""
        print(f"{result.name:<20} {result.status}{detail}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Automate PSYQ field-truth tracing pipeline")
    parser.add_argument("--project-path", default="ghidra_proj/TBProject", help="Path to the Ghidra project (directory/file)")
    parser.add_argument("--project-name", default="TBProject", help="Ghidra project name")
    parser.add_argument("--program", default="SCES_019.23", help="Program name or pattern to process")
    parser.add_argument("--script-path", default="ghidra_scripts/FieldTruthTracer.py", help="FieldTruthTracer script path")
    parser.add_argument(
        "--ghidra-headless",
        default="ghidra_11.4.2_PUBLIC/support/analyzeHeadless.bat",
        help="Path to analyzeHeadless executable",
    )
    parser.add_argument(
        "--priorities",
        nargs="*",
        default=["high", "second"],
        help="Priorities to include when building the job",
    )
    parser.add_argument("--extra", nargs="*", default=["--enable-logging"], help="Additional args for FieldTruthTracer")
    parser.add_argument("--limit", type=int, help="Limit the number of targets processed")
    parser.add_argument("--refresh-scripts", nargs="*", default=list(DEFAULT_REFRESH_SCRIPTS), help="Data-prep scripts to run first")
    parser.add_argument("--dry-run", action="store_true", help="Print commands without executing them")
    parser.add_argument("--execute", action="store_true", help="Run headless Ghidra commands (requires analyzeHeadless)")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    project_path = _as_path(args.project_path)
    script_path = _as_path(args.script_path)
    headless_path = _as_path(args.ghidra_headless)
    job_json = _as_path(DEFAULT_JOB_JSON)
    commands_path = _as_path(DEFAULT_COMMANDS_PATH)
    log_dir = _as_path(DEFAULT_LOG_DIR)

    results: List[StepResult] = []

    results.extend(refresh_exports(args.refresh_scripts, dry_run=args.dry_run))

    results.append(
        generate_job(
            project_path=project_path,
            script_path=script_path,
            headless_path=headless_path,
            priorities=args.priorities,
            limit=args.limit,
            extra=args.extra,
            dry_run=args.dry_run,
        )
    )

    results.append(
        emit_headless_commands(
            project_name=args.project_name,
            program=args.program,
            shell="powershell",
            limit=args.limit,
            dry_run=args.dry_run,
        )
    )

    results.extend(
        execute_headless(
            commands_path,
            dry_run=args.dry_run,
            execute=args.execute,
            limit=args.limit,
        )
    )

    results.extend(summarize_logs(job_json, log_dir, limit=args.limit))

    print_report(results)


if __name__ == "__main__":
    main()
