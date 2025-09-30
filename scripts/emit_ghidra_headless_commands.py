#!/usr/bin/env python3
"""Generate shell commands for running Ghidra headless field-truth jobs."""
from __future__ import annotations

import argparse
import json
import pathlib
import shlex
from typing import Dict, Iterable, List, Sequence

JOB_JSON = pathlib.Path("exports/ghidra_field_truth_job.json")
OUTPUT_PS1 = pathlib.Path("exports/ghidra_headless_commands.ps1")


def load_job(path: pathlib.Path) -> dict:
    if not path.exists():
        raise FileNotFoundError(f"Job file not found: {path}. Run generate_ghidra_field_truth_job.py first.")
    return json.loads(path.read_text(encoding="utf-8"))


def _quote_ps(arg: str) -> str:
    if not arg:
        return "''"
    return "'" + arg.replace("'", "''") + "'"


def _quote_sh(arg: str) -> str:
    return shlex.quote(arg)


def _env_map_for_target(target: dict, extra_args: Sequence[str]) -> Dict[str, str]:
    env: Dict[str, str] = {
        "FT_CRATE": str(target.get("crate_index")),
        "FT_SLOT": str(target.get("slot")),
        "FT_PRIORITY": target.get("priority", ""),
        "FT_FOCUS_SCORE": str(target.get("focus_score", "")),
    }
    if target.get("focus_hint"):
        env["FT_FOCUS"] = target["focus_hint"]
    domains = target.get("domains") or []
    if domains:
        env["FT_DOMAINS"] = ",".join(domains)
    if any(arg == "--enable-logging" for arg in extra_args):
        env["FT_ENABLE_LOGGING"] = "1"
    return {k: v for k, v in env.items() if v}


def build_command(
    shell: str,
    headless: str,
    project_dir: str,
    project_name: str,
    program_pattern: str,
    script_name: str,
    script_dir: str | None,
    extra_args: Sequence[str],
    target: dict,
) -> str:
    focus_hint = target.get("focus_hint", "")
    domains = target.get("domains", [])
    headless_args: List[str] = [headless, project_dir, project_name, "-process", program_pattern]
    if script_dir:
        headless_args.extend(["-scriptPath", script_dir])
    headless_args.extend(["-postScript", script_name])
    script_args: List[str] = [
        "--crate",
        str(target.get("crate_index")),
        "--slot",
        str(target.get("slot")),
    ]
    if target.get("priority"):
        script_args.extend(["--priority", target["priority"]])
    if target.get("focus_score") is not None and target.get("focus_score") != "":
        script_args.extend(["--focusScore", str(target.get("focus_score"))])
    if focus_hint:
        script_args.extend(["--focus", focus_hint])
    if domains:
        script_args.extend(["--domains", ",".join(domains)])
    script_args.extend(extra_args)

    headless_args.extend(script_args)

    if shell == "powershell":
        quote = _quote_ps
        quoted_args = " ".join(quote(arg) for arg in headless_args)
        env_map = _env_map_for_target(target, extra_args)
        segments: List[str] = []
        if env_map:
            assignments = "; ".join(f"$env:{key}={quote(value)}" for key, value in env_map.items())
            segments.append(assignments)
        segments.append(f"& {quoted_args}")
        if env_map:
            removals = ",".join(f"Env:{key}" for key in env_map)
            segments.append(f"Remove-Item {removals}")
        return "; ".join(segments)
    if shell == "bash":
        quote = _quote_sh
        quoted_args = " ".join(quote(arg) for arg in headless_args)
        env_map = _env_map_for_target(target, extra_args)
        if env_map:
            exports = " ".join(f"{key}={quote(value)}" for key, value in env_map.items())
            return f"{exports} {quoted_args}"
        return quoted_args
    raise ValueError(f"Unsupported shell: {shell}")


def emit_commands(
    job: dict,
    project_name: str,
    program_pattern: str,
    shell: str,
    limit: int | None,
) -> List[str]:
    headless_path = job.get("headless_path", "analyzeHeadless")
    project_path = pathlib.Path(job.get("project_path", "."))
    raw_script_path = job.get("script_path", "")
    extra_args = job.get("additional_args", [])
    targets: Iterable[dict] = job.get("targets", [])
    if limit is not None:
        targets = list(targets)[:limit]

    project_dir = str(project_path.parent)
    command_list: List[str] = []
    for target in targets:
        if raw_script_path:
            script_path = pathlib.Path(raw_script_path)
            if script_path.is_absolute():
                script_dir = str(script_path.parent)
                script_name = script_path.name
            else:
                script_dir = None
                script_name = raw_script_path
        else:
            script_dir = None
            script_name = raw_script_path

        command = build_command(
            shell=shell,
            headless=headless_path,
            project_dir=project_dir,
            project_name=project_name,
            program_pattern=program_pattern,
            script_name=script_name,
            script_dir=script_dir,
            extra_args=extra_args,
            target=target,
        )
        command_list.append(command)
    return command_list


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Emit shell commands from Ghidra field-truth job JSON")
    parser.add_argument("--job", default=str(JOB_JSON), help="Path to ghidra_field_truth_job.json")
    parser.add_argument("--project-name", required=True, help="Ghidra project name")
    parser.add_argument(
        "--program-pattern",
        default="*.exe",
        help="Program name or pattern passed to analyzeHeadless -process",
    )
    parser.add_argument("--output", default=str(OUTPUT_PS1), help="Command file to write")
    parser.add_argument("--shell", choices=["powershell", "bash"], default="powershell", help="Shell format")
    parser.add_argument("--limit", type=int, help="Optional limit on number of targets")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    job = load_job(pathlib.Path(args.job))
    commands = emit_commands(
        job=job,
        project_name=args.project_name,
        program_pattern=args.program_pattern,
        shell=args.shell,
        limit=args.limit,
    )
    out_path = pathlib.Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if args.shell == "powershell":
        header = [
            "# Auto-generated headless commands",
            "# Update --program-pattern if needed; run with PowerShell",
            "",
        ]
    else:
        header = [
            "#!/usr/bin/env bash",
            "# Auto-generated headless commands",
            "set -euo pipefail",
            "",
        ]
    out_path.write_text("\n".join(header + commands) + "\n", encoding="utf-8")
    print(f"Wrote {out_path} with {len(commands)} command(s)")


if __name__ == "__main__":
    main()
