#!/usr/bin/env python3
"""Pipeline Orchestrator

Runs a standard sequence of reverse-engineering automation steps:
 1. Refine vertical classification (if script exists)
 2. Compute coverage report
 3. Populate legacy vertical diff
 4. Aggregate function categories
 5. Regenerate workspace inventory

Usage:
  python scripts/pipeline.py [--skip-inventory] [--steps step1,step2]

Steps identifiers:
  refine_vertical, coverage, legacy_diff, categories, inventory
"""
from __future__ import annotations
import subprocess, sys, shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

AVAILABLE = {
    'orientation': ['python', 'scripts/detect_orientation_funcs.py'],
    'refine_vertical': ['python', 'scripts/refine_vertical_core.py'],
    'coverage': ['python', 'scripts/compute_mapping_coverage.py'],
    'legacy_diff': ['python', 'scripts/populate_vertical_legacy_diff.py'],
    'categories': ['python', 'scripts/aggregate_function_categories.py'],
    'input_hubs': ['python', 'scripts/extract_input_hubs.py'],
    'gravity_deep': ['python', 'scripts/gravity_deep_pass.py'],
    'gravity_ptr': ['python', 'scripts/gravity_pointer_chase.py'],
    'gravity_ptr_v2': ['python', 'scripts/gravity_pointer_chase_v2.py'],
    'gravity_integrator': ['python', 'scripts/gravity_integrator_cluster.py'],
    'gravity_velpos_v3': ['python', 'scripts/gravity_velocity_pos_pair_scan.py'],
    'gravity_neighborhood': ['python', 'scripts/gravity_neighborhood_seed.py'],
    'gravity_neighborhood_ext': ['python', 'scripts/gravity_neighborhood_extend.py'],
    'gravity_composed': ['python', 'scripts/gravity_composed_integrator_scan.py'],
    'gravity_chain_rank': ['python', 'scripts/gravity_chain_rank.py'],
    'gravity_siblings': ['python', 'scripts/gravity_sibling_cluster.py'],
    'gravity_deep_callees': ['python', 'scripts/gravity_deep_callee_scan.py'],
    'gravity_chain_extend': ['python', 'scripts/gravity_extend_composed_chains.py'],
    'gravity_vertical_fields': ['python', 'scripts/gravity_vertical_field_patterns.py'],
    'gravity_vertical_roles': ['python', 'scripts/gravity_vertical_field_roles.py'],
    'gravity_chain_intersections': ['python', 'scripts/gravity_chain_intersections.py'],
    'orient_annotate': ['python', 'scripts/annotate_orientation_candidates.py'],
    'orientation_wide': ['python', 'scripts/orientation_wide_scan.py'],
    'orientation_score': ['python', 'scripts/orientation_score_rank.py'],
    'orientation_focus': ['python', 'scripts/orientation_focus_extract.py'],
    'orientation_roles': ['python', 'scripts/orientation_role_infer.py'],
    'orientation_roles_refined': ['python', 'scripts/orientation_role_refine.py'],
    'orientation_bundle': ['python', 'scripts/orientation_bundle_scan.py'],
    'input_hub_skel': ['python', 'scripts/generate_input_hub_skeletons.py'],
    'input_hub_enrich': ['python', 'scripts/enrich_input_hubs.py'],
    'overlay_hashes': ['python', 'scripts/hash_overlays.py'],
    'overlay_media': ['python', 'scripts/overlay_media_metrics.py'],
    'crosswalk': ['python', 'scripts/update_coverage_crosswalk.py'],
    'inventory': ['python', 'scripts/inventory_workspace.py'],
}

def run(cmd):
    print(f"\n>>> RUN {' '.join(cmd)}")
    res = subprocess.run(cmd, cwd=ROOT)
    if res.returncode != 0:
        print(f"Step failed: {' '.join(cmd)}", file=sys.stderr)
        sys.exit(res.returncode)

def main():
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--steps', help='Comma list of steps to run (default: all)')
    args = ap.parse_args()
    if args.steps:
        steps = [s.strip() for s in args.steps.split(',') if s.strip()]
    else:
        steps = list(AVAILABLE.keys())
    for step in steps:
        if step not in AVAILABLE:
            print(f"Unknown step: {step}", file=sys.stderr)
            sys.exit(1)
        script_path = ROOT / AVAILABLE[step][1]
        if not script_path.exists():
            print(f"Skipping missing script: {script_path}")
            continue
        run(AVAILABLE[step])
    print('\nPipeline complete.')

if __name__ == '__main__':
    main()
