#!/usr/bin/env python3
import os, json

ROOT = os.path.join(os.path.expanduser('~'), 'tb-re')
BOOK = os.path.join(ROOT, 'exports', 'suspects_bookmarks.json')

# Curated renames (high-confidence, safe)
CURATED = {
    'MAIN.EXE': {
        'FUN_0001cc58': 'stub_return_zero',
        'thunk_FUN_0001f5d4': 'alloc_mem_thunk',
        'FUN_00014f80': 'spu_apply_channel_params',
        'FUN_000090e0': 'main_update',
        'FUN_0001cc38': 'sync_wait'
    },
    'GAME.BIN': {
        # Integrator ∩ Orientation (direct Z pos writes) — ranked in Q12 overlay
        'FUN_00022e5c': 'phys_integrate_pos_z_step1',
        'FUN_00023000': 'phys_integrate_pos_z_step2',
        'FUN_00023210': 'phys_integrate_pos_z_step3',

        # Additional direct Z writers in the same cluster
        'FUN_00023110': 'phys_integrate_pos_z_step4',
        'FUN_00023180': 'phys_integrate_pos_z_step5',
        'FUN_00022dc8': 'phys_integrate_pos_z_entry',

        # Basis/normalization chain
        'FUN_00044f80': 'orient_normalize_basis',
        'FUN_00044a14': 'orient_recompute_basis_cross',

        # Initializer for the 0x128–0x18C actor block
        'FUN_00032c18': 'actor_config_block_init'
    }
}

def main():
    if not os.path.exists(BOOK):
        raise SystemExit('Not found: ' + BOOK)
    with open(BOOK, 'r', encoding='utf-8') as f:
        data = json.load(f)

    changed = 0
    for bin_name, renames in CURATED.items():
        items = data.get(bin_name) or []
        for it in items:
            nm = it.get('name')
            newnm = renames.get(nm)
            if newnm:
                # Preserve any existing new_name but prefer curated
                if it.get('new_name') != newnm:
                    it['new_name'] = newnm
                    # ensure category exists for better bookmark type grouping
                    if not it.get('category'):
                        it['category'] = 'naming'
                    changed += 1
        data[bin_name] = items

    if changed:
        with open(BOOK, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
        print(f'Updated {changed} bookmark entries with curated new_name values.')
    else:
        print('No changes made (entries may already have these names).')

if __name__ == '__main__':
    main()
