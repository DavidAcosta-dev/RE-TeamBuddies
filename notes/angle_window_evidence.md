# Angle window config: evidence and field map

Purpose: Track what we've learned about the angle window/config functions and document offsets used so naming stays consistent across MAIN.EXE and GAME.BIN.

Key named functions

- phys_angle_state_init (0x1E11C): initializes angle fields; calls phys_recompute_basis.
- phys_angle_update_reset (0x1E150): resets angle deltas; calls phys_recompute_basis.
- phys_angle_update_recompute (0x1E404): writes angle fields (0x31/0x02/0x04/0x3A) then calls phys_recompute_basis.
- phys_angle_window_config_scaled (0x1E2D4): configures window with scaled inputs; writes 0x02, 0x04, and computes 0x38/0x3C via trig helpers.
- phys_angle_window_config (0x1E314): similar, unscaled; called by 0x20A54 and 0x20C14.
- phys_recompute_basis (0x35984): recomputes orientation basis using Q12 angles.

Observed field map (structure-relative, based on decomp patterns)

- +0x02: angle magnitude/window param; value often left-shifted by 1–2 bits depending on scale.
- +0x04: paired window param; copied from input without scaling in the unscaled version.
- +0x31: byte flag updated in update_recompute; likely dirty/needs_basis flag.
- +0x3A/+0x3C: short pair derived via trig LUT helpers; consistent with sin/cos window bounds or basis seeds.
- +0x38: occasionally paired with +0x3A/+0x3C; appears to hold companion short from trig.

Trig helpers (suspect; apply=0 until confirmed)

- 0x1C7FC (suspect_trig_LUT_A): returns a short; called with scaled inputs; results stored at +0x38/+0x3A.
- 0x1C83C (suspect_trig_LUT_B): returns a short; results stored at +0x3C.
Evidence: both appear in angle config and other Q12 math sites; signatures suggest LUT-based sin/cos.

Indicators supporting Q12

- >>6 integration shifts in related code.
- 12-bit angle mask 0x0FFF in angle update paths.
- LUT usage for trig-like operations.

Next validations

- Cross-binary: confirm same call shapes in GAME.BIN and names align.
- BIOS/lib ref: compare call signatures against PSYQ trig helpers if present.
- Callgraph: ensure every angle write path leads to phys_recompute_basis.
