# Physics Integrator Map

This report lists functions that likely implement position updates from velocity using Q12 (>> 0xC).

| Function | EA | Base | Axes | Direct pos write |
|---|---:|---|---|:---:|
| FUN_00022dc8 | 0x22dc8 | `param_1` | Z | yes |
| FUN_00022e5c | 0x22e5c | `unaff_s2` | Z | yes |
| FUN_00023000 | 0x23000 | `unaff_s2` | Z | yes |
| FUN_00023110 | 0x23110 | `unaff_s2` | Z | yes |
| FUN_00023180 | 0x23180 | `unaff_s2` | Z | yes |
| FUN_00023210 | 0x23210 | `unaff_s2` | Z | yes |
| FUN_00023698 | 0x23698 | `param_1` | Z | no |
| FUN_00025c18 | 0x25c18 | `iVar2` | Z | no |
| FUN_00035cc0 | 0x35cc0 | `param_1` | Z | no |
| FUN_00044a14 | 0x44a14 | `param_1` | Z | no |
| FUN_00044f80 | 0x44f80 | `param_1` | Z | no |
| FUN_00046024 | 0x46024 | `param_1` | Z | no |
