# Gravity Vertical Field Role Inference

Source pattern file: gravity_vertical_field_patterns.md

| Offset | Proposed Role | Confidence | Dot | VelProj | PosUpd | MagUse | RawRefs | Notes | Evidence |
|--------|---------------|------------|-----|---------|--------|--------|---------|-------|----------|
| 0x3c | base_dir_axis_x | 0.950 | 14 | 0 | 0 | 0 | 125 | locked |  |
| 0x3e | base_dir_axis_y | 0.950 | 16 | 0 | 0 | 0 | 110 | locked |  |
| 0x40 | base_dir_axis_z | 0.950 | 16 | 0 | 0 | 0 | 112 | locked |  |
| 0x34 | velocity_axis_x | 0.850 | 0 | 20 | 0 | 0 | 90 | locked |  |
| 0x36 | velocity_axis_y | 0.850 | 0 | 19 | 0 | 0 | 85 | locked |  |
| 0x38 | velocity_axis_z | 0.850 | 0 | 14 | 0 | 0 | 89 | locked |  |
| 0x44 | velocity_magnitude | 0.650 | 0 | 0 | 0 | 0 | 65 | locked | reuse3 |

Heuristic summary:
- Direction axes inferred from frequent tri-component dot product style lines with >> 0xc shifts.
- Velocity components inferred from projection assignments (dir * magnitude >> 0xc) and position update lines.
- Magnitude field inferred from co-occurrence with direction components and shift scaling.

Tune thresholds with environment variables MIN_DOT_COUNT and MIN_VEL_PROJECTION.