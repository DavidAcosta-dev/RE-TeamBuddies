# Crate Naming Suggestions

## Pickup Start (slot 0x3c / pad 0x40)

- crate_pickup_start?: FUN_000235d4  | pad= | slots=0x3c,0x40 | callers=FUN_00002f34,FUN_0001a804,FUN_000235d4 | callees=FUN_0001cc58,FUN_00021424,FUN_000235d4,FUN_000246d8,FUN_00024bbc,FUN_00035324
- crate_pickup_start?: FUN_00023588  | pad=0x10,0x40 | slots=0x3c,0x40 | callers=FUN_00009708,FUN_00023588 | callees=FUN_0001cc58,FUN_00021424,FUN_00023588,FUN_000246d8,FUN_00024bbc,FUN_00035324
- crate_pickup_start?: FUN_00008528  | pad= | slots=0x38,0x3c | callers=FUN_00008528 | callees=FUN_00008528,FUN_0001cba8,FUN_0001cc58,FUN_0001f5d4,FUN_00020484,FUN_000204e4
- crate_pickup_start?: FUN_00009708  | pad= | slots=0x38,0x3c,0x40 | callers=FUN_00009708 | callees=FUN_00009708,FUN_0001cc58,FUN_0001cc68,FUN_0001d600,FUN_0001f5e8,FUN_00021c64
- crate_pickup_start?: FUN_000171fc  | pad= | slots=0x3c | callers=FUN_000171fc | callees=FUN_000171fc,FUN_0001cb60,FUN_0001cc58,FUN_0001d600,FUN_0001dd68,FUN_0002e148
- crate_pickup_start?: FUN_000090e0  | pad= | slots=0x38,0x3c,0x40 | callers=FUN_000090e0 | callees=FUN_000090e0,FUN_0001caf0,FUN_0001cbb8,FUN_0001cc38,FUN_0001cc58,FUN_0001d600
- crate_pickup_start?: FUN_0002391c  | pad= | slots=0x3c | callers=FUN_000080a0,FUN_0001f734,FUN_00022234,FUN_0002391c | callees=FUN_0002391c,FUN_000246d8,FUN_00035324
- crate_pickup_start?: FUN_0001a348  | pad= | slots=0x38,0x3c,0x40 | callers=FUN_00002f34,FUN_0001a348,FUN_0001a804 | callees=FUN_0001a348,FUN_0001f5e8

## Throw Start (slot 0x40 / pad 0x10)

- crate_throw_start?: FUN_000235d4  | pad= | slots=0x3c,0x40 | callers=FUN_00002f34,FUN_0001a804,FUN_000235d4 | callees=FUN_0001cc58,FUN_00021424,FUN_000235d4,FUN_000246d8,FUN_00024bbc,FUN_00035324
- crate_throw_start?: FUN_00023588  | pad=0x10,0x40 | slots=0x3c,0x40 | callers=FUN_00009708,FUN_00023588 | callees=FUN_0001cc58,FUN_00021424,FUN_00023588,FUN_000246d8,FUN_00024bbc,FUN_00035324
- crate_throw_start?: FUN_0001a804  | pad= | slots=0x40 | callers=FUN_0001a804 | callees=FUN_00018878,FUN_0001a348,FUN_0001a734,FUN_0001a804,FUN_0001d600,FUN_0002245c
- crate_throw_start?: FUN_00009708  | pad= | slots=0x38,0x3c,0x40 | callers=FUN_00009708 | callees=FUN_00009708,FUN_0001cc58,FUN_0001cc68,FUN_0001d600,FUN_0001f5e8,FUN_00021c64
- crate_throw_start?: FUN_000090e0  | pad= | slots=0x38,0x3c,0x40 | callers=FUN_000090e0 | callees=FUN_000090e0,FUN_0001caf0,FUN_0001cbb8,FUN_0001cc38,FUN_0001cc58,FUN_0001d600
- crate_throw_start?: FUN_0001a348  | pad= | slots=0x38,0x3c,0x40 | callers=FUN_00002f34,FUN_0001a348,FUN_0001a804 | callees=FUN_0001a348,FUN_0001f5e8

## Carry/Base Idle (slot 0x38)

- crate_carry_idle_state?: FUN_00008528  | pad= | slots=0x38,0x3c | callers=FUN_00008528 | callees=FUN_00008528,FUN_0001cba8,FUN_0001cc58,FUN_0001f5d4,FUN_00020484,FUN_000204e4
- crate_carry_idle_state?: FUN_00009708  | pad= | slots=0x38,0x3c,0x40 | callers=FUN_00009708 | callees=FUN_00009708,FUN_0001cc58,FUN_0001cc68,FUN_0001d600,FUN_0001f5e8,FUN_00021c64
- crate_carry_idle_state?: FUN_000090e0  | pad= | slots=0x38,0x3c,0x40 | callers=FUN_000090e0 | callees=FUN_000090e0,FUN_0001caf0,FUN_0001cbb8,FUN_0001cc38,FUN_0001cc58,FUN_0001d600
- crate_carry_idle_state?: FUN_0001a734  | pad= | slots=0x38 | callers=FUN_00002f34,FUN_0000a944,FUN_0001a734,FUN_0001a804 | callees=FUN_0001a734,FUN_0002d2dc,FUN_00030c18
- crate_carry_idle_state?: FUN_000204e4  | pad= | slots=0x38 | callers=FUN_00008528,FUN_000204e4 | callees=FUN_000204e4,FUN_00024bbc,FUN_00035324
- crate_carry_idle_state?: FUN_0001a348  | pad= | slots=0x38,0x3c,0x40 | callers=FUN_00002f34,FUN_0001a348,FUN_0001a804 | callees=FUN_0001a348,FUN_0001f5e8
- crate_carry_idle_state?: FUN_0001eec8  | pad= | slots=0x38 | callers=FUN_0001eec8 | callees=FUN_0001eec8,FUN_0001f5e8
