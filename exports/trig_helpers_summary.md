# Trig helper summary for MAIN.EXE

## Callers of suspected trig helpers

### stub_ret0_FUN_0001c7fc

- callers: 5
- stub_ret0_FUN_00000edc (0xEDC)
- FUN_0000d438 (0xD438)
- phys_angle_window_config (0x1E314)
- phys_angle_update_recompute (0x1E404) [phys_recompute_basis]
- suspect_FUN_0001fab8 (0x1FAB8)

### stub_ret0_FUN_0001c83c

- callers: 2
- phys_angle_window_config (0x1E314)
- suspect_FUN_0001fab8 (0x1FAB8)

## stub_ret0_FUN_0001c7fc (0x1C7FC)

- callers: 5

Callers (up to 20):
- FUN_0000d438 (0xD438)
- phys_angle_update_recompute (0x1E404) [phys_recompute_basis]
- phys_angle_window_config (0x1E314)
- stub_ret0_FUN_00000edc (0xEDC)
- suspect_FUN_0001fab8 (0x1FAB8)

Decomp (truncated):
```

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int stub_ret0_FUN_0001c7fc(void)

{
  byte bVar1;
  code *in_v0;
  int iVar2;
  int *unaff_s0;
  int unaff_s1;
  int unaff_s2;
  int unaff_s3;
  int unaff_s5;
  
  (*in_v0)();
  *unaff_s0 = -1;
  while( true ) {
    (*_DAT_80053b44)();
    iVar2 = FUN_00032d54();
    if (iVar2 < 0) {
      return iVar2;
    }
    FUN_00035094(0x3c);
    iVar2 = FUN_00033164();
    if (iVar2 == 0) {
      iVar2 = FUN_00034130();
      return iVar2;
    }
    _DAT_80053b9c = _DAT_80053b9c + -1;
    if (_DAT_80053b9c < 2) {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    iVar2 = *unaff_s0;
    if (iVar2 < 0) break;
    if (0 < iVar2) {
      unaff_s3 = *(int *)(unaff_s2 + _DAT_80053b70 + 0xc) + iVar2 * 0xf0 + -0xf0;
      (*_DAT_80053b5c)(unaff_s3);
```

## stub_ret0_FUN_0001c83c (0x1C83C)

- callers: 2

Callers (up to 20):
- phys_angle_window_config (0x1E314)
- suspect_FUN_0001fab8 (0x1FAB8)

Decomp (truncated):
```

/* WARNING: Control flow encountered bad instruction data */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int stub_ret0_FUN_0001c83c(void)

{
  byte bVar1;
  int iVar2;
  int *unaff_s0;
  int unaff_s1;
  int unaff_s2;
  int unaff_s3;
  int unaff_s5;
  
  while( true ) {
    FUN_00035094(0x3c);
    iVar2 = FUN_00033164();
    if (iVar2 == 0) {
      iVar2 = FUN_00034130();
      return iVar2;
    }
    _DAT_80053b9c = _DAT_80053b9c + -1;
    if (_DAT_80053b9c < 2) {
                    /* WARNING: Bad instruction - Truncating control flow here */
      halt_baddata();
    }
    iVar2 = *unaff_s0;
    if (iVar2 < 0) {
      while( true ) {
        _DAT_80053b9c = _DAT_80053b9c + -1;
        if (_DAT_80053b9c < 1) {
          FUN_000331f4();
          bVar1 = *(byte *)(unaff_s1 + 0x44);
          *(byte *)(unaff_s1 + 0x44) = bVar1 + 1;
          *(undefined1 *)((uint)bVar1 + *(int *)(unaff_s1 + 0x3c)) = *_DAT_80053ba0;
          (*_DAT_80053b3c)(0);
          return 0;
        }
        (*_DAT_80053b44)();
```
