# Field usage in FUN_0001a558

- L10: `FUN_0002d1a4(*(undefined4 *)(unaff_s0 + *(int *)(unaff_s0 + 0x38) * 4 + 4),`
- L12: `*(uint *)(unaff_s0 + 0x38) = *(uint *)(unaff_s0 + 0x38) ^ 1;`
- L13: `iVar2 = (int)*(short *)(unaff_s0 + 0x60) * (int)*(short *)(unaff_s0 + 0x62);`
- L17: `FUN_0002d220(*(undefined4 *)(unaff_s0 + *(int *)(unaff_s0 + 0x3c) * 4 + 0xc),iVar2 >> 1);`
- L18: `*(uint *)(unaff_s0 + 0x3c) = *(uint *)(unaff_s0 + 0x3c) ^ 1;`

Raw snippet (truncated):

````

undefined4 FUN_0001a558(void)

{
  undefined4 uVar1;
  int unaff_s0;
  int iVar2;
  
  if ((*(int *)(unaff_s0 + 0x24) == 0) || (*(int *)(unaff_s0 + 0x8c) != 0)) {
    FUN_0002d1a4(*(undefined4 *)(unaff_s0 + *(int *)(unaff_s0 + 0x38) * 4 + 4),
                 *(undefined4 *)(unaff_s0 + 0x44));
    *(uint *)(unaff_s0 + 0x38) = *(uint *)(unaff_s0 + 0x38) ^ 1;
    iVar2 = (int)*(short *)(unaff_s0 + 0x60) * (int)*(short *)(unaff_s0 + 0x62);
    if (iVar2 < 0) {
      iVar2 = iVar2 + 1;
    }
    FUN_0002d220(*(undefined4 *)(unaff_s0 + *(int *)(unaff_s0 + 0x3c) * 4 + 0xc),iVar2 >> 1);
    *(uint *)(unaff_s0 + 0x3c) = *(uint *)(unaff_s0 + 0x3c) ^ 1;
    uVar1 = 1;
  }
  else {
    FUN_00031cd0();
    uVar1 = 0;
  }
  return uVar1;
}

````
