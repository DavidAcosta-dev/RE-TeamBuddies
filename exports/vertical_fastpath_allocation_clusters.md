# Fast-path allocation -> updater clusters

| Function | EA | alloc@ | fast@ | dist | zeroGateInWindow |
|----------|----|-------:|------:|-----:|------------------:|
| FUN_0000a944 | 0xa944 | 21 | 26 | 5 | 0 |
| FUN_0000a944 | 0xa944 | 21 | 26 | 5 | 0 |
| FUN_0000a944 | 0xa944 | 21 | 26 | 5 | 0 |
| FUN_0000a944 | 0xa944 | 21 | 26 | 5 | 0 |

## Snippets

### FUN_0000a944 0xa944 dist=5

````
  FUN_0001a3b0(param_1 + 0x31,0,0,0);
  FUN_0001a3b0(param_1 + 0x36,0,0,0);
  iVar1 = thunk_FUN_0001f5d4(8);
  if (iVar1 != 0) {
    FUN_000233dc(iVar1,0x1000);
  }
  param_1[0x3b] = iVar1;
  FUN_0001a558(*(undefined4 *)param_1[0x3b],((undefined4 *)param_1[0x3b])[1]);
  iVar1 = thunk_FUN_0001f5d4(8);
  if (iVar1 != 0) {
    FUN_000233dc(iVar1,0x1000);
  }
  param_1[0x3c] = iVar1;
  FUN_0001a558(*(undefined4 *)param_1[0x3c],((undefined4 *)param_1[0x3c])[1]);
  *param_1 = 0;
  FUN_0001a674(param_1 + *param_1 * 0x17 + 3);
````

### FUN_0000a944 0xa944 dist=5

````
  FUN_0001a3b0(param_1 + 0x31,0,0,0);
  FUN_0001a3b0(param_1 + 0x36,0,0,0);
  iVar1 = thunk_FUN_0001f5d4(8);
  if (iVar1 != 0) {
    FUN_000233dc(iVar1,0x1000);
  }
  param_1[0x3b] = iVar1;
  FUN_0001a558(*(undefined4 *)param_1[0x3b],((undefined4 *)param_1[0x3b])[1]);
  iVar1 = thunk_FUN_0001f5d4(8);
  if (iVar1 != 0) {
    FUN_000233dc(iVar1,0x1000);
  }
  param_1[0x3c] = iVar1;
  FUN_0001a558(*(undefined4 *)param_1[0x3c],((undefined4 *)param_1[0x3c])[1]);
  *param_1 = 0;
  FUN_0001a674(param_1 + *param_1 * 0x17 + 3);
````

### FUN_0000a944 0xa944 dist=5

````
  FUN_0001a3b0(param_1 + 0x31,0,0,0);
  FUN_0001a3b0(param_1 + 0x36,0,0,0);
  iVar1 = thunk_FUN_0001f5d4(8);
  if (iVar1 != 0) {
    FUN_000233dc(iVar1,0x1000);
  }
  param_1[0x3b] = iVar1;
  FUN_0001a558(*(undefined4 *)param_1[0x3b],((undefined4 *)param_1[0x3b])[1]);
  iVar1 = thunk_FUN_0001f5d4(8);
  if (iVar1 != 0) {
    FUN_000233dc(iVar1,0x1000);
  }
  param_1[0x3c] = iVar1;
  FUN_0001a558(*(undefined4 *)param_1[0x3c],((undefined4 *)param_1[0x3c])[1]);
  *param_1 = 0;
  FUN_0001a674(param_1 + *param_1 * 0x17 + 3);
````

### FUN_0000a944 0xa944 dist=5

````
  FUN_0001a3b0(param_1 + 0x31,0,0,0);
  FUN_0001a3b0(param_1 + 0x36,0,0,0);
  iVar1 = thunk_FUN_0001f5d4(8);
  if (iVar1 != 0) {
    FUN_000233dc(iVar1,0x1000);
  }
  param_1[0x3b] = iVar1;
  FUN_0001a558(*(undefined4 *)param_1[0x3b],((undefined4 *)param_1[0x3b])[1]);
  iVar1 = thunk_FUN_0001f5d4(8);
  if (iVar1 != 0) {
    FUN_000233dc(iVar1,0x1000);
  }
  param_1[0x3c] = iVar1;
  FUN_0001a558(*(undefined4 *)param_1[0x3c],((undefined4 *)param_1[0x3c])[1]);
  *param_1 = 0;
  FUN_0001a674(param_1 + *param_1 * 0x17 + 3);
````

