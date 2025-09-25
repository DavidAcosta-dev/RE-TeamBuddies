# Vertical updater caller candidates

| Caller | EA | Calls | Line | Score | Marks (S=sec,F=flag,G=gate,T=step,C=scale,X=toggle) |
|--------|----|-------|------|-------|-----------------------------------------------|
| FUN_0000a944 | 0xa944 | FUN_0001a558 | 26 | 0 |  |
| FUN_0000a944 | 0xa944 | FUN_0001a558 | 32 | 0 |  |
| FUN_0000ac5c | 0xac5c | FUN_0001a558 | 8 | 0 |  |
| FUN_0000a944 | 0xa944 | FUN_0001a558 | 26 | 0 |  |
| FUN_0000a944 | 0xa944 | FUN_0001a558 | 32 | 0 |  |
| FUN_0000ac5c | 0xac5c | FUN_0001a558 | 8 | 0 |  |
| FUN_0000a944 | 0xa944 | FUN_0001a558 | 26 | 0 |  |
| FUN_0000a944 | 0xa944 | FUN_0001a558 | 32 | 0 |  |
| FUN_0000ac5c | 0xac5c | FUN_0001a558 | 8 | 0 |  |
| FUN_0000a944 | 0xa944 | FUN_0001a558 | 26 | 0 |  |
| FUN_0000a944 | 0xa944 | FUN_0001a558 | 32 | 0 |  |
| FUN_0000ac5c | 0xac5c | FUN_0001a558 | 8 | 0 |  |

## Snippets

### FUN_0000a944 0xa944 line 26 score=0

````
  FUN_000187c4(param_1 + 0x1a,0,param_1[2],param_1[1],param_1[2]);
  *(undefined1 *)((int)param_1 + 0x7e) = 0;
  FUN_00018878(param_1 + 0x36,0,0,param_1[1],param_1[2]);
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
  FUN_0001a734(param_1 + *param_1 * 5 + 0x31);
  FUN_0001a2b0(1);
````

### FUN_0000a944 0xa944 line 32 score=0

````
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
  FUN_0001a734(param_1 + *param_1 * 5 + 0x31);
  FUN_0001a2b0(1);
  return;
}

````

### FUN_0000ac5c 0xac5c line 8 score=0

````

void FUN_0000ac5c(int *param_1,int param_2)

{
  if (param_2 != *param_1) {
    *param_1 = param_2;
    FUN_0001a674(param_1 + *param_1 * 0x17 + 3);
    FUN_0001a558(*(undefined4 *)param_1[*param_1 + 0x3b],((undefined4 *)param_1[*param_1 + 0x3b])[1]
                );
  }
  return;
}

````

### FUN_0000a944 0xa944 line 26 score=0

````
  FUN_000187c4(param_1 + 0x1a,0,param_1[2],param_1[1],param_1[2]);
  *(undefined1 *)((int)param_1 + 0x7e) = 0;
  FUN_00018878(param_1 + 0x36,0,0,param_1[1],param_1[2]);
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
  FUN_0001a734(param_1 + *param_1 * 5 + 0x31);
  FUN_0001a2b0(1);
````

### FUN_0000a944 0xa944 line 32 score=0

````
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
  FUN_0001a734(param_1 + *param_1 * 5 + 0x31);
  FUN_0001a2b0(1);
  return;
}

````

### FUN_0000ac5c 0xac5c line 8 score=0

````

void FUN_0000ac5c(int *param_1,int param_2)

{
  if (param_2 != *param_1) {
    *param_1 = param_2;
    FUN_0001a674(param_1 + *param_1 * 0x17 + 3);
    FUN_0001a558(*(undefined4 *)param_1[*param_1 + 0x3b],((undefined4 *)param_1[*param_1 + 0x3b])[1]
                );
  }
  return;
}

````

### FUN_0000a944 0xa944 line 26 score=0

````
  FUN_000187c4(param_1 + 0x1a,0,param_1[2],param_1[1],param_1[2]);
  *(undefined1 *)((int)param_1 + 0x7e) = 0;
  FUN_00018878(param_1 + 0x36,0,0,param_1[1],param_1[2]);
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
  FUN_0001a734(param_1 + *param_1 * 5 + 0x31);
  FUN_0001a2b0(1);
````

### FUN_0000a944 0xa944 line 32 score=0

````
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
  FUN_0001a734(param_1 + *param_1 * 5 + 0x31);
  FUN_0001a2b0(1);
  return;
}

````

### FUN_0000ac5c 0xac5c line 8 score=0

````

void FUN_0000ac5c(int *param_1,int param_2)

{
  if (param_2 != *param_1) {
    *param_1 = param_2;
    FUN_0001a674(param_1 + *param_1 * 0x17 + 3);
    FUN_0001a558(*(undefined4 *)param_1[*param_1 + 0x3b],((undefined4 *)param_1[*param_1 + 0x3b])[1]
                );
  }
  return;
}

````

### FUN_0000a944 0xa944 line 26 score=0

````
  FUN_000187c4(param_1 + 0x1a,0,param_1[2],param_1[1],param_1[2]);
  *(undefined1 *)((int)param_1 + 0x7e) = 0;
  FUN_00018878(param_1 + 0x36,0,0,param_1[1],param_1[2]);
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
  FUN_0001a734(param_1 + *param_1 * 5 + 0x31);
  FUN_0001a2b0(1);
````

### FUN_0000a944 0xa944 line 32 score=0

````
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
  FUN_0001a734(param_1 + *param_1 * 5 + 0x31);
  FUN_0001a2b0(1);
  return;
}

````

### FUN_0000ac5c 0xac5c line 8 score=0

````

void FUN_0000ac5c(int *param_1,int param_2)

{
  if (param_2 != *param_1) {
    *param_1 = param_2;
    FUN_0001a674(param_1 + *param_1 * 0x17 + 3);
    FUN_0001a558(*(undefined4 *)param_1[*param_1 + 0x3b],((undefined4 *)param_1[*param_1 + 0x3b])[1]
                );
  }
  return;
}

````

