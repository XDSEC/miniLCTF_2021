# Mini-L

**URL**:https://ctf.xidian.edu.cn/#/index
**Team**:cuttl3fish
**Start Time**: 5.06 20:00
**End Time**: 5.12 20:00

## WEB

### web1 easy-java | kyr

不会java，枯嘞

```java
New java.io.BufferedReader(New java.io.FileReader("/flag")).readLine()
```

## MISC

### 抓猫猫 | kyr

hint：kawaii neko chan says that : what doesn't kill u makes u stronger

so what u should do is follow what she said , 然后同时连俩 bot 让他们对线，看看谁更腻害

### 好白给的签到题 | kyr

```python
import base64
f = open("story.txt", "rb").read()
while 1:
    fll=flast
    if b'{' in f and b'}' in f:
        print(f[::-1])
        break
    try:
        flast=f
        f=base64.b64decode(f)
    except:
        flast=fll
        try:
            f=base64.b64decode(f[::-1])
        except:
            f=base64.b64decode(flast[::-1])
```

## CRYPTO

### 土 块 | kyr

把题目中的`game`函数拿出来研究，如下

```python
from tukuai import game
cheat=[[9,[1,0]],[9,[0,1]]]
init_state = [0] * 4
coin1 = randint(0, 1)
coin2 = randint(0, 1)
temp = coin1 * 2 + coin2
init_state[temp] = 1
servercoin,qc = game(cheat, init_state)
print(coin1)
print(coin2)
print(init_state)
print('my coin is ' + str(servercoin) + ' your coin is?')
from qiskit.tools.visualization import plot_bloch_multivector
display(plot_bloch_multivector(init_state))
simulator=Aer.get_backend('qasm_simulator')
result=execute(qc,backend=simulator).result()
from qiskit.tools.visualization import plot_histogram
display(qc.draw(output='mpl'))
display(plot_histogram(result.get_counts(qc)))
```

画出几个图出来看看，只要绘出 bot 的输出 = my coin 的量子电路即可，如下

```
       ┌──────────────────────┐┌───┐        
q12_0: ┤0                     ├┤ X ├──■─────
       │  initialize(0,0,1,0) │└─┬─┘┌─┴─┐┌─┐
q12_1: ┤1                     ├──■──┤ X ├┤M├
       └──────────────────────┘     └───┘└╥┘
 c1: 1/═══════════════════════════════════╩═
                                          0 
```

## Reverse

#### 0oooops | track

> 这道题涉及到windows的异常处理机制SEH

##### SEH

这个题不涉及太多SEH的底层，大概有以下几个点需要了解的：

- SEH实际包含两个主要功能：结束处理（termination handling）和异常处理（exception handling)
- 每当你建立一个try块，它必须跟随一个 `__finally`块或一个`__except`块。
- 一个`try`块之后不能既有finally块又有except块。但可以在try-except块中嵌套try-finally块，反过来 也可以。
- `__try`,`__finally`关键字用来标出结束处理程序两段代码的轮廓
  不管保护体（try块） 是如何退出的。不论你在保护体中使用return，还是goto，或者是longjump，结束处理程序 （finally块）都将被调用。
- 在try使用`__leave`关键字会引起跳转到try块的结尾
- 给`ms_exc.registration.TryLevel`赋值是用于处理嵌套的try

> 学习自HAPPY师傅的博客

然后看看题，main函数直接看发现异常，于是看汇编，定位到伪代码异常处。IDA的分析结果如下

```assembly
.text:00412330 loc_412330:                             ; CODE XREF: _main_0+15C↑j
.text:00412330 ;   __try { // __except at loc_412377
.text:00412330                 mov     [ebp+ms_exc.registration.TryLevel], 0
.text:00412337                 lea     ebx, [ebp+Str]
.text:0041233D                 xor     eax, eax
.text:0041233F                 db      3Eh
.text:0041233F                 mov     dword ptr [eax], 0
.text:00412346                 mov     edx, 0
.text:0041234B                 div     edx
```



发现非常明显的**除零异常**还有**eax清零后却试图访问它的内存**，以及SEH结构。不需要对它进行任何patch，因为必须让程序捕获到这个异常，才会去执行`__except_filter`，也就是

```assembly
text:00412356 loc_412356:                             ; DATA XREF: .rdata:stru_41A238↓o
.text:00412356 ;   __except filter // owned by 412330
.text:00412356                 mov     eax, [ebp+ms_exc.exc_ptr]
.text:00412359                 mov     ecx, [eax]
.text:0041235B                 mov     edx, [ecx]
.text:0041235D                 mov     [ebp+var_1BC], edx
.text:00412363                 mov     eax, [ebp+ms_exc.exc_ptr]
.text:00412366                 push    eax
.text:00412367                 mov     ecx, [ebp+var_1BC]
.text:0041236D                 push    ecx
.text:0041236E                 call    sub_411131
.text:00412373                 add     esp, 8
.text:00412376                 retn
```



稍微看一看`sub_411131`函数的内部逻辑

```c
int __cdecl sub_411DD0(int a1, _EXCEPTION_POINTERS *a2)
{
  unsigned int i; // [esp+D0h] [ebp-40h]
  char v4[40]; // [esp+DCh] [ebp-34h] BYREF
  char *v5; // [esp+104h] [ebp-Ch]

  __CheckForDebuggerJustMyCode(&unk_41D015);
  if ( a2->ExceptionRecord->ExceptionCode != 0xC0000094 ) // 除零异常相应的异常代码
    return 0;
  v5 = (char *)(a2->ContextRecord->Ebx + 9);
  qmemcpy(v4, "!V -}VG-bp}m-nG!b|ra GyGE|Drp D", 31);
  for ( i = 0; i < 0x1F; ++i )
  {
    if ( v4[i] != ((unsigned __int8)a2->ContextRecord->Eip ^ ((v5[2 * i + 1] ^ 0x4D) - 4) ^ 0x13) )
    {
      a2->ContextRecord->Eip += 54;
      return -1;
    }
  }
  a2->ContextRecord->Eip += 63;
  return -1;
}
```

可以发现将运算结果存在v5中，但是只有奇数位，不妨试着还原一下（伪代码）

```c
char magic_1[] = "!V -}VG-bp}m-nG!b|ra GyGE|Drp D";
    for(int i = 0; i < 0x1f; i++) {
        // printf("%c", ((magic_1[i] ^ 0x13 ^ errr_addr)+4)^0x4d);
        flag[2 * i + 1] = ((magic_1[i] ^ 0x13 ^ errr_addr)+4)^0x4d;
    }
```

并且如果满足条件，将会改变eip的值，将进程从异常中跳出来，不妨看看跳到了哪里

```python
print(hex(0x41234B + 63))
```

那里是congratulations的提示信息，但很明显我们还没拿到完整的flag

##### VEH && TLS

查看IDA的Exports窗口可以看到TlsCallback_0_0

> TLS，Thread Local Storage 线程局部存储，TLS回调函数的调用运行要先于PE代码执行，该特性使它可以作为一种反调试技术使用。
>
> TLS是各线程的独立的数据存储空间，使用TLS技术可在线程内部独立使用或修改进程的全局数据或静态数据。



return了一个奇怪的函数

```c
PVOID __stdcall TlsCallback_0_0(int a1, int a2, int a3)
{
  __CheckForDebuggerJustMyCode(&unk_41D015);
  return AddVectoredExceptionHandler(1u, Handler);
}

// attributes: thunk
LONG __stdcall Handler(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
  return sub_411BD0(ExceptionInfo);
}

int __stdcall sub_411BD0(_EXCEPTION_POINTERS *a1)
{
  unsigned int i; // [esp+D0h] [ebp-40h]
  char v3[40]; // [esp+DCh] [ebp-34h]
  DWORD v4; // [esp+104h] [ebp-Ch]

  __CheckForDebuggerJustMyCode(&unk_41D015);
  if ( a1->ExceptionRecord->ExceptionCode != 0xC0000005 ) // 不可访问地址相应的异常代码
    return 0;
  v4 = a1->ContextRecord->Ebx + 9;
  v3[0] = 16;
  v3[1] = 4;
  v3[2] = 24;
  v3[3] = 11;
  v3[4] = 24;
  v3[5] = 16;
  v3[6] = 4;
  v3[7] = 21;
  v3[8] = 11;
  v3[9] = 5;
  v3[10] = 31;
  v3[11] = 46;
  v3[12] = 33;
  v3[13] = 46;
  v3[14] = 72;
  v3[15] = 21;
  v3[16] = 6;
  v3[17] = 46;
  v3[18] = 17;
  v3[19] = 69;
  v3[20] = 5;
  v3[21] = 62;
  v3[22] = 46;
  v3[23] = 24;
  v3[24] = 21;
  v3[25] = 72;
  v3[26] = 46;
  v3[27] = 69;
  v3[28] = 33;
  v3[29] = 31;
  v3[30] = 10;
  for ( i = 0; i < 0x1F; ++i )
  {
    if ( v3[i] != (((*(char *)(v4 + 2 * i) ^ 0x37) + 4) ^ 0x42) )
    {
      a1->ContextRecord->Eip += 66;
      return -1;
    }
  }
  a1->ContextRecord->Eip += 7;
  return -1;
}
```

（Handler显然是第二段解密），因为我实在是太菜了，又查了一下这个函数的功能，发现了另一个异常处理机制VEH

VEH处理流程

> - CPU捕获异常信息
> - 通过KiDispatchException进行分发(EIP=KiUserExceptionDispatcher)
> - KiUserExceptionDispatcher调用RtIDispatchException.
> - RtIDispatchException查找VEH处理函数链表并调用相关处理函数
> - 代码返回到KiUserExceptionDispatcher
> - 调用ZwContinue再次进入0环(ZwContinue调用NtContinue,主要作用就是恢复 TRAPFRAME然后通过_KiServiceExit返回到3环)。
> - 线程再次返回3环后,从修正后的位置开始执行
>
> 学习自：https://blog.csdn.net/weixin_42052102/article/details/83540134



##### EXP

**这样一来整个流程大致明了了**

- VEH抓到`0xC0000005`
- SEH抓到`0xC0000094`
- 分别的flag在各自的handler里面

脚本如下，写的比较乱

```c
#include <stdio.h>

int main() {
    char flag[100] = {0};
    unsigned char errr_addr = 0x30234B;
    char magic_1[] = "!V -}VG-bp}m-nG!b|ra GyGE|Drp D";
    for(int i = 0; i < 0x1f; i++) {
        // printf("%c", ((magic_1[i] ^ 0x13 ^ errr_addr)+4)^0x4d);
        flag[2 * i + 1] = ((magic_1[i] ^ 0x13 ^ errr_addr)+4)^0x4d;
    }
    printf("\n");
    char magic_2[] = {16,4,24,11,24,16,4,21,11,5,31,46,33,46,72,21,6,46,17,69,5,62,46,24,21,72,46,69,33,31,10};
    for(int i = 0; i < 0x1f; i++) {
        // printf("%c", ((magic_2[i]^0x42)-4)^0x37);
        flag[2 * i] = ((magic_2[i]^0x42)-4)^0x37;
    }
    printf("%s", flag);
    // miniLctf{y0u_a1r4ady_und4rstand_th4_w1nd0ws_exc4pt1On_handl1e_m4chan1sm}
    return 0;
}
```

### sub | track

> 傀儡进程

#### Pre_check

这题居然让我电脑报毒了，让我康康！（康不懂，爬了

main函数很混乱，但仔细看能看出一点东西，貌似是创建一个进程，尝试把另一个文件读进来，然后开始执行？还看见一个熟悉的SMC

看了hint之后搜到了傀儡进程，一个最基本傀儡进程的实现如下

- CreateProcess创建进程，传入参数CREATE_SUSPENDED使进程挂起
- NtUnmapViewOfSection清空新进程的内存数据
- VirtualAllocEx申请新的内存
- WriteProcessMemory向内存写入payload
- SetThreadContext设置入口点
- ResumeThread唤醒进程，执行payload

#### Dump

emmm直接调的话，由于各种奇怪的反调试，好像没法成功，于是我打开了010editor，直接把傀儡进程在运行前全都异或回去，并dump出来单独分析

清晰的main函数

```c
int __cdecl main_0(int argc, const char **argv, const char **envp)
{
  size_t input_len; // eax
  char v5; // [esp+0h] [ebp-10Ch]
  char v6; // [esp+0h] [ebp-10Ch]
  char input[56]; // [esp+D0h] [ebp-3Ch] BYREF

  __CheckForDebuggerJustMyCode(&unk_40C015);
  memset(input, 0, 0x32u);
  printf("Please input your flag: ", v5);
  scanf("%s", (char)input);
  input_len = strlen(input);
  if ( (unsigned __int8)off_40A040(input, input_len) )
    printf("Congratulation~~~", v6);
  else
    printf("Try again~~~", v6);
  getchar();
  getchar();
  return 0;
}
```

把`off_40A040`一路往下点，就看到加密逻辑

```c
char __cdecl sub_4014F0(int a1, int a2)
{
  int i; // [esp+DCh] [ebp-8h]

  __CheckForDebuggerJustMyCode(&unk_40C015);
  if ( a2 != 32 )
    return 0;
  for ( i = 0; i < 32; ++i )
  {
    if ( (char)(((*(_BYTE *)(i + a1) ^ 0x66) + 4) ^ 0x55) != byte_40A020[i] )
      return 0;
  }
  return 1;
}
```

挺常规的，直接还原？

```python
magic_1 = [0x5A,0x46,0x59,0x46,0x7B,0x5C,0x43,0x51,0x74,0x63,0x47,0x0E,0x4C,0x68,0x0E,0x4C,0x68,0x43,0x47,0x03,0x68,0x51,0x5E,0x44,0x03,0x68,0x51,0x0E,0x5E,0x50,0x1E,0x4A]
flag = ''

for i in range(len(magic_1)):
    flag += chr(((magic_1[i] ^ 0x55) -4) ^ 0x66)

print(flag)
# miniLctf{Th1s_1s_th4_fak4_f1ag!}
```

我aklsjdaiwjdawijdaiwdjqw（

#### EXP

又是上一题一样的，在Exports里面有`TlsCallback_0_0`

里面有对于`off_40A040`的指向进行处理，然后就没啥问题了

```python
magic_1 = [0x5A,0x46,0x59,0x46,0x7B,0x5C,0x43,0x51,0x74,0x63,0x47,0x0E,0x4C,0x68,0x0E,0x4C,0x68,0x43,0x47,0x03,0x68,0x51,0x5E,0x44,0x03,0x68,0x51,0x0E,0x5E,0x50,0x1E,0x4A]
fake_flag = ''

for i in range(len(magic_1)):
    fake_flag += chr(((magic_1[i] ^ 0x55) -4) ^ 0x66)

print(fake_flag)

magic_2=[0x5A,0x26,0x59,0x26,0x7B,0x5C,0x43,0x51,0x54,0x6D,0x52,0x68,0x0E,0x4C,0x68,0x4C,0x0F,0x68,0x0E,0x59,0x43,0x03,0x4D,0x03,0x4C,0x43,0x0E,0x59,0x50,0x1E,0x1E,0x4A]
flag = ''

for i in range(len(magic_2)):
    flag += chr(((magic_2[i] ^ 0x66) - 4) ^ 0x55)

print(flag)
```

