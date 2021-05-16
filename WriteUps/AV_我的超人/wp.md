# miniLCTF

## misc

### 好康的硬盘

下载下来压缩包和一个文本文档

txt内容为

```
我看你是在进行一个peach的想




















‌‌‌‌‍﻿‌‌‌‌‌‌‍‬‌‍‌‌‌‌‍﻿‌﻿‌‌‌‌‍﻿‌﻿‌‌‌‌‍﻿‍﻿or‌‌‌‌‍‬﻿﻿‌‌‌‌‍﻿‌‬‌‌‌‌‍‬‍‌‌‌‌‌‌﻿‬‬‌‌‌‌‍‬﻿‍ ‌‌‌‌‍‬‬‍‌‌‌‌‍‬﻿‬‌‌‌‌‍‬‬‍you‌‌‌‌‍‬﻿‌ are‌‌‌‌‌‬‬‬‌‌‌‌‌‬‬‬‌‌‌‌‌‬‬‬‌‌‌‌‌‬‬‬ not?
```

可以明显看出其中的0位宽字符隐写，找到解密网站[Unicode Steganography with Zero-Width Characters (330k.github.io)](http://330k.github.io/misc_tools/unicode_steganography.html)解出其中隐藏内容为

```
minil****
```

这应该是个提示，先用四位数字试着爆破一下，因为太菜，所以只能自己写脚本进行爆破

```python
from unrar import rarfile#导入rarfile库

path1 = "E:\\ctf\\miniL\\misc\\好康的硬盘\\luoqian.rar"#需要解压的文件路径及地址
path2 = "E:\\ctf\\miniL\\misc\\好康的硬盘"#需要解压到的文件夹地址

rf = rarfile.RarFile(path1)  # pwd为解压密码
for i in range(999,10000):
    s=f'minil{i}'
    print(f'正在进行第{i-998}次尝试')
    try:
        rf.extractall(path = path2, pwd = s)  
    except RuntimeError:
         pass
    else:
         print("++++++++++++++++++++++++++++++++++++++++++")
         print(s)
         break
    
print('结束了')
```

也学习了一下如何用python解压rar压缩包

解压出来密码为minil4396 ~~（厂长感觉有被冒犯到）~~

提取其中的镜像文件，丢入DiskGenius中进行恢复，找到一个 ~~好康的~~ MP4文件和一个奇怪的邮件，看一遍视频，发现其中隐藏了几个图片，丢到Free Video to JPG Converter软件中分离出图片，发现一串数字7355608 ~~（好家伙，直接装c4）~~ 。暂时不知道有啥用，接着看邮件，似乎是垃圾邮件，百度一下得知这是一种加密，我们找到的数字应该就是加密的password，解密，得到flag：`MiniLCTF{n3ver_g0nna_L3t_Y0u_dowN}`

### 抓猫猫

其实这个题。。。。做的时候是试出来的，今天经过贴贴讲解，得知这是一个有关博弈论的数学问题，既然遇到了，就学习一下

#### k倍博弈

两个人取一堆n的石子，先手不能全部取完，之后每人取的个数不能超过另一个人上轮取的K倍。

当k=1时，必败态都是2^i,我们可以借助二进制的思想来理解，将n表示为2进制，先手拿掉最后一个1，后手肯定没法去掉更高位的1，所以后手取完，先手至少还能拿掉最后一个1，所以先手必胜。当n=2^i时，先手必败，因为此时n的二进制只有一个1，先手第一次不能取完，所以先手取了以后，后手一定能取到最后一个1，然后先手不能去掉更高位的1，所以先手必败。

假设`n=6(110)`，我们先去掉最后一个1，变为4（100），此时如果对手取两个，那么我们直接去两个就能取完，如果对手取一个，还剩3个，我们能取到最后一个。

当k=2时，这就是一个Fibonacci博弈，可知先手必胜当且仅当n不为Fibonacci数，还是利用，先手取掉最后一个1，后手无法去掉更高位的1，所以后手取完，先手至少还能拿掉最后一个1。Fibonacci数列有一个很好的性质就是，任何一个整数都可以表示为若干项不连续的Fibonacci数，所以我们先去掉最后一个1，即一个数x，后手肯定无法去掉更高的数2x，小于高两位的1，所以后手无法取完。

假设`n=11=7+3+1`，表示为10101，我们先手去掉最后一个1，后手无法去掉高两位的1，所以后手取完，我们至少还能去掉最后一个1。

当k的时候，想办法构造数列，使得数列的任意两项之间的倍数大于k。

就像Fibonacci博弈一样，我们还是想要构造一个想Fibonacci一样的数列，我们用a数组，表示要构造的数列，`b[i]`表示`a[1..i]`所能组成的最大数，为了方便理解，我们还是用Fibonacci数列举例子，显然`a[ ]={1,2,3,5,8...}`,`b[3]=4`,因为5本身就是Fibonacci数，而`6=1+2+3`，相邻两项的倍数根本就不大于`2`，`6=1+5`，`b[4]=6`。所以b数组中的数时我们要构造的数列中的一些满足要求的数的和，`a[i]=b[i-1]+1`,为什么呢，因为`a[i]`中的数是不可构造的，因为取到它就是必败。而`b[i-1]`是`a[1..i-1]`所能构造的最大数，那么加1，就是无法被前面的数列构造出来，所以只能另外开一项。

关于`b[i]`的构造，由于`b[i]`是`a[1..i]`中的数构造出来的，所以我们一定会用到`a[i]`,不然就成了`b[i-1]`了，所以我们先要按递减顺序找到`a[t]*k<a[i]`,那么`b[i]=b[t]+a[i]`,如果前面找不到那么`b[i]=a[i]`,为什么呢，因为前面的数没有k项或者说构造出来太小了，所以只能选取一个，那么肯定选取最大的哪一个，前面`a[1...i-1]`所构造的项`b[i-1]`小于`a[i]`,所以这种情况下`b[i]=a[i]`。所以我们先手能不能必胜就看n在不在这个`a[ ]`数组里面，给出模板

```c
#include<cstdio>
using namespace std;
const int maxn=1000000+7;
int a[maxn];   //构造的数列
int b[maxn];    //b[i]为a[1..i]所能凑出的最大数
int main()
{
  int n,k;
  while(scanf("%d %d",&n,&k)==2){
    int i=0,j=0;
    a[0]=b[0]=1;
    while(a[i]<n){
      i++;
      a[i]=b[i-1]+1;    //a[i]为a[1..i-1]所能构造出的最大的那个数+1
      while(a[j+1]*k<a[i]) j++;  //寻找临界点
      if(a[j]*k<a[i])  b[i]=b[j]+a[i];   //a[1..j]所能构造出来的最大值加上a[i]
      else b[i]=a[i];   //相邻  小于了K倍 自然构造的最大的数就是a[i]了
    }
    if(a[i]==n)  printf("Lost\n");   //如果数列a中有n则先手必败
    else printf("Win\n");
  }
  return 0;
}
```

### 好白给的签到题

emmmmm，确实挺白给，但是我太菜，所以一路手撕下去，经过无数base64和反向base64后，最后得到flag

```python
import base64
p=open('story.txt')
c=p.read().strip()
s=c
'''
while 1:
    try:
        s=base64.b64decode(s)
        print(s)
    except:
        try:
            s=base64.b64decode(s[::-1])
            print(s)
        except:
            break
'''
z='9smRjNnSWF2b4dkV6BHbStGdrJVcaZUVxM3VZhlWFJlaO52UHZkMURDZrZFNwFTYXhGbSRHZxM2caVlW5plRidFaX5kcK1WVzhnMVpnWsJFbw1mVyRGbNNEarlFVWpXYThWRjhXSWl1Rwh1VyI0MhxmWGF2ckx2YHRGMWNDayEGWoV0YyFzaWtmWVpFMwZkYsR3aWdXVsZ1QotWWYJ1VSpGZrdFeRZVW0QGbWdXUE10UsdUYHBHbSdEZWpVYatWYXpFShpXWsZVNjBTW6BnRiVlQU1EWaxWTahXbVNHcxEGWaZ0YHZ0VZdkUWdlW41WZohmRhlFZGVmVGpXWop1ahdlWEFGWK1GVzRGMZBjUHJ2U0VVTYJVMSdnRUlFWoJTYSxGbTlXWxQVMjZlVhBHbWlGasRlcWxmVzplVaNDaYJ2V5s2VWpkMW9UNtZFNxsWTUJlaTFnWWd1SGpWVwplRiJlVGp1RW1mUrpVMWlkWFZVakZkY1RWMjdkSqZFSSJTYYxGSjJnSGdFM01WVWh3VN5EdrdlVSZ0VTR2aZdFaXZ1TaVkWHZVbhFGetZFNGxWZo5kRhNnUWN1VkVkWYBnVSFGeFN2VxAjVHRWVZpFcwIFWSREZ0plRNdHetZVYShlYTZkbXdVMwY1U41mVZpFblhGaGplcOZ0U4NnMWhGcsJ1VKRUZ0ZlMVtGeHZlS1UlYT5kVNRnWG1kUKRVWZhXbSpmWsNVeVFjUrZlVXpkQIJ2U0d1T0JFbONnWwYFV1sWYXJkRjhXRHd1a0JTV1Y1aNhmUU1Edax2U3ZlVU9kVUJVYkZVTGRmRlJkUGZVTChkYXZFbSRnVGN1aaxmVyh2MWdlVEJ2caZUYDJ1aXpnSsZlWk52VyxmRXdHdtVFaCh0VW5kbWdkVtVVYWxmV'
s=base64.b64decode(z[::-1])
'''
while 1:
    s=base64.b64decode(s)
    print(s)
'''
z='==QOwQVVY5kbWdVMwY1Rw1mV3tGVWdlVE5kVsxmThZFbWdlUtJlToh1V4lVMUNnWWZVeKZlYYRmRllXSyQmW4dVWDpkRWFGZV5kVaZkV4NWVZRlRUZ1Vkh0YyplVjFTQ6lFcohlYYRWVNZEZxQ1S4d1VaBXVWhFZW1ESSdUYLplVURlWsZ1VKhlTWZ0VhtmQEpleB5mVXB3RhVnWsVFeRZUV'
s=base64.b64decode(z[::-1])
'''
while 1:
    s=base64.b64decode(s)
    print(s)
'''
z='mNVRoN2MSBnTqpFaVxWO1I2aCRHWygTMlBjWVFFM4BnYtxmT'
s=base64.b64decode(z[::-1])
while 1:
    s=base64.b64decode(s[::-1])
    print(s[::-1])
##MiniLCTF{5o_m@ny_Ra66its!!}
```

## web

### web1 minil-java



下载文件可以看到java代码![image-20210512210742887.png](https://i.loli.net/2021/05/12/mArguityZX6VkqS.png)



首先看到路由是设置在根目录下，然后可以看到一个if语句条件是一个equals方法的匹配，当我们在url中键入\\\\时会绕过这个if语句，进入else部分。对题目进行一番查找，发现里面有spel漏洞，但是应该这道题时java的代码执行![image-20210512212657841.png](https://i.loli.net/2021/05/12/eC91nak74DNoixg.png)



通过第一步会看到这个so页面，下面考虑如何构造java代码进行读取/flag，java的io流可以进行文件读取



?code=(new java.util.Scanner(new+java.io.File('/flag'))).next()//利用next()方法进行读取，就可以看到flag



![image-20210512213544072.png](https://i.loli.net/2021/05/12/uaKZEfxSloTj8X1.png)



不会Java，还是想了好久 orz



### web2 L-INC





首先![image-20210512213836087.png](https://i.loli.net/2021/05/12/qQOlBsjKTILMHXJ.png)



![image-20210512213850043.png](https://i.loli.net/2021/05/12/VtDfrBsX9Zamg5z.png)



然后点一下become vip会发现让我们自己找办法成为VIP。我们抓包，发现里面有一串base64代码，放到解码网站进行解码，发现出现user name ub等关键字，猜想可能是python的字节码，所以我们把这一串base64放入python脚本进行解码（python序列化）![image-20210512214327107.png](https://i.loli.net/2021/05/12/OhEVN4eWrkSTfuj.png)



发现\x89，对所有的字节码进行处理找到对应的操作，更改为\x88，然后再进行base64编码，更改cookie，从repeater进行发包，就可以看到成功给你了vip，并且存在ssti漏洞，name变成了56。所以为我们开始进行ssti，发现它什么也没过滤![2-1620827122510.png](https://i.loli.net/2021/05/12/TH87lopYZfLd1eR.png)



应该在根目录下有一个flag文件



构造如下payload



\```

{{''.__class__.__base__.__subclasses__()[132].__init__.__globals__['popen']('cat /flag*').read()}}

\```



![1-1620826592194.png](https://i.loli.net/2021/05/12/oVKXkRZglh5eCAE.png)



## reverse

### 0oooops

emmmmm，做出来了，但没完全做出来，感觉也算是猜着做的，没弄清这题的原理是什么，找到两个，加密函数，第一部分

```c
if ( **(_DWORD **)a1 != -1073741819 )
    return 0;
  v4 = *(_DWORD *)(*(_DWORD *)(a1 + 4) + 164) + 9;
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
      *(_DWORD *)(*(_DWORD *)(a1 + 4) + 184) += 66;
      return -1;
    }
  }
  *(_DWORD *)(*(_DWORD *)(a1 + 4) + 184) += 7;
  return -1;
}
```

解密

```python
v3=[0]*31
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
for i in range(0x1f):
    print(chr(((v3[i]^0x42)-4)^0x37),end='')
```

第二部分加密

```c
if ( **(_DWORD **)a2 != -1073741676 )
    return 0;
  v5 = *(_DWORD *)(*(_DWORD *)(a2 + 4) + 164) + 9;
  qmemcpy(v4, "!V -}VG-bp}m-nG!b|ra GyGE|Drp D", 31);
  for ( i = 0; i < 0x1F; ++i )
  {
    if ( v4[i] != ((unsigned __int8)*(_DWORD *)(*(_DWORD *)(a2 + 4) + 184) ^ ((*(char *)(v5 + 2 * i + 1) ^ 0x4D) - 4) ^ 0x13) )
    {
      *(_DWORD *)(*(_DWORD *)(a2 + 4) + 184) += 54;
      return -1;
    }
  }
  *(_DWORD *)(*(_DWORD *)(a2 + 4) + 184) += 63;
  return -1;
}
```

因为不知道其中的一个值，所以选择了爆破

```python
c='!V -}VG-bp}m-nG!b|ra GyGE|Drp D'
for i in range(128):
    for j in range(0x1f):
        print(chr(((((ord(c[j])^i)^0x13)+4)^0x4d)),end='')
    print(i)
```

最后在合在一起

```python
a1='yuarayudrtn_h_1dw_x4tO_ad1_4hns'
a2='0_14d_n4sadt4wn0secp1nhnlemca1m'
for i in range(31):
    print(a1[i]+a2[i],end='')
```

得到flag

```
y0u_a1r4ady_und4rstand_th4_w1nd0ws_exc4pt1On_handl1e_m4chan1sm
```

