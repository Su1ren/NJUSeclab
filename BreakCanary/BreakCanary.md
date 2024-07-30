这个实验的目标非常简单，就是修改 exploit 程序，实现对 canary 的暴力破解。
但是由于 Seclab 已经已无在线存档，链接无法实现，因此攻击无法进行。所以本次实验只是对服务器端的 canary 暴力破解的学习，主要是学习相关论文。
## StackGuard
这篇论文主要是介绍了 StackGuard 和 MemGuard 机制，讨论他们的实现原理和适用场景。
### StackGuard
StackGuard 机制主要是提出 canary，其原委是用以防御利用缓冲区溢出的莫里斯蠕虫。StackGuard 并不需要源码，是一种编译技术上的扩展。
由于 C 语言不带数组边界检查，因此是缓冲区溢出的主要受害者。
![stack.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1718615578949-2f02c03b-61bb-4745-96eb-45915c952585.png#averageHue=%23f0f0f0&clientId=u3c52d32c-df4b-4&from=ui&id=u31f47deb&originHeight=531&originWidth=705&originalType=binary&ratio=1&rotation=0&showTitle=false&size=32092&status=done&style=none&taskId=u6a029917-7a20-4979-91b6-0134912de4f&title=)
由于缓冲区的内容从下往上填充，缓冲区溢出就是通过向缓冲区填入 shellcode 和填充指令（一般是 NOP），覆盖函数返回地址来实现的。
如果程序的输入是从本地进程提供的，那么此类漏洞可能允许任何具有本地帐户的用户成为 root 用户；若用户输入来自网络上另一台主机，那么可以利用这个漏洞在目标主机上获取 root 权限。
基于此，文章提出了一种名为 canary 的机制，在栈上保存的返回地址下方添加一个随机数称为 canary。当函数序建立时，从 canary 数组中获取一个 canary 随机数；当函数结束后，将栈上的 canary 与原 canary 对比检查是否被修改，以此判断返回地址是否被修改。
![canary.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1718616193208-af6be20f-a32a-4ed6-9239-606e5785899e.png#averageHue=%23f0f0f0&clientId=u3c52d32c-df4b-4&from=ui&id=u32258e52&originHeight=477&originWidth=693&originalType=binary&ratio=1&rotation=0&showTitle=false&size=29833&status=done&style=none&taskId=ubc557e48-0170-499a-b564-61ce973f14c&title=)
虽然我们可以用野指针修改内存中的数据，但是由于缓冲区写入的顺序限制，在缓冲区溢出攻击中，可以认为 canary 完整则返回地址完整。
canary 机制也不是毫无破绽的，文中提出了两种破解机制：

1. 跳过 canary：如果攻击者可以利用结构体数组的对齐特性，在数组紧密排布时将 canary 嵌入到对齐的插空中去，导致 canary 实际上被跳过了。
2. 虽然 canary 是随机生成的，但是如果 canary 的值容易得到，那么这个检测也就形同虚设了。攻击者拿到了 canary 值，在修改返回地址同时将canary 放回去，绕过了检测。
### MemGuard
MemGuard 是一种单字内存保护机制，被保护的内存字段只能通过 MemGuard 机制提供的 API 修改。
MemGuard 将包含准不变量的内虚拟内存页标记为只读，通过 trap 来处理对保护页的写入操作，并模拟对非保护页的写入。对非保护页的模拟写入有很大的开销，但是对于内核地址空间这样的重要内容而言是可接受的。
但如果是频繁写入的靠近栈顶的内容，使用 MemGuard 的保护控制开销就太大了。
## Hacking Blind
服务器端的程序通常使用 fork 来针对服务启动子进程，子进程和父进程共用一个 canary 值。这样当我们通过在子进程中利用缓冲区溢出来覆盖 canary 时，若 canary 检查不匹配，则子进程会崩溃之后重启，但不会重新将地址空间随机化，canary 也不会改变。
这样我们不需要获得源码，就可以利用构造的输入，以及返回的结果来测试自己覆盖的 canary 是否正确实现 canary 暴力破解。根据每次猜测的规模可以分为 canary 整体穷举和逐字节破解。
### canary 穷举
这种方法下每次对 canary 进行整体穷举，在 32 位下 canary 为 4 Bytes，包含 3 Bytes 的随机数以及一个 0 字节。最坏情况下需要 224 次尝试，平均为 223 = 8388608 次尝试。对于本网段的攻击者而言，可以在数小时内完成破解。
### 逐字节破解
相比第一种方法，逐字节破解效率更高。攻击者每次只猜测 canary 的一个字节，也就是需要 256 次尝试。若尝试覆盖的 canary 未触发异常，则第一字节的信息可以通过输入得到。之后对后续的每一个随机字节进行如上操作，直到破解出所有字节。
这种方法破解 canary 十分高效，只需要最多 3 * 256 = 768 次尝试。因此 canary 的实现中会将 canary 中的一个字节设为 0 字节，来截断 strcpy 之类的字符串拷贝操作，使得栈上数据写入失效。
![bec63756948aad8dae9608b99aa31e17_3_Figure_5_-1217111630.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1722331860694-613e17c2-04be-4ad5-a37d-5a103bf33b14.png#averageHue=%23ececec&clientId=ub11e9e6b-9330-4&from=ui&id=u37547637&originHeight=354&originWidth=576&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=19615&status=done&style=none&taskId=u48447b54-7e63-4615-9bc3-8c0d0a3ee0e&title=)
## 参考文章

- [https://developer.aliyun.com/article/1463176](https://developer.aliyun.com/article/1463176)
- [https://blog.csdn.net/u010429831/article/details/118566925](https://blog.csdn.net/u010429831/article/details/118566925)
- COWAN C, PU C, MAIER D, et al. StackGuard: automatic adaptive detection and prevention of buffer-overflow attacks[J]. USENIX Security Symposium,USENIX Security Symposium, 1998.
- BITTAU A, BELAY A, MASHTIZADEH A, et al. Hacking Blind[C/OL]//2014 IEEE Symposium on Security and Privacy, San Jose, CA. 2014. [http://dx.doi.org/10.1109/sp.2014.22.](http://dx.doi.org/10.1109/sp.2014.22.) DOI:10.1109/sp.2014.22.
- MARCO-GISBERT H, RIPOLL I. Preventing Brute Force Attacks Against Stack Canary Protection on Networking Servers[C/OL]//2013 IEEE 12th International Symposium on Network Computing and Applications, Cambridge, MA, USA. 2013. [http://dx.doi.org/10.1109/nca.2013.12.](http://dx.doi.org/10.1109/nca.2013.12.) DOI:10.1109/nca.2013.12.
