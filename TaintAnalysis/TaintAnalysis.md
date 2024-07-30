在导师推荐之下，我打算从这个染色实验开始，学习一些软件分析的知识，在实验室之后会用到。
本实验介绍如何使用 Intel PIN 对程序进行染色分析，实验对象是一段存在缓冲区溢出漏洞的 C 语言代码，使用 Intel PIN 跟踪漏洞程序的输入流向，以检测两次缓冲区溢出。
首先我们要清楚，PIN 是一种编译器。但是不同于传统的编译器，PIN 的输入是可执行文件。PIN 根据我们的要求对可执行文件进行编译，产生新的可执行文件。
## 环境部署
我们首先需要在 Intel 下载相关组件。
`wget [https://software.intel.com/sites/landingpage/pintool/downloads/pin-external-3.31-98861-g71afcc22f-gcc-linux.tar.gz](https://software.intel.com/sites/landingpage/pintool/downloads/pin-external-3.31-98861-g71afcc22f-gcc-linux.tar.gz)`
之后解压即可使用。
`tar -xf pin-external-3.31-98861-g71afcc22f-gcc-linux.tar.gz`
Intel PIN 提供了不少样例代码，我们可以选一例来学习怎么使用。样例 PIN 代码在 source/tools 中，可以通过讲解使用。
样例在 `source/tools/ManualExamples` 路径下，我们将其路径下所有程序编译为 32 位程序：
`make all TARGET=ia32`
这条指令会在当前目录下生成 obj-ia32 路径。
也可以将单独代码的编译：
`make obj-intel64/inscount0.so TARGET=ia32`
这条指令会在当前目录下生成 obj-intel64 路径。
之后可以运行 PIN tools，指令格式为：
`<Pin executable> <Pin options> -t <Pintool> <Other Pintool argvs> -- <Test application> <Test application argvs>`
我们拿 /bin/ls 来示例（默认当前路径仍然在 ManualExamples）：
`$ ../../../pin -t obj-intel64/inscount0.so -- /bin/ls`
这条在 PIN 提供的插桩指令下运行目标程序 /bin/ls，通过 inscount0.so 实现指令计数。
但是这生成的文件 inscout0.so 比较难分析，我们修改一下指令，生成一个日志文件：
 `$ ../../../pin -t obj-intel64/inscount0.so -o inscount0.log -- /bin/ls`
![image.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1721117450986-fc151dac-2169-4bb5-802c-3d11f525471b.png#averageHue=%234b7f68&clientId=ue0068ec8-5df2-4&from=paste&height=38&id=u46a65c3e&originHeight=57&originWidth=1172&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=55197&status=done&style=none&taskId=u3b60c434-ba0e-4834-82d3-53dfb8d3a6d&title=&width=781.3333333333334)
可以发现执行了 706053 条指令。
## 实验内容
本次实验的内容是通过染色分析实现缓冲区溢出检测。
下面给出代码：
```c
#include<stdio.h>
#include<string.h>
struct MyType{
	char input[10];
	int offset;
	int BUFF[100];
};
char * readstr(char *str){
	char c;
	int i=0;
	while((c=getchar()) !='\n'){
		str[i]=c;
		i++;
	}
	str[i]='\0';
	return str;
}

struct MyType Data;
int vulfun1(){
	Data.offset = 10;
	readstr(Data.input);
	*(Data.BUFF + Data.offset) = Data.input[0]+Data.input[1]+Data.input[3]+Data.input[4];
	return 0;
}
int vulfun2(){
	char buff[10];
	readstr(buff);
	return 0;
}
int main(){
	vulfun1();
	vulfun2();
	return 0;
}
```
可以看出，代码中的函数 vulfun1 和 vulfun2 各存在一个缓冲区溢出漏洞：

- vulfun1 中，readstr 没有对输入长度做检测，因此可能将 Data 的 offset 字段修改。进而在下一条指令中修改 Data 的 BUFF 字段，实现程序数据流劫持。
- vulfun2 中，同样的原因产生了一个非常经典的缓冲区溢出，可以用来篡改函数的返回地址，事项程序的控制流劫持。

该程序会接受两次输入，用于触发漏洞。分别输入 `012345678912a` 和 `012345678901234567` 尝试触发两个漏洞。
## 实验要求
本次实验的目标是编写 PIN Tools 来实现染色分析，跟踪上述漏洞程序的输入流向，以检测两次缓冲区溢出。需要解决以下问题：

- 利用 PIN 提供的 API 函数截取程序的输入；
- 利用 PIN 实现对数据流传播的跟踪；
- 在指针解引用时确定指针是否被输入防污染；
- 在程序返回时确定返回地址是否被篡改。

下面我们一一解决。
## 实验过程
### 了解 Pintools
现在我们明确了任务，通过一个 pintools 的执行观察到了其效果。但是还不知道 PINtools 到底要怎么编写，我们以上述的 inscount.cpp 源码文件来分析其结构。
```c
/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

#include <iostream>
#include <fstream>
#include "pin.H"
using std::cerr;
using std::endl;
using std::ios;
using std::ofstream;
using std::string;

ofstream OutFile;

// 执行的指令数保存于此
// 设为全局静态变量，便于编译器优化 docount 函数
static UINT64 icount = 0;

// 每当一条指令执行后，该函数都会被调用
VOID docount() { icount++; }

// 每当遇到一条新指令，该函数都会被 PIN 调用
VOID Instruction(INS ins, VOID* v)
{
    // 插入对 docount 的调用到每条指令执行之前，不传入任何参数
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_END);
}

KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "inscount.out", "specify output file name");

// 程序退出时调用此函数
VOID Fini(INT32 code, VOID* v)
{
    // Write to a file since cout and cerr maybe closed by the application
    OutFile.setf(ios::showbase);
    OutFile << "Count " << icount << endl;
    OutFile.close();
}

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool counts the number of dynamic instructions executed" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */
/*   argc, argv are the entire command line: pin -t <toolname> -- ...    */
/* ===================================================================== */

int main(int argc, char* argv[])
{
    // PIN 的初始化
    if (PIN_Init(argc, argv)) return Usage();

    OutFile.open(KnobOutputFile.Value().c_str());

    // 注册指令粒度的回调函数，名为 Instruction
    INS_AddInstrumentFunction(Instruction, 0);

    // 注册完成函数程序退出后调用
    PIN_AddFiniFunction(Fini, 0);

    // 启动 PIN 程序，不会返回
    PIN_StartProgram();

    return 0;
}
```
该 Pintools 执行流程如下：

- 在主函数 main 中：
- 初始化 PIN_Init，注册指令粒度的回调函数 `INS_AddInstrumentFunction()`。以上程序中被注册的插桩函数名为 Instruction；
- 注册完成函数 PIN_AddFiniFunction，常用于最后输出分析结果；
- 启动 PIN 执行 PIN_StartProgram；
- 在每条指令执行之前（IPOINT_BEFORE）执行分析函数 docount，功能是对全局变量递增计数；
- 执行完成函数 Fini，输出计数结果到文件。
### main 函数编写规范
Pintool 的入口是 main 函数，通常需要承担下面工作：

- 初始化 PIN 系统环境：
`BOOL LEVEL_PINCLIENT::PIN_Init(INT32 argc, CHAR** argv)`；
- 初始化符号表：当需要调用程序符号信息时需要这一步，通常是指令粒度以上。
`VOID LEVEL_PINCLIENT::PIN_InitSymbols()`；
- 初始化同步变量；
- 注册不同粒度回调函数：TRACE（轨迹粒度，单入口多出口的指令序列）、IMG（镜像粒度，整个被加载到内存的二进制可执行模块）、RTN（例程粒度，有面向过程程序语言编译器产生的函数/例程/进程）、INS（指令粒度，代表一条指令，是最小的粒度，会降低程序执行效率）
- 注册结束回调函数：当插桩程序运行结束后，可以调用结束函数来释放不再使用的资源，然后输出分析结果。
`VOID PIN_AddFiniFunction(FINI_CALLBACK fun, VOID *val)`；
- 最后启动 PIN 虚拟机进行插桩，启动程序开始运行：
`VOID PIN_StartProgram()`。

### 插桩、分析函数编写
在 main 函数中注册插桩和回调函数之后，PIN 虚拟机将在运行过程中对该种粒度的插桩对象选择性地进行插桩。各种粒度的插桩函数如下：

- INS：`VOID LEVEL_PINCLIENT::INS_InsertCall(INS ins, IPOINT action, AFUNPTR funptr, ...)`
- RTN：`VOID LEVEL_PINCLIENT::RTN_InsertCall(RTN rtn, IPOINT action, AFUNPTR funptr, ...)`
- TRACE：`VOID LEVEL_PINCLIENT::TRACE_InsertCall(TRACE trace, IPOINT action, AFUNPTR funptr, ...)`
- BBL：Basic Block，单入口单出口的指令序列。`VOID LEVEL_PINCLIENT::BBL_InsertCall(BBL bbl, IPOINT action, AFUNPTR funptr, ...)`

其中 funptr 为用户定义的分析函数，函数参数与变长参数 `...` 参数列表传入的参数个数相同，参数列表以 `IARG_END` 标记结束。
### 定位程序输入
我们要知道用户输入的位置，必然需要知道程序是如何读取用户输入的。本程序中，使用的输入函数为 getchar，而 getchar 的实现是预先分配一块缓冲区，然后用户输入数据保存在其中。之后再逐字符读取缓冲区的内容作为 getchar 的输出，根据 gdb 调试结果从汇编也可以看出这一点。
![image.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1721208246541-e8fcfab5-b995-4691-83e9-e259ed057307.png#averageHue=%23797c86&clientId=u6ed9102d-f1e7-4&from=paste&height=233&id=u1eb3a7b3&originHeight=350&originWidth=791&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=209749&status=done&style=none&taskId=u0d2d549d-cdf0-42df-9a9d-da7e0bf824f&title=&width=527.3333333333334)
既然如此，那么我们大概可以判断，在读取用户输入时会触发 SYS_read 系统调用，除了描述符之外，还有两个参数：起始地址和数据块大小。因此我们可以通过检测系统调用的方式获知用户输入的地址。
编写 pintools 如下：
```cpp
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <syscall.h>
#include <cstdint>
#include "pin.H"
using namespace std;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "read_calls.out", "specify output file name");

ofstream outFile;
vector<UINT64> addressTainted;

VOID SyscallEntry(THREADID threadIndex, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v) {
	UINT64 start,size;
	
    if (PIN_GetSyscallNumber(ctx, std) == SYS_read) {
    	// TRICKS();
    	start = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 1)));
    	size = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 2)));
        outFile << "[TAINT]\t\tbytes tainted from " << std::hex << "0x" << start << " to 0x" << start + size << endl;
    }
}

VOID Fini(INT32 code, VOID *v) {
    outFile.close();
}

int main(int argc, char *argv[]) {
    PIN_Init(argc, argv);
    PIN_InitSymbols();
    outFile.open(KnobOutputFile.Value().c_str());
    PIN_AddSyscallEntryFunction(SyscallEntry, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}
```
运行结果如下：
`[TAINT]		bytes tainted from 0x7fffffffcf68 to 0x7fffffffd2a8`
`[TAINT]		bytes tainted from 0x5555555592a0 to 0x5555555596a0`
`[TAINT]		bytes tainted from 0x5555555592a0 to 0x5555555596a0`
记录三条，第一条，应该是读取了栈上数据，但是函数体并没有栈上的数据读取，暂时还不知道含义。
第二条和第三条是同一地址，而且大小也相同，可以计算为 0x400 = 1024 Bytes，应该就是一块输入缓冲区。可能我们的输入内容正是被保存到了 0x5555555592a0 起始的内存空间，应该是在堆区的一块内存。
我们可以通过 gdb 来验证一下，第一次输入之后：
![image.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1721207707129-e4363292-3fb8-4903-a12b-cc40d19fe0e1.png#averageHue=%23787982&clientId=u6ed9102d-f1e7-4&from=paste&height=56&id=u4a578c04&originHeight=84&originWidth=526&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=24727&status=done&style=none&taskId=u7896c10c-a9b3-47d0-8718-72a3b78d8f1&title=&width=350.6666666666667)
可以发现输入内容确实被保存在 0x5555555592a0，查看页面映射，确实是在堆中。
![image.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1721208094052-93e59021-37eb-4f7d-9904-38f0401b01e8.png#averageHue=%23737584&clientId=u6ed9102d-f1e7-4&from=paste&height=24&id=ucff005b3&originHeight=36&originWidth=867&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=23536&status=done&style=none&taskId=uce6d05a4-636e-4eab-859e-8a30df950e9&title=&width=578)
第二次输入的结果，发现竟然是在同一地址。
![image.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1721208323149-50983d6e-2255-40eb-8253-7f18a2114c2d.png#averageHue=%23747681&clientId=u6ed9102d-f1e7-4&from=paste&height=93&id=u8ec9dc92&originHeight=139&originWidth=559&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=64002&status=done&style=none&taskId=ud158bc69-9a0b-4f58-893f-ec3aeefbda6&title=&width=372.6666666666667)
可以看出确实如此：
![image.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1721208350033-bca386ad-3588-40d8-88a0-1dd0e40a824e.png#averageHue=%23787b86&clientId=u6ed9102d-f1e7-4&from=paste&height=69&id=ue1cdc32d&originHeight=103&originWidth=889&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=75083&status=done&style=none&taskId=u2d90b567-3c67-4866-bede-6cbd614eefa&title=&width=592.6666666666666)
那么我们可以确定了，我们的输入一开始被保存在堆的缓冲区中，地址为 0x5555555592a0。
也可以使用 PIN_SafeCopy 将这段地址内容拷贝到缓冲区打印出来：
```cpp
VOID SyscallEntry(THREADID threadIndex, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v) {
	unsigned int i;
	UINT64 start,size;
    if (PIN_GetSyscallNumber(ctx, std) == __NR_read) {
    	// TRICKS();
    	start = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 1)));
    	size = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 2)));
    	char buffer[size + 1];
    	
    	for(i = 0;i < size;++i) {
    		addressTainted.push_back(start + i);
    	}
        outFile << "[TAINT]\t\tbytes tainted from " << std::hex << "0x" << start << " to 0x" << start + size << endl;
        PIN_SafeCopy(buffer, reinterpret_cast<const void*>(start), size);
        buffer[size] = '\0';
        string str(buffer);
        outFile << "Read 0x" << size << " bytes:  " << str << endl;
    }
}
```
### 数据传播跟踪
为了方便实验进行，我们将 ASLR 关闭。编译为 32 位程序，关闭 PIE，Canary，设定为静态编译，我这里显示有点问题。
![image.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1721288717522-157f43b7-620e-4bd9-9729-7e7e0fb6f0bd.png#averageHue=%237a7b83&clientId=u93446297-7520-4&from=paste&height=115&id=mhoVZ&originHeight=172&originWidth=448&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=46563&status=done&style=none&taskId=u01c0b6dc-1ce6-4738-a63d-8e34139939b&title=&width=298.6666666666667)
之后，我们再继续实验。
定位了程序输入，接下来我们要确定带有污点的数据是如何在内存中传播的。如果没有后续的内存存取，那么被污染的数据永远只会留在原地。所以我们不难想到，需要跟踪被染色的内存区域的内存存取操作。为此我们需要添加一个函数，检测到对染色地区的访问都会被记录下来。
首先是读取读取操作的记录，内存存取需要使用寄存器，污点数据的传播也离不开寄存器。所以寄存器的信息我们也需要记录。若从污点区域读取数据，那么寄存器就会被污染。
```cpp
/*
    addressTainted：保存的被染色的内存地址动态数组
    insAddr：指令地址
    insDis：指令反汇编
    operandCount：指令操作数
    reg_r：寄存器
    memOp：操作内存地址
    sp：sink point 污点数据传播点
*/
VOID ReadMem(UINT32 insAddr, std::string insDis, UINT32 OperandCount, REG reg_r, UINT32 memOp, UINT32 sp) {
	vector<UINT32>::iterator i;
	UINT32 addr = memOp; // 内存操作目标地址
	if(OperandCount != 2) { // 操作数不为 2，说明并不是我们考虑追踪的指令
		return ;
	}
	for(i = addressTainted.begin();i != addressTainted.end();++i) {
		if(addr == *i) { // 属于被污染的地址
			if(insAddr <= 0x80b8000) // 由于静态编译，指令在代码段中
				std::cout << std::hex << insAddr << ":\t[READ in " << addr << "][T]" << " insDis: " << insDis << sp << std::endl;
			taintReg(reg_r); // 将寄存器标记为染色
			return ;
		}
	}
	/* 若内存读取不在染色区域内，而且寄存器处于被染色状态，则指令执行后寄存器会被赋新值，解除染色 */
	if(checkIfRegTainted(reg_r)) {
		if(ins <= 0x80b8000) 
			std::cout << std::hex << insAddr << ":\t[READ in " << addr << "][F]" << " insDis: " << insDis << sp << std::endl;
		removeRegTainted(reg_r); // 移除染色状态
	}
}
```
然后是内存写入操作，若污点数据区被写入了无污点数据，那么被写的一块内存就要去掉污点，不再被用户控制了。这里要注意，区分一次写入的字节数。
```cpp
VOID WriteMem(UINT32 insAddr, std::string insDis, UINT32 OperandCount, REG reg_r, REG reg_0, UINT32 memOp, UINT32 sp) {
	vector<UINT32>::iterator i;
	UINT32 addr = memOp;
	UINT32 length = 0; // 写入字节长度
	if(OperandCount != 2)
		return ;
	if(!REG_valid(reg_r)) { // 若 reg_r 无效
		if(REG_valid(reg_0)) { // reg_0 有效
			reg_r = reg_0; // 则寄存器信息迁转
		} else { // 否则根据反汇编判断
            /* 例如 mov dword ptr [eax * 4 + 0x804a080], 0xa */
			if(insDis.find("dword ptr", 0) != string::npos) {
				length = 4;
			} else if(insDis.find("word ptr", 0) != string::npos) {
				length = 2;
			} else {
				length = 1;
			}
		}
	} // reg_r 有效
	for(i = address.begin();i != address.end();++i) {
		if(addr == *i) { // 目标地址已被染色
			if(insAddr <= 0x80b8000)
				std::cout << std::hex << insAddr << ":\t[WRITE in " << addr << "][F]" << " insDis:" << insDis << sp << std::endl;
			std::cout << std::hex << reg_r << std::endl;
			if(!REG_valid(reg_r) || !checkIfRegTainted(reg_r)) { // 寄存器还未被染色
				if(REG_is_Lower8(reg_r) || REG_is_Upper8(reg_r)) { // 判断寄存器大小确定写入字节数
					length = 1;
				} else if(REG_is_Half16(reg_r)) {
					length = 2;
				} else if(REG_is_Half32(reg_r)) {
					length = 4;
				}
				removeMemTainted(addr, length); // 寄存器内容未被染色，则赋值后，被染色的区域还原
			}
		}
	}
}
```
总结起来，污点通过寄存器的传播可以表示为：
```cpp
/*
    寄存器之间的污染数据传播
    reg_r：存储数据源的寄存器，相当于 mov 在 Intel 语法下的第二操作数
    reg_w：被写入数据的寄存器，相当于 mov 在 Intel 语法下的第一操作数
    reg_r 默认是有效的，不然寄存器数据传递没法进行。
*/
VOID spreadRegTaint(UINT32 insAddr, std::string insDis, UINT32 OperandCount, REG reg_r, REG reg_w) {
	if(REG_valid(reg_w) {
		if(checkIfRegTainted(reg_w) && (!REG_valid(reg_r) || !checkIfRegTainted(reg_r))) {
			if(insAddr <= 0x80b8000) 
				std::cout << std::hex << insAddr << ":\t[SPREAD][F]" << " insDis:" << insDis << std::endl;
			removeRegTainted(reg_w); // 被写的寄存器已污染，源寄存器未污染或无效，则不再是污染状态
		} else if(!checkIfRegTainted(reg_w) && checkIfRegTainted(reg_r)) {
			if(insAddr <= 0x80b8000) 
				std::cout << std::hex << insAddr << ":\t[SPREAD][F]" << " insDis:" << insDis << std::endl;
			taintReg(reg_w); // 若被写入寄存器未被污染，但源寄存器已被污染，则写入的寄存器也被污染
		}
	}
}
```
最后我们将这些函数都注册为指令级语句。
```cpp
VOID Instruction(INS ins, VOID* v) {
	std::cout << std::hex << INS_Address(ins) << ":\t" << INS_Disassemble(ins) << std::endl;
	if(INS_OperandCount(ins) <= 1)
		return ;
	if(INS_MemoryoperandIsRead(ins, 0)) {
		INS_InsertCall(
			ins, IPOINT_BEFORE, (AFUNPTR)ReadMem,
			IARG_ADDRINT, INS_Address(ins),
			IARG_PTR, new string(INS_Disassemble(ins)),
			IARG_UINT32, INS_OperandCount(ins),
			IARG_UINT32, INS_OperandReg(ins, 0),
			IARG_MEMORYOP_EA, 0,
			IARG_REG_VALUE, REG_STACK_PTR,
			IARG_END);
	} else if(INS_MemoryOperandIsWritten(ins, 0)) {
		INS_InsertCall(
			ins, IPOINT_BEFORE, (AFUNPTR)WriteMem,
			IARG_ADDRINT, INS_Address(ins),
			IARG_PTR, new string(INS_Disassemble(ins)),
			IARG_UINT32, INS_OperandCount(ins),
			IARG_UINT32, INS_OperandReg(ins, 1),
			IARG_UINT32, INS_OperandReg(ins, 0),
			IARG_MEMORYOP_EA, 0,
			IARG_REG_VALUE, REG_STACK_PTR,
			IARG_END);
	} else if(INS_OperandIsReg(ins, 0)) {
		INS_InsertCall(
			ins, IPOINT_BEFORE, (AFUNPTR)spreadRegTaint,
			IARG_ADDRINT, INS_Address(ins),
			IARG_PTR, new string(INS_Disassemble(ins)),
			IARG_UINT32, INS_OperandCount(ins),
			IARG_UINT32, INS_RegR(ins, 0),
			IARG_UINT32, INS_RegW(ins, 0),
			IARG_END);
	}
}
```
整体的代码如下：
```cpp
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <syscall.h>
#include <vector>
#include "pin.H"
#include<string>
#define D(x) x
using namespace std;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "read_calls.out", "specify output file name");

ofstream outFile;
vector<UINT32> addressTainted;

class ShadowReg{
private:
    bool shadow_reg_[287] = {false};
public:

    bool checkReg(REG reg);
    bool taintReg(REG reg);
    bool removeReg(REG reg);
};
ShadowReg* shadow_reg;
string GetREGName(REG reg);

string GetREGName(REG reg) {
  string reg_name; 
	reg_name="UNKnowReg:"+reg; 
	switch(reg){

    //case REG_RAX:  regsTainted.push_front(REG_RAX);
    case REG_EAX:  reg_name="REG_EAX"; 
    	break;
    case REG_AX:   reg_name="REG_AX"; 
    	break;
    case REG_AH:   reg_name="REG_AH"; 
    	break;
    case REG_AL:   reg_name="REG_AL"; 
         break;

    //case REG_RBX:  regsTainted.push_front(REG_RBX);
    case REG_EBX:  reg_name="REG_EBX"; 
    	break;
    case REG_BX:   reg_name="REG_BX"; 
    	break; 
    case REG_BH:   reg_name="REG_BH"; 
    	break; 
    case REG_BL:   reg_name="REG_BL"; 
         break;

    //case REG_RCX:  regsTainted.push_front(REG_RCX); 
    case REG_ECX:  reg_name="REG_ECX"; 
    	break;
    case REG_CX:   reg_name="REG_CX"; 
    	break;
    case REG_CH:   reg_name="REG_CH"; 
    	break;
    case REG_CL:   reg_name="REG_CL"; 
    	break;

    //case REG_RDX:  regsTainted.push_front(REG_RDX); 
    case REG_EDX:  reg_name="REG_EDX"; 
    	break; 
    case REG_DX:   reg_name="REG_DX"; 
    	break;
    case REG_DH:   reg_name="REG_DH"; 
    	break;
    case REG_DL:   reg_name="REG_DL"; 
    	break;

    //case REG_RDI:  regsTainted.push_front(REG_RDI); 
    case REG_EDI:  reg_name="REG_EDI"; 
    	break; 
    case REG_DI:   reg_name="REG_DI"; 
    	break;

    //case REG_RSI:  regsTainted.push_front(REG_RSI); 
    case REG_ESI:  reg_name="REG_ESI"; 
    	break;
    case REG_SI:   reg_name="REG_SI"; 
    	break;
    case REG_EFLAGS: reg_name="REG_EFLAGS"; 
    	break;

    case REG_XMM0: reg_name="REG_XMM0"; 
    	break;
    case REG_XMM1: reg_name="REG_XMM1"; 
    	break;
    case REG_XMM2: reg_name="REG_XMM2"; 
    	break;
    case REG_XMM3: reg_name="REG_XMM3"; 
    	break;
    case REG_XMM4: reg_name="REG_XMM4"; 
    	break;
    case REG_XMM5: reg_name="REG_XMM5"; 
    	break;
    case REG_XMM6: reg_name="REG_XMM6"; 
    	break;
    case REG_XMM7: reg_name="REG_XMM7"; 
    	break;
    default:
      reg_name="UNKnowReg";  
  }
  return reg_name;
}

/* ===================================================================== */
/* funcions for Tainting */
/* ===================================================================== */
bool ShadowReg::checkReg(REG reg)
{
	return shadow_reg_[reg];
}

bool ShadowReg::taintReg(REG reg)
{
	if (shadow_reg_[reg] == true){
		D(cout << "\t\t\t--" << REG_StringShort(reg) << " is already tainted" << endl;)
	}

	switch(reg){

		//case REG_RAX:  regsTainted.push_front(REG_RAX);
		case REG_EAX:  shadow_reg_[REG_EAX]=true; 
		case REG_AX:   shadow_reg_[REG_AX]=true; 
		case REG_AH:   shadow_reg_[REG_AH]=true;
		case REG_AL:   shadow_reg_[REG_AL]=true; 
			       break;

			       //case REG_RBX:  regsTainted.push_front(REG_RBX);
		case REG_EBX:  shadow_reg_[REG_EBX]=true; 
		case REG_BX:   shadow_reg_[REG_BX]=true; 
		case REG_BH:   shadow_reg_[REG_BH]=true; 
		case REG_BL:   shadow_reg_[REG_BL]=true; 
			       break;

			       //case REG_RCX:  regsTainted.push_front(REG_RCX); 
		case REG_ECX:  shadow_reg_[REG_ECX]=true; 
		case REG_CX:   shadow_reg_[REG_CX]=true; 
		case REG_CH:   shadow_reg_[REG_CH]=true; 
		case REG_CL:   shadow_reg_[REG_CL]=true; 
			       break;

			       //case REG_RDX:  regsTainted.push_front(REG_RDX); 
		case REG_EDX:  shadow_reg_[REG_EDX]=true;  
		case REG_DX:   shadow_reg_[REG_DX]=true; 
		case REG_DH:   shadow_reg_[REG_DH]=true;  
		case REG_DL:   shadow_reg_[REG_DL]=true;  
			       break;

			       //case REG_RDI:  regsTainted.push_front(REG_RDI); 
		case REG_EDI:  shadow_reg_[REG_EDI]=true;  
		case REG_DI:   shadow_reg_[REG_DI]=true; 
			       //case REG_DIL:  regsTainted.push_front(REG_DIL); 
			       break;

			       //case REG_RSI:  regsTainted.push_front(REG_RSI); 
		case REG_ESI:  shadow_reg_[REG_ESI]=true; 
		case REG_SI:   shadow_reg_[REG_SI]=true;  
			       //case REG_SIL:  regsTainted.push_front(REG_SIL); 
			       break;
		case REG_EFLAGS: shadow_reg_[REG_EFLAGS]=true; 
				 break;

		case REG_XMM0: shadow_reg_[REG_XMM0]=true; 
			       break;
		case REG_XMM1: shadow_reg_[REG_XMM1]=true; 
			       break;
		case REG_XMM2: shadow_reg_[REG_XMM2]=true; 
			       break;
		case REG_XMM3: shadow_reg_[REG_XMM3]=true; 
			       break;
		case REG_XMM4: shadow_reg_[REG_XMM4]=true; 
			       break;
		case REG_XMM5: shadow_reg_[REG_XMM5]=true; 
			       break;
		case REG_XMM6: shadow_reg_[REG_XMM6]=true; 
			       break;
		case REG_XMM7: shadow_reg_[REG_XMM7]=true; 
			       break;

		default:
			       D(cout << "\t\t\t--" << REG_StringShort(reg) << " can't be tainted" << endl;)
			       return false;
	}
	D(cout << "\t\t\t--" << REG_StringShort(reg) << " is now tainted" << endl;)
	return true;
}

bool ShadowReg::removeReg(REG reg)
{
	switch(reg){

		//case REG_RAX:  regsTainted.remove(REG_RAX);
		case REG_EAX:  shadow_reg_[REG_EAX]=false;
		case REG_AX:   shadow_reg_[REG_AX]=false;
		case REG_AH:   shadow_reg_[REG_AH]=false;
		case REG_AL:   shadow_reg_[REG_AL]=false;
			       break;

			       //case REG_RBX:  regsTainted.remove(REG_RBX);
		case REG_EBX:  shadow_reg_[REG_EBX]=false;
		case REG_BX:   shadow_reg_[REG_BX]=false;
		case REG_BH:   shadow_reg_[REG_BH]=false;
		case REG_BL:   shadow_reg_[REG_BL]=false;
			       break;

			       //case REG_RCX:  regsTainted.remove(REG_RCX); 
		case REG_ECX:  shadow_reg_[REG_ECX]=false;
		case REG_CX:   shadow_reg_[REG_CX]=false;
		case REG_CH:   shadow_reg_[REG_CH]=false;
		case REG_CL:   shadow_reg_[REG_CL]=false;
			       break;

			       //case REG_RDX:  regsTainted.remove(REG_RDX); 
		case REG_EDX:  shadow_reg_[REG_EDX]=false;
		case REG_DX:   shadow_reg_[REG_DX]=false;
		case REG_DH:   shadow_reg_[REG_DH]=false;
		case REG_DL:   shadow_reg_[REG_DL]=false;
			       break;

			       //case REG_RDI:  regsTainted.remove(REG_RDI); 
		case REG_EDI:  shadow_reg_[REG_EDI]=false;
		case REG_DI:   shadow_reg_[REG_DI]=false;
			       //case REG_DIL:  regsTainted.remove(REG_DIL); 
			       break;

			       //case REG_RSI:  regsTainted.remove(REG_RSI); 
		case REG_ESI:  shadow_reg_[REG_ESI]=false;
		case REG_SI:   shadow_reg_[REG_SI]=false;
			       //case REG_SIL:  regsTainted.remove(REG_SIL); 
			       break;

		case REG_EFLAGS: shadow_reg_[REG_EFLAGS]=false;
				 break;

		case REG_XMM0: shadow_reg_[REG_XMM0]=false;
			       break;
		case REG_XMM1: shadow_reg_[REG_XMM1]=false;
			       break;
		case REG_XMM2: shadow_reg_[REG_XMM2]=false;
			       break;
		case REG_XMM3: shadow_reg_[REG_XMM3]=false;
			       break;
		case REG_XMM4: shadow_reg_[REG_XMM4]=false;
			       break;
		case REG_XMM5: shadow_reg_[REG_XMM5]=false;
			       break;
		case REG_XMM6: shadow_reg_[REG_XMM6]=false;
			       break;
		case REG_XMM7: shadow_reg_[REG_XMM7]=false;
			       break;

		default:
			       return false;
	}
	D(cout << "\t\t\t--" << REG_StringShort(reg) << " is now freed" << endl;)
	return true;
}


VOID removeMemTainted(UINT32 addr, UINT32 length) {
	vector<UINT32> newAddr;
	for(UINT32 i = 0;i < addressTainted.size();++i) {
		if(addressTainted[i] < addr || addressTainted[i] >= addr + length)
			newAddr.push_back(addressTainted[i]);
	}
	addressTainted = newAddr;
}


VOID SyscallEntry(THREADID threadIndex, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v) {
	unsigned int i;
	UINT32 start,size;
    if (PIN_GetSyscallNumber(ctx, std) == __NR_read) {
    	// TRICKS();
    	start = static_cast<UINT32>((PIN_GetSyscallArgument(ctx, std, 1)));
    	size = static_cast<UINT32>((PIN_GetSyscallArgument(ctx, std, 2)));
    	// char buffer[size + 1];
    	
    	for(i = 0;i < size;++i) {
    		addressTainted.push_back(start + i);
    	}
        outFile << "[TAINT]\t\tbytes tainted from " << std::hex << "0x" << start << " to 0x" << start + size << endl;
        
    }
}


VOID ReadMem(UINT32 insAddr, std::string insDis, UINT32 OperandCount, REG reg_r, UINT32 memOp, UINT32 sp) {
	vector<UINT32>::iterator i;
	UINT32 addr = memOp;
	if(OperandCount != 2) {
		return ;
	}
	for(i = addressTainted.begin();i != addressTainted.end();++i) {
		if(addr == *i) {
			if(insAddr <= 0x80b8000) 
				outFile << std::hex << insAddr << ":\t[READ in " << addr << "][T]" << " insDis: " << insDis << std::endl;
			shadow_reg->taintReg(reg_r);
			return ;
		}
	}
	/* if mem != tainted and reg == taint , then free the reg */
	if(shadow_reg->checkReg(reg_r)) {
		if(insAddr <= 0x80b8000) 
			outFile << std::hex << insAddr << ":\tREAD in " << addr << "][F]" << " insDis: " << insDis << std::endl;
		shadow_reg->removeReg(reg_r);
	}
}


VOID WriteMem(UINT32 insAddr, std::string insDis, UINT32 OperandCount, REG reg_r, REG reg_0, UINT32 memOp, UINT32 sp) {
	vector<UINT32>::iterator i;
	UINT32 addr = memOp;
	UINT32 length = 0;
	if(OperandCount != 2)
		return ;
	if(!REG_valid(reg_r)) {
		if(REG_valid(reg_0)) {
			reg_r = reg_0;
		} else {
			if(insDis.find("dword ptr", 0) != string::npos) {
				length = 4;
			} else if(insDis.find("word ptr", 0) != string::npos) {
				length = 2;
			} else {
				length = 1;
			}
		}
	}
	for(i = addressTainted.begin();i != addressTainted.end();++i) {
		if(addr == *i) {
			if(insAddr <= 0x80b8000)
				outFile << std::hex << insAddr << ":\t[WRITE in " << addr << "][F]" << " insDis:" << insDis << sp << std::endl;
			// outFile << std::hex << reg_r << std::endl;
			if(!REG_valid(reg_r) || !shadow_reg->checkReg(reg_r)) {
				if(REG_is_Lower8(reg_r) || REG_is_Upper8(reg_r)) {
					length = 1;
				} else if(REG_is_Half16(reg_r)) {
					length = 2;
				} else if(REG_is_Half32(reg_r)) {
					length = 4;
				}
				removeMemTainted(addr, length);
			}
		}
	}
}


VOID spreadRegTaint(UINT32 insAddr, std::string insDis, UINT32 OperandCount, REG reg_r, REG reg_w) {
	if(REG_valid(reg_w)) {
		if(shadow_reg->checkReg(reg_w) && (!REG_valid(reg_r) || !shadow_reg->checkReg(reg_r))) {
			if(insAddr <= 0x80b8000) 
				outFile << std::hex << insAddr << ":\t[SPREAD][F]" << " insDis:" << insDis << std::endl;
			shadow_reg->removeReg(reg_w);
		} else if(!shadow_reg->checkReg(reg_w) && shadow_reg->checkReg(reg_r)) {
			if(insAddr <= 0x80b8000) 
				outFile << std::hex << insAddr << ":\t[SPREAD][F]" << " insDis:" << insDis << std::endl;
			shadow_reg->taintReg(reg_w);
		}
	}
}


VOID Fini(INT32 code, VOID *v) {
    outFile.close();
}


VOID Instruction(INS ins, VOID* v) {
	//outFile << std::hex << INS_Address(ins) << ":\t" << INS_Disassemble(ins) << std::endl;
	if(INS_OperandCount(ins) <= 1)
		return ;
	if(INS_IsMemoryRead(ins)) {
		INS_InsertCall(
			ins, IPOINT_BEFORE, (AFUNPTR)ReadMem,
			IARG_ADDRINT, INS_Address(ins),
			IARG_PTR, new string(INS_Disassemble(ins)),
			IARG_UINT32, INS_OperandCount(ins),
			IARG_UINT32, INS_OperandReg(ins, 0),
			IARG_MEMORYOP_EA, 0,
			IARG_REG_VALUE, REG_STACK_PTR,
			IARG_END);
	} else if(INS_IsMemoryWrite(ins)) {
		INS_InsertCall(
			ins, IPOINT_BEFORE, (AFUNPTR)WriteMem,
			IARG_ADDRINT, INS_Address(ins),
			IARG_PTR, new string(INS_Disassemble(ins)),
			IARG_UINT32, INS_OperandCount(ins),
			IARG_UINT32, INS_OperandReg(ins, 1),
			IARG_UINT32, INS_OperandReg(ins, 0),
			IARG_MEMORYOP_EA, 0,
			IARG_REG_VALUE, REG_STACK_PTR,
			IARG_END);
	} else if(INS_OperandIsReg(ins, 0)) {
		INS_InsertCall(
			ins, IPOINT_BEFORE, (AFUNPTR)spreadRegTaint,
			IARG_ADDRINT, INS_Address(ins),
			IARG_PTR, new string(INS_Disassemble(ins)),
			IARG_UINT32, INS_OperandCount(ins),
			IARG_UINT32, INS_RegR(ins, 0),
			IARG_UINT32, INS_RegW(ins, 0),
			IARG_END);
	}
}


VOID TaintInit() {
	shadow_reg = new ShadowReg();
	
}


int main(int argc, char *argv[]) {
    PIN_Init(argc, argv);
    PIN_InitSymbols();
    TaintInit();
    PIN_SetSyntaxIntel();
    outFile.open(KnobOutputFile.Value().c_str());
    
    PIN_AddSyscallEntryFunction(SyscallEntry, 0);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}
```
编译之后，运行输入可以看到寄存器的染色过程，最后输出到文件的内存染色记录：
```
[TAINT]		bytes tainted from 0x80f2e90 to 0x80f3290
8054fe3:	[READ in 80f2e90][T] insDis: movzx eax, byte ptr [eax]
805816e:	[SPREAD][F] insDis:cmp eax, 0xffffffff
8058173:	[READ in 80ed324][F] insDis: mov eax, dword ptr [ebx+0x4]
805817c:	[READ in 80f2e90][T] insDis: movzx eax, byte ptr [eax]
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
80545d6:	[READ in 80f2e91][T] insDis: movzx eax, byte ptr [eax]
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
80545d6:	[READ in 80f2e92][T] insDis: movzx eax, byte ptr [eax]
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
80545d6:	[READ in 80f2e93][T] insDis: movzx eax, byte ptr [eax]
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
80545d6:	[READ in 80f2e94][T] insDis: movzx eax, byte ptr [eax]
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
80545d6:	[READ in 80f2e95][T] insDis: movzx eax, byte ptr [eax]
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
80545d6:	[READ in 80f2e96][T] insDis: movzx eax, byte ptr [eax]
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
80545d6:	[READ in 80f2e97][T] insDis: movzx eax, byte ptr [eax]
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
80545d6:	[READ in 80f2e98][T] insDis: movzx eax, byte ptr [eax]
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
80545d6:	[READ in 80f2e99][T] insDis: movzx eax, byte ptr [eax]
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
80545d6:	[READ in 80f2e9a][T] insDis: movzx eax, byte ptr [eax]
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
80545d6:	[READ in 80f2e9b][T] insDis: movzx eax, byte ptr [eax]
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
80545d6:	[READ in 80f2e9c][T] insDis: movzx eax, byte ptr [eax]
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
80545d6:	[READ in 80f2e9d][T] insDis: movzx eax, byte ptr [eax]
8049797:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
8057ec9:	[SPREAD][F] insDis:test eax, eax
[TAINT]		bytes tainted from 0x80f2e90 to 0x80f3290
8054fe3:	[READ in 80f2e90][T] insDis: movzx eax, byte ptr [eax]
805816e:	[SPREAD][F] insDis:cmp eax, 0xffffffff
8058173:	[READ in 80ed324][F] insDis: mov eax, dword ptr [ebx+0x4]
805817c:	[READ in 80f2e90][T] insDis: movzx eax, byte ptr [eax]
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
80545d6:	[READ in 80f2e91][T] insDis: movzx eax, byte ptr [eax]
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
80545d6:	[READ in 80f2e92][T] insDis: movzx eax, byte ptr [eax]
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
80545d6:	[READ in 80f2e93][T] insDis: movzx eax, byte ptr [eax]
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
80545d6:	[READ in 80f2e94][T] insDis: movzx eax, byte ptr [eax]
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
80545d6:	[READ in 80f2e95][T] insDis: movzx eax, byte ptr [eax]
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
80545d6:	[READ in 80f2e96][T] insDis: movzx eax, byte ptr [eax]
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
80545d6:	[READ in 80f2e97][T] insDis: movzx eax, byte ptr [eax]
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
80545d6:	[READ in 80f2e98][T] insDis: movzx eax, byte ptr [eax]
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
80545d6:	[READ in 80f2e99][T] insDis: movzx eax, byte ptr [eax]
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
80545d6:	[READ in 80f2e9a][T] insDis: movzx eax, byte ptr [eax]
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
80545d6:	[READ in 80f2e9b][T] insDis: movzx eax, byte ptr [eax]
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
80545d6:	[READ in 80f2e9c][T] insDis: movzx eax, byte ptr [eax]
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
80545d6:	[READ in 80f2e9d][T] insDis: movzx eax, byte ptr [eax]
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
80545d6:	[READ in 80f2e9e][T] insDis: movzx eax, byte ptr [eax]
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
80545d6:	[READ in 80f2e9f][T] insDis: movzx eax, byte ptr [eax]
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
80545d6:	[READ in 80f2ea0][T] insDis: movzx eax, byte ptr [eax]
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
80545d6:	[READ in 80f2ea1][T] insDis: movzx eax, byte ptr [eax]
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
80545d6:	[READ in 80f2ea2][T] insDis: movzx eax, byte ptr [eax]
8049797:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
```
不过可以看出 WriteMem 似乎没有起到作用，问题在哪里呢？因为我们没有加上通过内存写产生的新染色内存区域，为了方便，我们将染色内存区域改为集合的形式，方便增删。
最后得到的整体代码如下：
```cpp
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <syscall.h>
#include <vector>
#include <string>
#include <set>
#include "pin.H"

#define D(x) x
using namespace std;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "read_calls.out", "specify output file name");

ofstream outFile;
set<UINT32> addressTainted;

class ShadowReg{
private:
    bool shadow_reg_[287] = {false};
public:

    bool checkReg(REG reg);
    bool taintReg(REG reg);
    bool removeReg(REG reg);
};
ShadowReg* shadow_reg;
string GetREGName(REG reg);

string GetREGName(REG reg) {
  string reg_name; 
	reg_name="UNKnowReg:"+reg; 
	switch(reg){

    //case REG_RAX:  regsTainted.push_front(REG_RAX);
    case REG_EAX:  reg_name="REG_EAX"; 
    	break;
    case REG_AX:   reg_name="REG_AX"; 
    	break;
    case REG_AH:   reg_name="REG_AH"; 
    	break;
    case REG_AL:   reg_name="REG_AL"; 
         break;

    //case REG_RBX:  regsTainted.push_front(REG_RBX);
    case REG_EBX:  reg_name="REG_EBX"; 
    	break;
    case REG_BX:   reg_name="REG_BX"; 
    	break; 
    case REG_BH:   reg_name="REG_BH"; 
    	break; 
    case REG_BL:   reg_name="REG_BL"; 
         break;

    //case REG_RCX:  regsTainted.push_front(REG_RCX); 
    case REG_ECX:  reg_name="REG_ECX"; 
    	break;
    case REG_CX:   reg_name="REG_CX"; 
    	break;
    case REG_CH:   reg_name="REG_CH"; 
    	break;
    case REG_CL:   reg_name="REG_CL"; 
    	break;

    //case REG_RDX:  regsTainted.push_front(REG_RDX); 
    case REG_EDX:  reg_name="REG_EDX"; 
    	break; 
    case REG_DX:   reg_name="REG_DX"; 
    	break;
    case REG_DH:   reg_name="REG_DH"; 
    	break;
    case REG_DL:   reg_name="REG_DL"; 
    	break;

    //case REG_RDI:  regsTainted.push_front(REG_RDI); 
    case REG_EDI:  reg_name="REG_EDI"; 
    	break; 
    case REG_DI:   reg_name="REG_DI"; 
    	break;

    //case REG_RSI:  regsTainted.push_front(REG_RSI); 
    case REG_ESI:  reg_name="REG_ESI"; 
    	break;
    case REG_SI:   reg_name="REG_SI"; 
    	break;
    case REG_EFLAGS: reg_name="REG_EFLAGS"; 
    	break;

    case REG_XMM0: reg_name="REG_XMM0"; 
    	break;
    case REG_XMM1: reg_name="REG_XMM1"; 
    	break;
    case REG_XMM2: reg_name="REG_XMM2"; 
    	break;
    case REG_XMM3: reg_name="REG_XMM3"; 
    	break;
    case REG_XMM4: reg_name="REG_XMM4"; 
    	break;
    case REG_XMM5: reg_name="REG_XMM5"; 
    	break;
    case REG_XMM6: reg_name="REG_XMM6"; 
    	break;
    case REG_XMM7: reg_name="REG_XMM7"; 
    	break;
    default:
      reg_name="UNKnowReg";  
  }
  return reg_name;
}

/* ===================================================================== */
/* funcions for Tainting */
/* ===================================================================== */
bool ShadowReg::checkReg(REG reg)
{
	return shadow_reg_[reg];
}

bool ShadowReg::taintReg(REG reg)
{
	if (shadow_reg_[reg] == true){
		D(cout << "\t\t\t--" << REG_StringShort(reg) << " is already tainted" << endl;)
	}

	switch(reg){

		//case REG_RAX:  regsTainted.push_front(REG_RAX);
		case REG_EAX:  shadow_reg_[REG_EAX]=true; 
		case REG_AX:   shadow_reg_[REG_AX]=true; 
		case REG_AH:   shadow_reg_[REG_AH]=true;
		case REG_AL:   shadow_reg_[REG_AL]=true; 
			       break;

			       //case REG_RBX:  regsTainted.push_front(REG_RBX);
		case REG_EBX:  shadow_reg_[REG_EBX]=true; 
		case REG_BX:   shadow_reg_[REG_BX]=true; 
		case REG_BH:   shadow_reg_[REG_BH]=true; 
		case REG_BL:   shadow_reg_[REG_BL]=true; 
			       break;

			       //case REG_RCX:  regsTainted.push_front(REG_RCX); 
		case REG_ECX:  shadow_reg_[REG_ECX]=true; 
		case REG_CX:   shadow_reg_[REG_CX]=true; 
		case REG_CH:   shadow_reg_[REG_CH]=true; 
		case REG_CL:   shadow_reg_[REG_CL]=true; 
			       break;

			       //case REG_RDX:  regsTainted.push_front(REG_RDX); 
		case REG_EDX:  shadow_reg_[REG_EDX]=true;  
		case REG_DX:   shadow_reg_[REG_DX]=true; 
		case REG_DH:   shadow_reg_[REG_DH]=true;  
		case REG_DL:   shadow_reg_[REG_DL]=true;  
			       break;

			       //case REG_RDI:  regsTainted.push_front(REG_RDI); 
		case REG_EDI:  shadow_reg_[REG_EDI]=true;  
		case REG_DI:   shadow_reg_[REG_DI]=true; 
			       //case REG_DIL:  regsTainted.push_front(REG_DIL); 
			       break;

			       //case REG_RSI:  regsTainted.push_front(REG_RSI); 
		case REG_ESI:  shadow_reg_[REG_ESI]=true; 
		case REG_SI:   shadow_reg_[REG_SI]=true;  
			       //case REG_SIL:  regsTainted.push_front(REG_SIL); 
			       break;
		case REG_EFLAGS: shadow_reg_[REG_EFLAGS]=true; 
				 break;

		case REG_XMM0: shadow_reg_[REG_XMM0]=true; 
			       break;
		case REG_XMM1: shadow_reg_[REG_XMM1]=true; 
			       break;
		case REG_XMM2: shadow_reg_[REG_XMM2]=true; 
			       break;
		case REG_XMM3: shadow_reg_[REG_XMM3]=true; 
			       break;
		case REG_XMM4: shadow_reg_[REG_XMM4]=true; 
			       break;
		case REG_XMM5: shadow_reg_[REG_XMM5]=true; 
			       break;
		case REG_XMM6: shadow_reg_[REG_XMM6]=true; 
			       break;
		case REG_XMM7: shadow_reg_[REG_XMM7]=true; 
			       break;

		default:
			       D(cout << "\t\t\t--" << REG_StringShort(reg) << " can't be tainted" << endl;)
			       return false;
	}
	D(cout << "\t\t\t--" << REG_StringShort(reg) << " is now tainted" << endl;)
	return true;
}

bool ShadowReg::removeReg(REG reg)
{
	switch(reg){

		//case REG_RAX:  regsTainted.remove(REG_RAX);
		case REG_EAX:  shadow_reg_[REG_EAX]=false;
		case REG_AX:   shadow_reg_[REG_AX]=false;
		case REG_AH:   shadow_reg_[REG_AH]=false;
		case REG_AL:   shadow_reg_[REG_AL]=false;
			       break;

			       //case REG_RBX:  regsTainted.remove(REG_RBX);
		case REG_EBX:  shadow_reg_[REG_EBX]=false;
		case REG_BX:   shadow_reg_[REG_BX]=false;
		case REG_BH:   shadow_reg_[REG_BH]=false;
		case REG_BL:   shadow_reg_[REG_BL]=false;
			       break;

			       //case REG_RCX:  regsTainted.remove(REG_RCX); 
		case REG_ECX:  shadow_reg_[REG_ECX]=false;
		case REG_CX:   shadow_reg_[REG_CX]=false;
		case REG_CH:   shadow_reg_[REG_CH]=false;
		case REG_CL:   shadow_reg_[REG_CL]=false;
			       break;

			       //case REG_RDX:  regsTainted.remove(REG_RDX); 
		case REG_EDX:  shadow_reg_[REG_EDX]=false;
		case REG_DX:   shadow_reg_[REG_DX]=false;
		case REG_DH:   shadow_reg_[REG_DH]=false;
		case REG_DL:   shadow_reg_[REG_DL]=false;
			       break;

			       //case REG_RDI:  regsTainted.remove(REG_RDI); 
		case REG_EDI:  shadow_reg_[REG_EDI]=false;
		case REG_DI:   shadow_reg_[REG_DI]=false;
			       //case REG_DIL:  regsTainted.remove(REG_DIL); 
			       break;

			       //case REG_RSI:  regsTainted.remove(REG_RSI); 
		case REG_ESI:  shadow_reg_[REG_ESI]=false;
		case REG_SI:   shadow_reg_[REG_SI]=false;
			       //case REG_SIL:  regsTainted.remove(REG_SIL); 
			       break;

		case REG_EFLAGS: shadow_reg_[REG_EFLAGS]=false;
				 break;

		case REG_XMM0: shadow_reg_[REG_XMM0]=false;
			       break;
		case REG_XMM1: shadow_reg_[REG_XMM1]=false;
			       break;
		case REG_XMM2: shadow_reg_[REG_XMM2]=false;
			       break;
		case REG_XMM3: shadow_reg_[REG_XMM3]=false;
			       break;
		case REG_XMM4: shadow_reg_[REG_XMM4]=false;
			       break;
		case REG_XMM5: shadow_reg_[REG_XMM5]=false;
			       break;
		case REG_XMM6: shadow_reg_[REG_XMM6]=false;
			       break;
		case REG_XMM7: shadow_reg_[REG_XMM7]=false;
			       break;

		default:
			       return false;
	}
	D(cout << "\t\t\t--" << REG_StringShort(reg) << " is now freed" << endl;)
	return true;
}


VOID removeMemTainted(UINT32 addr, UINT32 length) {
	for(auto temp = addressTainted.begin();temp != addressTainted.end();) {
		if(*temp >= addr && *temp < addr + length) {
			temp = addressTainted.erase(temp);
		} else {
			++temp;
		}
	}
}


VOID SyscallEntry(THREADID threadIndex, CONTEXT *ctx, SYSCALL_STANDARD std, VOID *v) {
	unsigned int i;
	UINT32 start,size;
    if (PIN_GetSyscallNumber(ctx, std) == __NR_read) {
    	// TRICKS();
    	start = static_cast<UINT32>((PIN_GetSyscallArgument(ctx, std, 1)));
    	size = static_cast<UINT32>((PIN_GetSyscallArgument(ctx, std, 2)));
    	// char buffer[size + 1];
    	
    	for(i = 0;i < size;++i) {
    		addressTainted.insert(start + i);
    	}
        outFile << "[TAINT]\t\tbytes tainted from " << std::hex << "0x" << start << " to 0x" << start + size << endl;
        
    }
}


VOID ReadMem(UINT32 insAddr, std::string insDis, UINT32 OperandCount, REG reg_r, UINT32 memOp, UINT32 sp) {
	//vector<UINT32>::iterator i;
	UINT32 addr = memOp;
	if(OperandCount != 2) {
		return ;
	}
	
	if(addressTainted.count(addr)) {
		if(insAddr <= 0x80b8000) 
			outFile << std::hex << insAddr << ":\t[READ in " << addr << "][T]" << " insDis: " << insDis << std::endl;
		shadow_reg->taintReg(reg_r);
		return ;
	}
	/* if mem != tainted and reg == taint , then free the reg */
	if(shadow_reg->checkReg(reg_r)) {
		if(insAddr <= 0x80b8000) 
			outFile << std::hex << insAddr << ":\t[READ in " << addr << "][F]" << " insDis: " << insDis << std::endl;
		shadow_reg->removeReg(reg_r);
	}
}


VOID WriteMem(UINT32 insAddr, std::string insDis, UINT32 OperandCount, REG reg_r, REG reg_0, UINT32 memOp, UINT32 sp) {
	vector<UINT32>::iterator i;
	UINT32 addr = memOp;
	UINT32 length = 0;
	if(OperandCount != 2)
		return ;
	if(!REG_valid(reg_r)) {
		if(REG_valid(reg_0)) {
			reg_r = reg_0;
		} else {
			if(insDis.find("dword ptr", 0) != string::npos) {
				length = 4;
			} else if(insDis.find("word ptr", 0) != string::npos) {
				length = 2;
			} else {
				length = 1;
			}
		}
	}
	// std::cout << "Write" << addressTainted.size() << std::endl;
	if(addressTainted.count(addr)) {
		if(insAddr <= 0x80b8000)
			outFile << std::hex << insAddr << ":\t[WRITE in " << addr << "][F]" << " insDis:" << insDis << " sink point: " << sp << std::endl;
		 std::cout << std::hex << reg_r << "Write" << std::endl;
		if(!REG_valid(reg_r) || !shadow_reg->checkReg(reg_r)) {
			if(REG_is_Lower8(reg_r) || REG_is_Upper8(reg_r)) {
				length = 1;
			} else if(REG_is_Half16(reg_r)) {
				length = 2;
			} else if(REG_is_Half32(reg_r)) {
				length = 4;
			}
			removeMemTainted(addr, length);
		}
	} else if(REG_valid(reg_r) && shadow_reg->checkReg(reg_r)) {
		if(insAddr <= 0x80b8000) 
			outFile << std::hex << insAddr << ":\t[WRITE in " << addr << "][T]" << " insDis:" << insDis << " sink point: " << sp << std::endl;
		 std::cout << std::hex << reg_r << "Write" << std::endl;
		 if(REG_is_Lower8(reg_r) || REG_is_Upper8(reg_r)) {
				length = 1;
		} else if(REG_is_Half16(reg_r)) {
			length = 2;
		} else if(REG_is_Half32(reg_r)) {
			length = 4;
		}
		for(UINT32 i = 0;i < length;++i) 
			addressTainted.insert(addr + i);
	}
}


VOID spreadRegTaint(UINT32 insAddr, std::string insDis, UINT32 OperandCount, REG reg_r, REG reg_w) {
	if(REG_valid(reg_w)) {
		if(shadow_reg->checkReg(reg_w) && (!REG_valid(reg_r) || !shadow_reg->checkReg(reg_r))) {
			if(insAddr <= 0x80b8000) 
				outFile << std::hex << insAddr << ":\t[SPREAD][F]" << " insDis:" << insDis << std::endl;
			shadow_reg->removeReg(reg_w);
		} else if(!shadow_reg->checkReg(reg_w) && shadow_reg->checkReg(reg_r)) {
			if(insAddr <= 0x80b8000) 
				outFile << std::hex << insAddr << ":\t[SPREAD][T]" << " insDis:" << insDis << std::endl;
			shadow_reg->taintReg(reg_w);
		}
	}
}


VOID Fini(INT32 code, VOID *v) {
    outFile.close();
}


VOID Instruction(INS ins, VOID* v) {
	//outFile << std::hex << INS_Address(ins) << ":\t" << INS_Disassemble(ins) << std::endl;
	if(INS_OperandCount(ins) <= 1)
		return ;
	if(INS_IsMemoryRead(ins)) {
		INS_InsertCall(
			ins, IPOINT_BEFORE, (AFUNPTR)ReadMem,
			IARG_ADDRINT, INS_Address(ins),
			IARG_PTR, new string(INS_Disassemble(ins)),
			IARG_UINT32, INS_OperandCount(ins),
			IARG_UINT32, INS_OperandReg(ins, 0),
			IARG_MEMORYOP_EA, 0,
			IARG_REG_VALUE, REG_STACK_PTR,
			IARG_END);
	} else if(INS_IsMemoryWrite(ins)) {
		INS_InsertCall(
			ins, IPOINT_BEFORE, (AFUNPTR)WriteMem,
			IARG_ADDRINT, INS_Address(ins),
			IARG_PTR, new string(INS_Disassemble(ins)),
			IARG_UINT32, INS_OperandCount(ins),
			IARG_UINT32, INS_OperandReg(ins, 1),
			IARG_UINT32, INS_OperandReg(ins, 0),
			IARG_MEMORYOP_EA, 0,
			IARG_REG_VALUE, REG_STACK_PTR,
			IARG_END);
	} else if(INS_OperandIsReg(ins, 0)) {
		INS_InsertCall(
			ins, IPOINT_BEFORE, (AFUNPTR)spreadRegTaint,
			IARG_ADDRINT, INS_Address(ins),
			IARG_PTR, new string(INS_Disassemble(ins)),
			IARG_UINT32, INS_OperandCount(ins),
			IARG_UINT32, INS_RegR(ins, 0),
			IARG_UINT32, INS_RegW(ins, 0),
			IARG_END);
	}
}


VOID TaintInit() {
	shadow_reg = new ShadowReg();
	
}



int main(int argc, char *argv[]) {
    PIN_Init(argc, argv);
    PIN_InitSymbols();
    TaintInit();
    PIN_SetSyntaxIntel();
    outFile.open(KnobOutputFile.Value().c_str());
    
    PIN_AddSyscallEntryFunction(SyscallEntry, 0);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}
```
产生如下的分析结果：
```
[TAINT]		bytes tainted from 0x80f2e90 to 0x80f3290
    8054fe3:	[READ in 80f2e90][T] insDis: movzx eax, byte ptr [eax]
805816e:	[SPREAD][T] insDis:cmp eax, 0xffffffff
        8058173:	[READ in 80ed324][F] insDis: mov eax, dword ptr [ebx+0x4]
805817c:	[READ in 80f2e90][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd5b][T] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd50
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd5b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in 80ee320][T] insDis:mov byte ptr [edx], al sink point: ffffcd50
804f99c:	[READ in ffffcd48][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e91][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd5b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd50
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd5b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in 80ee321][T] insDis:mov byte ptr [edx], al sink point: ffffcd50
804f99c:	[READ in ffffcd48][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e92][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd5b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd50
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd5b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in 80ee322][T] insDis:mov byte ptr [edx], al sink point: ffffcd50
804f99c:	[READ in ffffcd48][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e93][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd5b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd50
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd5b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in 80ee323][T] insDis:mov byte ptr [edx], al sink point: ffffcd50
804f99c:	[READ in ffffcd48][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e94][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd5b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd50
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd5b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in 80ee324][T] insDis:mov byte ptr [edx], al sink point: ffffcd50
804f99c:	[READ in ffffcd48][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e95][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd5b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd50
        8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd5b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in 80ee325][T] insDis:mov byte ptr [edx], al sink point: ffffcd50
804f99c:	[READ in ffffcd48][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e96][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd5b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd50
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd5b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in 80ee326][T] insDis:mov byte ptr [edx], al sink point: ffffcd50
804f99c:	[READ in ffffcd48][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e97][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd5b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd50
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd5b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in 80ee327][T] insDis:mov byte ptr [edx], al sink point: ffffcd50
804f99c:	[READ in ffffcd48][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e98][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd5b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd50
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd5b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in 80ee328][T] insDis:mov byte ptr [edx], al sink point: ffffcd50
804f99c:	[READ in ffffcd48][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e99][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd5b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd50
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd5b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in 80ee329][T] insDis:mov byte ptr [edx], al sink point: ffffcd50
804f99c:	[READ in ffffcd48][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e9a][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd5b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd50
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd5b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in 80ee32a][T] insDis:mov byte ptr [edx], al sink point: ffffcd50
804f99c:	[READ in ffffcd48][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e9b][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd5b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd50
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd5b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in 80ee32b][T] insDis:mov byte ptr [edx], al sink point: ffffcd50
804f99c:	[READ in ffffcd48][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e9c][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd5b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd50
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd5b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in 80ee32c][T] insDis:mov byte ptr [edx], al sink point: ffffcd50
804f99c:	[READ in ffffcd48][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e9d][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd5b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd50
8049797:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
80497c4:	[READ in 80ee320][T] insDis: movzx eax, byte ptr [0x80ee320]
80497cb:	[SPREAD][T] insDis:movsx edx, al
80497ce:	[READ in 80ee321][T] insDis: movzx eax, byte ptr [0x80ee321]
80497da:	[READ in 80ee323][T] insDis: movzx eax, byte ptr [0x80ee323]
80497e4:	[SPREAD][T] insDis:lea ecx, ptr [edx+eax*1]
80497e7:	[READ in 80ee324][T] insDis: movzx eax, byte ptr [0x80ee324]
80497f1:	[READ in 80ee32c][T] insDis: mov eax, dword ptr [0x80ee32c]
8049800:	[WRITE in 80ee4b4][T] insDis:mov dword ptr [eax], edx sink point: ffffcd80
8049802:	[SPREAD][F] insDis:mov eax, 0x0
8057ec9:	[SPREAD][F] insDis:test eax, eax
8057ee7:	[READ in 80ed328][F] insDis: mov edx, dword ptr [esi+0x8]
8057f45:	[SPREAD][F] insDis:mov ecx, edi
[TAINT]		bytes tainted from 0x80f2e90 to 0x80f3290
8054fe3:	[READ in 80f2e90][T] insDis: movzx eax, byte ptr [eax]
805816e:	[SPREAD][T] insDis:cmp eax, 0xffffffff
8058173:	[READ in 80ed324][F] insDis: mov eax, dword ptr [ebx+0x4]
805817c:	[READ in 80f2e90][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][T] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd76][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e91][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd77][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e92][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd78][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e93][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd79][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e94][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd7a][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e95][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd7b][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e96][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd7c][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e97][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd7d][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e98][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd7e][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e99][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd7f][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e9a][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd80][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e9b][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd81][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e9c][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd82][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e9d][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd83][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e9e][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd84][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e9f][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd85][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2ea0][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd86][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2ea1][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd87][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2ea2][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049797:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
```
这样我们也就可以解决第三个问题，只要确定指针解引用的赋值操作中，是否存在被染色区域的数据，就可以断定解引用是否被输入污染。
### 判断指针解引用
我们可以发现，两个 `[TAINT]` 也就是代表了前后两个函数。我们的输入数据首先被存到了 0x80f2e90 的缓冲区，没有初始化的全局变量 Data 在 BSS 段，地址范围是 0x80ed000 ~ 0x80ef000。
![image.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1721491748544-817a136e-0b68-49d2-8486-e0ce388e2cf6.png#averageHue=%2341424f&clientId=ucb6bfc95-c847-4&from=paste&height=227&id=udc6210d2&originHeight=340&originWidth=939&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=352613&status=done&style=none&taskId=ua9e8964d-96ec-481c-82f6-7bafed22d68&title=&width=626)
于是我们可以定位结果中针对这一内存区域的写操作，也就是 readstr 中对 Data.input 的写入。
于是找到了：
`8049780:	[WRITE in 80ee320][T] insDis:mov byte ptr [edx], al sink point: ffffcd50`
后续还有连续的 0x80ee321、322 等地址的写入，可以断定 0x80ee320 就是 Data 的起始地址。
定位到指针的解引用一行，是用 Data 内的数据对 Data 自身赋值。
`*(Data.BUFF + Data.offset) = Data.input[0]+Data.input[1]+Data.input[3]+Data.input[4];`
那么只要验证 Data.input 内的数据是否来自被染色区域，即可说明解引用操作是否被污染。
注意分析结果的 86 到 93 行，存在从 0x80ee320、321、323 到 324 的染色区域读取，对应为取的四个下标，以及 0x80ee32c 的读取，与 Data 起始地址的偏移为 12，是 4 Bytes 对齐的结果，表示读取 offset 字段，但是这时最低字节已经被我们的输入覆盖成 `'a'` 了，对应 ASCII 码为 97 = 0x61，于是有了 93 行的 0x80ee4b4 的写操作。
`8049800:	[WRITE in 80ee4b4][T] insDis:mov dword ptr [eax], edx sink point: ffffcd80`
所以可以断定，解引用时，指针已经被输入数据污染。
注意这里做指针运算时，指针类型为 int*，所以计算为 offset * sizeof(int) = 0x61 * 4。
`0x80ee320 + 0xc + 0x4 + 0x61 * 4 = 0x80ee4b4`
### 返回地址篡改
最后是确定返回地址是否被篡改的问题，也就是在第二个函数中，返回地址是否被覆盖。
首先从函数调用角度考虑，每当函数返回时（ret 指令执行之前），会进行栈的清理，最后 esp 指针指向返回地址，再执行 ret（pop eip）。
那么我们可以考虑在此时 pop esp，若栈上的数据属于污点数据，那么 esp 也会被污染。这样我们可以认为返回地址被篡改。
于是加上以下函数，从 CPU 的上下文信息中获取 esp 寄存器的信息，之后检查是否被污染。
```cpp
VOID FunctionRet(ADDRINT ip, CONTEXT *ctx) {
    ADDRINT value = ip;
    UINT8* ESP_value = (UINT8*)&value;
    PIN_GetContextRegval(ctx, REG_ESP, ESP_value);
    value += 8;
    value %= 0x10000000;
    //outFile << std::hex << "ESP->" << value << std::endl;
    if(addressTainted.count(value)) {
        outFile << std::hex << "ERROR:RET Address Is Tainted!" << " &&ESP->" << value << std::endl;
    }
}

/* 插桩新函数 */
else if(INS_IsRet(ins)) {
    INS_InsertCall(
        ins, IPOINT_BEFORE, (AFUNPTR)FunctionRet,
        IARG_INST_PTR, IARG_CONTEXT,
        IARG_END);
}
```
最后输出：
```cpp
[TAINT]		bytes tainted from 0x80f2e90 to 0x80f3290
8054fe3:	[READ in 80f2e90][T] insDis: movzx eax, byte ptr [eax]
805816e:	[SPREAD][T] insDis:cmp eax, 0xffffffff
8058173:	[READ in 80ed324][F] insDis: mov eax, dword ptr [ebx+0x4]
805817c:	[READ in 80f2e90][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd5b][T] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd50
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd5b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in 80ee320][T] insDis:mov byte ptr [edx], al sink point: ffffcd50
804f99c:	[READ in ffffcd48][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e91][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd5b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd50
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd5b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in 80ee321][T] insDis:mov byte ptr [edx], al sink point: ffffcd50
804f99c:	[READ in ffffcd48][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e92][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd5b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd50
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd5b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in 80ee322][T] insDis:mov byte ptr [edx], al sink point: ffffcd50
804f99c:	[READ in ffffcd48][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e93][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd5b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd50
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd5b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in 80ee323][T] insDis:mov byte ptr [edx], al sink point: ffffcd50
804f99c:	[READ in ffffcd48][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e94][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd5b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd50
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd5b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in 80ee324][T] insDis:mov byte ptr [edx], al sink point: ffffcd50
804f99c:	[READ in ffffcd48][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e95][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd5b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd50
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd5b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in 80ee325][T] insDis:mov byte ptr [edx], al sink point: ffffcd50
804f99c:	[READ in ffffcd48][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e96][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd5b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd50
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd5b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in 80ee326][T] insDis:mov byte ptr [edx], al sink point: ffffcd50
804f99c:	[READ in ffffcd48][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e97][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd5b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd50
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd5b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in 80ee327][T] insDis:mov byte ptr [edx], al sink point: ffffcd50
804f99c:	[READ in ffffcd48][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e98][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd5b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd50
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd5b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in 80ee328][T] insDis:mov byte ptr [edx], al sink point: ffffcd50
804f99c:	[READ in ffffcd48][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e99][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd5b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd50
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd5b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in 80ee329][T] insDis:mov byte ptr [edx], al sink point: ffffcd50
804f99c:	[READ in ffffcd48][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e9a][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd5b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd50
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd5b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in 80ee32a][T] insDis:mov byte ptr [edx], al sink point: ffffcd50
804f99c:	[READ in ffffcd48][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e9b][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd5b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd50
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd5b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in 80ee32b][T] insDis:mov byte ptr [edx], al sink point: ffffcd50
804f99c:	[READ in ffffcd48][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e9c][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd5b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd50
8049777:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd5b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in 80ee32c][T] insDis:mov byte ptr [edx], al sink point: ffffcd50
804f99c:	[READ in ffffcd48][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e9d][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd5b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd50
8049797:	[READ in ffffcd70][F] insDis: mov eax, dword ptr [ebp+0x8]
80497c4:	[READ in 80ee320][T] insDis: movzx eax, byte ptr [0x80ee320]
80497cb:	[SPREAD][T] insDis:movsx edx, al
80497ce:	[READ in 80ee321][T] insDis: movzx eax, byte ptr [0x80ee321]
80497da:	[READ in 80ee323][T] insDis: movzx eax, byte ptr [0x80ee323]
80497e4:	[SPREAD][T] insDis:lea ecx, ptr [edx+eax*1]
80497e7:	[READ in 80ee324][T] insDis: movzx eax, byte ptr [0x80ee324]
80497f1:	[READ in 80ee32c][T] insDis: mov eax, dword ptr [0x80ee32c]
8049800:	[WRITE in 80ee4b4][T] insDis:mov dword ptr [eax], edx sink point: ffffcd80
8049802:	[SPREAD][F] insDis:mov eax, 0x0
8057ec9:	[SPREAD][F] insDis:test eax, eax
8057ee7:	[READ in 80ed328][F] insDis: mov edx, dword ptr [esi+0x8]
8057f45:	[SPREAD][F] insDis:mov ecx, edi
[TAINT]		bytes tainted from 0x80f2e90 to 0x80f3290
8054fe3:	[READ in 80f2e90][T] insDis: movzx eax, byte ptr [eax]
805816e:	[SPREAD][T] insDis:cmp eax, 0xffffffff
8058173:	[READ in 80ed324][F] insDis: mov eax, dword ptr [ebx+0x4]
805817c:	[READ in 80f2e90][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][T] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd76][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e91][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd77][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e92][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd78][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e93][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd79][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e94][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd7a][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e95][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd7b][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e96][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd7c][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e97][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd7d][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e98][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd7e][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e99][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd7f][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e9a][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd80][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e9b][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd81][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e9c][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd82][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e9d][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd83][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e9e][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd84][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2e9f][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd85][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2ea0][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd86][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2ea1][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049777:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
804977c:	[READ in ffffcd4b][T] insDis: movzx eax, byte ptr [ebp-0xd]
8049780:	[WRITE in ffffcd87][T] insDis:mov byte ptr [edx], al sink point: ffffcd40
804f99c:	[READ in ffffcd38][F] insDis: mov eax, dword ptr [esp]
80545d6:	[READ in 80f2ea2][T] insDis: movzx eax, byte ptr [eax]
804978b:	[WRITE in ffffcd4b][F] insDis:mov byte ptr [ebp-0xd], al sink point: ffffcd40
8049797:	[READ in ffffcd60][F] insDis: mov eax, dword ptr [ebp+0x8]
```
可以看出，并没有什么区别，也就是返回地址并没有被篡改。
通过 gdb 调试我们也可以证明这一点。
![屏幕截图 2024-07-21 015118.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1721497897735-3cd6fde4-010c-4b88-95d4-43178ebcca03.png#averageHue=%2341414d&clientId=u5d2c9c44-3812-4&from=ui&id=uf7e45d3a&originHeight=595&originWidth=962&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=523126&status=done&style=none&taskId=u0b273cc7-5ec5-4a7a-a055-eedb8896b14&title=)
如图所示，输入的数据存于栈上，而返回地址保存在 0xffffd06c 处，仍然完整。
![屏幕截图 2024-07-21 020251.png](https://cdn.nlark.com/yuque/0/2024/png/43291115/1721498589549-0d845b29-133a-4c15-ab32-50b7134350f6.png#averageHue=%237a7a82&clientId=u5d2c9c44-3812-4&from=ui&id=ud6a38eef&originHeight=392&originWidth=1047&originalType=binary&ratio=1.5&rotation=0&showTitle=false&size=234255&status=done&style=none&taskId=ufdc27c09-4607-4e30-84da-9ee37a9ec5d&title=)
这张图可以看得更清楚，vulfun2 中缓冲区起始地址为 0xffffd056，离返回地址偏移为 0x16 = 22，而第二次输入字符为 18 字节，因此 ebp 值、返回地址都不会被覆盖。
## 参考文章

- [https://blog.csdn.net/qq_37650593/article/details/83151505](https://blog.csdn.net/qq_37650593/article/details/83151505)
- [https://blog.csdn.net/Edidaughter/article/details/122627186](https://blog.csdn.net/Edidaughter/article/details/122627186)
- [https://www.cnblogs.com/level5uiharu/p/16963907.html](https://www.cnblogs.com/level5uiharu/p/16963907.html)
- [https://firmianay.gitbooks.io/ctf-all-in-one/content/doc/5.2.1_pin.html](https://firmianay.gitbooks.io/ctf-all-in-one/content/doc/5.2.1_pin.html)
- [https://blog.csdn.net/shanlijia/article/details/107524369](https://blog.csdn.net/shanlijia/article/details/107524369)
- [https://ctf-wiki.github.io/ctf-tools/binary-core-tools/instrumentation/intel_pin/](https://ctf-wiki.github.io/ctf-tools/binary-core-tools/instrumentation/intel_pin/)
- [https://github.com/zhilongwang/TaintAnalysisWithPin](https://github.com/zhilongwang/TaintAnalysisWithPin)
