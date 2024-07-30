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
		D(std::cout << "\t\t\t--" << REG_StringShort(reg) << " is already tainted" << endl;)
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
		 //std::cout << std::hex << reg_r << "Write" << std::endl;
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


VOID FunctionRet(ADDRINT ip, CONTEXT *ctx) {
	if(ip <= 0x80b8000) {
		UINT32 value;
		UINT8* ESP_value = (UINT8*)&value;
		PIN_GetContextRegval(ctx, REG_ESP, ESP_value);
		//value += 8;
		value %= 0x10000000;
		//outFile << std::hex << "ESP->" << value << std::endl;
		if(addressTainted.count(value)) {
			outFile << std::hex << "ERROR:RET Address Is Tainted!" << " &&ESP->" << value << std::endl;
		}
	}
}


VOID Instruction(INS ins, VOID* v) {
	//outFile << std::hex << INS_Address(ins) << ":\t" << INS_Disassemble(ins) << std::endl;
	if(INS_OperandCount(ins) <= 1 && !INS_IsRet(ins))
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
	}/* else */if(INS_IsRet(ins)) {
		INS_InsertCall(
			ins, IPOINT_BEFORE, (AFUNPTR)FunctionRet,
			IARG_ADDRINT, INS_Address(ins),
			IARG_CONTEXT,
			IARG_END);
	}
}


VOID TaintInit() {
	shadow_reg = new ShadowReg();
}

/*
VOID on_call(ADDRINT ret) {
	if(addressTainted.count(ret)) {
		outFile << "Return address 0x" << hex << ret << " has been corrupted.\n" << endl;
	}
}


VOID ImageLoad(IMG img, VOID *v) {
    for (RTN rtn = IMG_RegtabRtn(img, 0); RTN_Valid(rtn); rtn = IMG_RegtabRtn(img, RTN_Next(rtn))) {
        RTN_Open(rtn);
        RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)FunctionRet, IARG_RETURN_IP, IARG_CONTEXT, IARG_END);
        RTN_Close(rtn);
    }
}
*/


int main(int argc, char *argv[]) {
    PIN_Init(argc, argv);
    PIN_InitSymbols();
    TaintInit();
    PIN_SetSyntaxIntel();
    outFile.open(KnobOutputFile.Value().c_str());
    
    PIN_AddSyscallEntryFunction(SyscallEntry, 0);
    //PIN_AddImageLoadFunction(ImageLoad, 0);
    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    return 0;
}
