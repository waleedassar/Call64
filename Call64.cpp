#include "stdafx.h"
#include "windows.h"
#include "stdio.h"
#include "malloc.h"
#include "Call64.h"
//-------------------------------Helper Functions------------------------------------
void* _aligned_malloc(unsigned long size,unsigned long alignment)
{
	if(size==0) return 0;
	unsigned long total_size=size+alignment+4;
	if(total_size<size) return 0;
	unsigned long pReal=(unsigned long)LocalAlloc(LMEM_ZEROINIT,total_size);
	unsigned long pRunner=pReal+4;
	if(pReal==0) return 0;

	while(pRunner & (alignment-1)) pRunner++;
	*(unsigned long*)(pRunner-4)=pReal;
	return (void*)pRunner;
}

void _aligned_free(void* pMem)
{
	if(!pMem) return;
	unsigned long p=*(((unsigned long*)pMem)-1);
	LocalFree((void*)p);
}
//--------------------------------------------------------------------------------
unsigned short Get64CSValue()
{
		unsigned short cs_64=0x33; //default
		unsigned long X86SwitchTo64BitMode=0;
		__asm
		{
					push eax
					mov eax,dword ptr fs:[0xC0]
					mov X86SwitchTo64BitMode,eax
					pop eax
		}
		if(!X86SwitchTo64BitMode) return 0;
		if(*(unsigned char*)X86SwitchTo64BitMode==0xEA) //Jmp Far
		{
			 cs_64=*(unsigned short*)(X86SwitchTo64BitMode+5);
		}
		return cs_64;
}
//------------------------------------------------------
char shellcode64[]=
"\x48\x8B\x0C\x24\x48\x89\x0F\x48\x83\xC4\x08\x48\x8B\x0C\x24"
"\x90\x90\x48\x8B\x54\x24\x08\x4C\x8B\x44\x24\x10\x4C\x8B\x4C"
"\x24\x18\xE8\x08\x00\x00\x00\x48\x89\x06\x48\x8B\x0F\x51\xCB"
"\x4C\x8B\xD1\xB8\xCE\xCE\xCE\xCE\x0F\x05\xC3";
//------------------------------------------------------

extern "C"
{

_declspec(dllexport) bool Call64(LARGE_INTEGER_* pReturnValue,unsigned long syscallNum,unsigned long numArg,...)
{
	//---------------Sanity checks-------------------------------------
	if(numArg>MAX_NUMBER_ARGUMENTS) return false;
	//-----------------------------------------------------------------
	va_list arguments;
	va_start(arguments,numArg);
	//-----------Initialize first four arguments------------------------
	unsigned long rem=0;
	unsigned long extra_stack_size=0x20;
	unsigned long* pStack=0;
	if(numArg>4)
	{
		rem=numArg-4;
		extra_stack_size+=(rem*sizeof(LARGE_INTEGER_));
		pStack=(unsigned long*)_alloca(extra_stack_size);
	    memset(pStack,0x0,extra_stack_size);

	}
	else
	{
		pStack=(unsigned long*)_alloca(extra_stack_size);
	    memset(pStack,0x0,extra_stack_size);
	}

	LARGE_INTEGER_* pR=0;
	LARGE_INTEGER_* pStack_=(LARGE_INTEGER_*)pStack;
	for(unsigned long i=0;i<numArg;i++)
	{
			pR=va_arg(arguments,LARGE_INTEGER_*);
			pStack_->Low=pR->Low;
			pStack_->High=pR->High;
			pStack_++;
	}
	//-----------------------------------------------------------------
	if(!pReturnValue) return false;
	char* p64Code=(char*)LocalAlloc(LMEM_ZEROINIT,0x100);  //This holds code
	memcpy(p64Code,shellcode64,sizeof(shellcode64));
	       *(unsigned long*)(&p64Code[0x31])=syscallNum;	   
		   memset(pReturnValue,0,sizeof(LARGE_INTEGER_));

		   char* pGate=&p64Code[0x50];
		   *(unsigned long*)pGate=(unsigned long)p64Code;
		   *(unsigned short*)(pGate+0x4)=Get64CSValue();
		   LARGE_INTEGER_ HouseKeeping;
		   LARGE_INTEGER_* pHouseKeeping=&HouseKeeping;
		   __asm
		   {
			   mov eax,pGate
			   mov esi,pReturnValue
			   mov edi,pHouseKeeping
			   call fword ptr[eax]
		   }
	LocalFree(p64Code);
	return true;
}

}


BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{
    return TRUE;
}

