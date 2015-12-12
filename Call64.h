#pragma once

//You can change this value
#define MAX_NUMBER_ARGUMENTS 0x30




struct LARGE_INTEGER_
{
	unsigned long Low;
	unsigned long High;
};


extern "C"
{

__declspec(dllimport) bool Call64(LARGE_INTEGER_* pReturnValue,unsigned long syscallNum,unsigned long numArg,...);

}