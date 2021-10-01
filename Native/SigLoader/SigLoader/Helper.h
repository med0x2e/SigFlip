#ifndef _HELPER_
#define _HELPER_

#pragma comment(lib, "dbghelp.lib") 

#include <stdio.h>
#include <windows.h>
#include <DbgHelp.h>
#include <WinTrust.h>
#include <time.h>

extern void decrypt(unsigned char* data, long dataLen, unsigned char* key, long keyLen, unsigned char* result);
extern BOOL IsWow64(HANDLE pHandle);

#endif 