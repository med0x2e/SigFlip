#ifndef _HELPER_
#define _HELPER_

#pragma comment(lib, "dbghelp.lib") 

#include <stdio.h>
#include <windows.h>
#include <DbgHelp.h>
#include <time.h>

#include <softpub.h> 

#define SHA1LEN  20

extern unsigned int PEChecksum(void *FileBase, unsigned int FileSize);
extern char* genRandomBytes(size_t length);
extern char* genKey();
extern void *memcopy(void *const dest, void const *const src, size_t bytes);
extern void crypt(unsigned char* data, long dataLen, char* key, long keyLen, unsigned char* result);
extern BOOL IsWow64(HANDLE pHandle);
extern BOOL Sha1(BYTE* peBlob, char* sha1Buf, DWORD dwBufferLen);
extern DWORD VerifyPESignature(PCWSTR FileName, HANDLE FileHandle);
extern void toMultiByte(DWORD strLen, CHAR* _Str, LPWSTR _wStr);
extern char* getFName(char* _fPath);

#endif 