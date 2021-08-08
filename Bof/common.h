#ifndef _COMMON_
#define _COMMON_
#pragma once
#pragma comment(lib, "dbghelp.lib") 

#include <windows.h>
#include <stdio.h>
#include <dbghelp.h>
#include <time.h>
#include <softpub.h>


WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE hModule, LPCSTR  lpProcName);
WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentProcess();
WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR lpModuleName);
WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle (HANDLE hObject);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA (LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
WINBASEAPI DWORD WINAPI KERNEL32$GetFileSize (HANDLE hFile, LPDWORD lpFileSizeHigh);
WINBASEAPI WINBOOL WINAPI KERNEL32$ReadFile (HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
WINBASEAPI void __cdecl MSVCRT$srand(unsigned int seed);  
WINBASEAPI int __cdecl MSVCRT$rand();  
WINBASEAPI FILE *__cdecl MSVCRT$fopen(const char *filename, const char *mode);
WINBASEAPI int __cdecl MSVCRT$fclose(FILE *stream);
WINBASEAPI size_t __cdecl MSVCRT$fwrite(const void *buffer,size_t size,size_t count,FILE *stream);
WINBASEAPI char* __cdecl MSVCRT$strrchr( const char *str, int c);
WINBASEAPI void *__cdecl MSVCRT$memcpy(void * __restrict__ _Dst,const void * __restrict__ _Src,size_t _MaxCount);
WINBASEAPI void *__cdecl MSVCRT$realloc(void *_Memory, size_t _NewSize);
WINBASEAPI void __cdecl MSVCRT$free(void *_Memory);
WINBASEAPI void __cdecl MSVCRT$memset(void *dest, int c, size_t count);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char *_Str);
WINBASEAPI void *__cdecl MSVCRT$malloc(size_t size);
WINBASEAPI time_t __cdecl MSVCRT$time( time_t *destTime );
WINADVAPI LONG WINAPI ADVAPI32$RegOpenKeyExA(HKEY hKey,LPCSTR lpSubKey,DWORD ulOptions,REGSAM samDesired,PHKEY phkResult);
WINADVAPI LONG WINAPI ADVAPI32$RegQueryValueExA(HKEY hKey,LPCSTR lpValueName,LPDWORD lpReserved,LPDWORD lpType,LPBYTE lpData,LPDWORD lpcbData);
WINADVAPI LONG WINAPI ADVAPI32$RegCloseKey(HKEY hKey);
DECLSPEC_IMPORT PIMAGE_NT_HEADERS IMAGEAPI DBGHELP$ImageNtHeader(PVOID Base);
DECLSPEC_IMPORT size_t __cdecl  MSVCRT$mbstowcs( wchar_t *wcstr, const char *mbstr, size_t count);
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$CryptAcquireContextA(HCRYPTPROV *, LPCSTR, LPCSTR, DWORD, DWORD );
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$CryptCreateHash( HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH * );
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$CryptReleaseContext( HCRYPTPROV, DWORD );
WINADVAPI BOOL WINAPI ADVAPI32$CryptHashData( HCRYPTHASH, PBYTE, DWORD, DWORD );
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$CryptDestroyHash( HCRYPTHASH );
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$CryptGetHashParam( HCRYPTHASH, DWORD, PBYTE, PDWORD, DWORD );
WINBASEAPI int __cdecl MSVCRT$sprintf(char *__stream, const char *__format, ...);
WINBASEAPI LONG WINAPI WINTRUST$WinVerifyTrust(HWND hwnd, GUID *pgActionID, LPVOID pWVTData);
WINBASEAPI void WINAPI SHLWAPI$PathStripPathA(LPSTR path);


#endif