#include "common.h"
#include "beacon.h"

#define SHA1LEN  20
#define print(format, ...) BeaconPrintf(CALLBACK_OUTPUT, format, ##__VA_ARGS__)


char* getFName(char* path, char* pFileName)
{

	MSVCRT$memcpy(pFileName, path, MSVCRT$strlen(path));

	if (path == NULL)
		return NULL;

	for (char* pCur = path; *pCur != '\0'; pCur++)
	{
		if (*pCur == '/' || *pCur == '\\')
			pFileName = pCur + 1;
	}

	return pFileName;
}

void crypt(unsigned char* data, long dataLen, char* key, long keyLen, unsigned char* result){
	unsigned char T[256];
	unsigned char S[256];
	unsigned char  tmp; 
	int j = 0, t = 0, i = 0;


	for (int i = 0; i < 256; i++){
		S[i] = i;
		T[i] = key[i % keyLen];
	}

	for (int i = 0; i < 256; i++){
		j = (j + S[i] + T[i]) % 256;
		tmp = S[j];
		S[j] = S[i];
		S[i] = tmp;
	}
	j = 0; 
	for (int x = 0; x < dataLen; x++){
		i = (i + 1) % 256; 
		j = (j + S[i]) % 256; 

		tmp = S[j];
		S[j] = S[i];
		S[i] = tmp;

		t = (S[i] + S[j]) % 256;

		result[x] = data[x] ^ S[t];
	}
}

BOOL IsWow64(HANDLE pHandle)
{
	BOOL isWow64 = FALSE;

	typedef BOOL(WINAPI *PFNIsWow64Process) (HANDLE, PBOOL);
	PFNIsWow64Process _FNIsWow64Process;
	_FNIsWow64Process = (PFNIsWow64Process)KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("kernel32"), "IsWow64Process");

	if (NULL != _FNIsWow64Process){
		if (!_FNIsWow64Process(pHandle, &isWow64)) {}
	}
	return isWow64;
}

LPWSTR toMultiByte(DWORD strLen, CHAR* _Str, LPWSTR _wStr) {
	DWORD wlen = strLen * 2;
	_wStr = (LPWSTR)MSVCRT$malloc(wlen * sizeof(wchar_t));
	MSVCRT$mbstowcs(_wStr, _Str, MSVCRT$strlen(_Str) + 1);

	return _wStr;
}
