#include "Helper.h"

void decrypt(unsigned char* data, long dataLen, unsigned char* key, long keyLen, unsigned char* result) {
	unsigned char T[256];
	unsigned char S[256];
	unsigned char  tmp;
	int j = 0, t = 0, i = 0;


	for (int i = 0; i < 256; i++) {
		S[i] = i;
		T[i] = key[i % keyLen];
	}

	for (int i = 0; i < 256; i++) {
		j = (j + S[i] + T[i]) % 256;
		tmp = S[j];
		S[j] = S[i];
		S[i] = tmp;
	}
	j = 0;
	for (int x = 0; x < dataLen; x++) {
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
	_FNIsWow64Process = (PFNIsWow64Process)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process");

	if (NULL != _FNIsWow64Process) {
		if (!_FNIsWow64Process(pHandle, &isWow64)) {}
	}
	return isWow64;
}