#include "common.h"
#include "beacon.h"

#define SHA1LEN  20
#define print(format, ...) BeaconPrintf(CALLBACK_OUTPUT, format, ##__VA_ARGS__)


BOOL checkConfig() {
	HKEY _hKey;
	LONG _nResult;
	BOOL _check = FALSE;

	if (ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, "\\Software\\Wow6432Node\\Microsoft\\Cryptography\\Wintrust\\Config",
		0, KEY_READ , &_hKey) == ERROR_SUCCESS || ADVAPI32$RegOpenKeyExA(HKEY_LOCAL_MACHINE, 
		"\\Software\\Microsoft\\Cryptography\\Wintrust\\Config",0, KEY_READ, &_hKey) == ERROR_SUCCESS) {
		
		DWORD dwType;
		_nResult = ADVAPI32$RegQueryValueExA(_hKey, "EnableCertPaddingCheck", NULL, &dwType, NULL, NULL);
		if (_nResult == ERROR_SUCCESS)
			_check = TRUE;
		ADVAPI32$RegCloseKey(_hKey);
	}

	return _check;
}

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


unsigned short ChkSum(unsigned int CheckSum, void *FileBase, int Length)
{

	int *Data;
	int sum;

	if (Length && FileBase != NULL)
	{
		Data = (int *)FileBase;
		do
		{
			sum = *(unsigned short *)Data + CheckSum;
			Data = (int *)((char *)Data + 2);
			CheckSum = (unsigned short)sum + (sum >> 16);
		} while (--Length);
	}

	return CheckSum + (CheckSum >> 16);
}

unsigned int PEChecksum(void *FileBase, unsigned int FileSize)
{

	void *RemainData;
	int RemainDataSize;
	unsigned int PeHeaderSize;
	unsigned int HeaderCheckSum;
	unsigned int PeHeaderCheckSum;
	unsigned int FileCheckSum;
	PIMAGE_NT_HEADERS NtHeaders;
	
	NtHeaders = DBGHELP$ImageNtHeader(FileBase);
	if (NtHeaders)
	{
		HeaderCheckSum = NtHeaders->OptionalHeader.CheckSum;
		PeHeaderSize = (unsigned int)NtHeaders - (unsigned int)FileBase +
			((unsigned int)&NtHeaders->OptionalHeader.CheckSum - (unsigned int)NtHeaders);
		RemainData = &NtHeaders->OptionalHeader.Subsystem;
		PeHeaderCheckSum = ChkSum(0, FileBase, PeHeaderSize >> 1);
		FileCheckSum = ChkSum(PeHeaderCheckSum, RemainData, ((FileSize - PeHeaderSize - 4)/4));
		
		if (FileSize & 1)
		{
			FileCheckSum += (unsigned short)*((char *)FileBase + FileSize - 1);
		}
	}
	else
	{
		FileCheckSum = 0;
	}

	return (FileSize + FileCheckSum);
}

void* genKey(char* _key) {

	char _tmpkey[16] = "randomkeyrandom";

	MSVCRT$srand(MSVCRT$time(NULL));
	
	for (int i = 0; i < 15; ++i) {
		_tmpkey[i] = '0' + MSVCRT$rand() % 72;
	}

	MSVCRT$memcpy(_key, _tmpkey, sizeof(_tmpkey));
}

char* genRandomBytes(size_t _Len, char* _rpadding) {
		MSVCRT$srand(MSVCRT$time(NULL));
		const char* st = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.-#'?!";
		size_t sLen = 26 * 2 + 10 + 7;
		unsigned int key = 0;

		for (int n = 0; n < _Len; n++) {
			key = MSVCRT$rand() % sLen;
			_rpadding[n] = st[key];
		}

		_rpadding[_Len] = '\0';

		return _rpadding;
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

void toMultiByte(DWORD strLen, CHAR* _Str, LPWSTR _wStr) {
	DWORD wlen = strLen * 2;
	_wStr = (LPWSTR)MSVCRT$malloc(wlen * sizeof(wchar_t));
	MSVCRT$mbstowcs(_wStr, _Str, MSVCRT$strlen(_Str) + 1);
}

BOOL Sha1(BYTE* peblob, char* sha1Buf, DWORD dwBufferLen)
{
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	BYTE rgbHash[SHA1LEN];
	DWORD cbHash = 0;

	if (!ADVAPI32$CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)){
		return FALSE;
	}

	if (!ADVAPI32$CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
		ADVAPI32$CryptReleaseContext(hProv, 0);
		return FALSE;
	}

	if (!ADVAPI32$CryptHashData(hHash, peblob, dwBufferLen, 0)){	
		ADVAPI32$CryptReleaseContext(hProv, 0);
		ADVAPI32$CryptDestroyHash(hHash);
		return FALSE;
	}


	cbHash = SHA1LEN;
	if (ADVAPI32$CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
		for (DWORD i = 0; i < cbHash; i++) {
			MSVCRT$sprintf( sha1Buf + (i * 2), "%02x", rgbHash[i]);
		}

	}
	else {
		return FALSE;
	}
	 
	ADVAPI32$CryptDestroyHash(hHash);
	ADVAPI32$CryptReleaseContext(hProv, 0);

	return TRUE;
}

DWORD VerifyPESignature(PCWSTR FileName, HANDLE FileHandle)
{
	DWORD Error = ERROR_SUCCESS;
	BOOL WintrustCalled = FALSE;
	GUID GenericActionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_DATA WintrustData = {};
	WINTRUST_FILE_INFO FileInfo = {};

	// Setup data structures for calling WinVerifyTrust 
	WintrustData.cbStruct = sizeof(WINTRUST_DATA);
	WintrustData.dwStateAction = WTD_STATEACTION_VERIFY;
	WintrustData.dwUIChoice = WTD_UI_NONE;
	WintrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	WintrustData.dwUnionChoice = WTD_CHOICE_FILE;

	FileInfo.cbStruct = sizeof(FileInfo);
	FileInfo.hFile = FileHandle;
	FileInfo.pcwszFilePath = FileName;
	WintrustData.pFile = &FileInfo;


	Error = WINTRUST$WinVerifyTrust(NULL, &GenericActionId, &WintrustData);
	WintrustCalled = TRUE;
	if (Error != ERROR_SUCCESS)
	{
		goto Cleanup;
	}

Cleanup:

	// Call WinVerifyTrust with WTD_STATEACTION_CLOSE to free memory allocated by WinVerifyTrust 
	if (WintrustCalled != FALSE)
	{
		WintrustData.dwStateAction = WTD_STATEACTION_CLOSE;
		WINTRUST$WinVerifyTrust(NULL, &GenericActionId, &WintrustData);
	}

	return Error;
}

