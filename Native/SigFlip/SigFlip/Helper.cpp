#include "pch.h"
#include "Helper.h"

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
	
	NtHeaders = ImageNtHeader(FileBase);
	if (NtHeaders)
	{
		HeaderCheckSum = NtHeaders->OptionalHeader.CheckSum;
		PeHeaderSize = (unsigned int)NtHeaders - (unsigned int)FileBase +
			((unsigned int)&NtHeaders->OptionalHeader.CheckSum - (unsigned int)NtHeaders);
		RemainDataSize = (FileSize - PeHeaderSize - 4) >> 1;
		RemainData = &NtHeaders->OptionalHeader.Subsystem;
		PeHeaderCheckSum = ChkSum(0, FileBase, PeHeaderSize >> 1);
		FileCheckSum = ChkSum(PeHeaderCheckSum, RemainData, RemainDataSize);

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

char* genKey() {

	char _key[16] = "randomkeyrandom";

	srand(time(NULL));
	
	for (int i = 0; i < 15; ++i) {
		_key[i] = '0' + rand() % 72;
	}
	return _key;
}

char* genRandomBytes(size_t length) {
		srand(time(NULL));
		const char* st = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,.-#'?!";
		size_t sLen = 26 * 2 + 10 + 7;
		char *rStr;

		rStr = (char*) malloc(sizeof(char) * (length + 1));

		if (!rStr) {
			return (char*)0;
		}

		unsigned int key = 0;

		for (int n = 0; n < length; n++) {
			key = rand() % sLen;
			rStr[n] = st[key];
		}

		rStr[length] = '\0';

		return rStr;
}

// Added
char* getCustomScript(char* _cPath) {
	char* rStr = NULL;
	size_t _sizeCustomScript = 0;
	size_t length = 0;
	size_t sz_rpadding;

	// Read file
	FILE* pFile = fopen(_cPath, "rb");
	int s_result = fseek(pFile, 0, SEEK_END);
	if (s_result != 0) {
		exit(EXIT_FAILURE);
	}

	// get size of file
	_sizeCustomScript = ftell(pFile);

	// Length always a multiple of 8
	length = (_sizeCustomScript - (_sizeCustomScript % 8)) + 8;

	// allocate memory
	rStr = (char*)malloc(sizeof(char) * (length + 1));

	// Read from start
	fseek(pFile, 0, SEEK_SET);

	for (int i = 0; i < length; i++) {
		if (i < _sizeCustomScript) {
			rStr[i] = fgetc(pFile);
		}
		else {
			rStr[i] = 0x20;
		}
	}

	rStr[length] = '\0';

	fclose(pFile);

	return rStr;
}
// --------------

void *memcopy(void *const dest, void const *const src, size_t bytes){
	while (bytes-- > (size_t)0)
		((unsigned char *)dest)[bytes] = ((unsigned char const *)src)[bytes];

	return dest;
}

char* getFName(char* _fPath) {

	char *sepd = (strrchr(_fPath, '/') != NULL) ? strrchr(_fPath, '/') : strrchr(_fPath, '\\');

	int l_sep, i = 0;
	char sep = sepd[0];
	if (*_fPath) {
		while (_fPath[i++]) if (_fPath[i] == sep) l_sep = i;
		return _fPath[l_sep] == sep ? &_fPath[l_sep + 1] : _fPath;
	}
	return _fPath;
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


BOOL Sha1(BYTE* peblob, char* sha1Buf, DWORD dwBufferLen)
{
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	BYTE rgbHash[SHA1LEN];
	DWORD cbHash = 0;

	// Get handle to the crypto provider
	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)){
		return FALSE;
	}

	if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash)) {
		CryptReleaseContext(hProv, 0);
		return FALSE;
	}

	if (!CryptHashData(hHash, peblob, dwBufferLen, 0)){	
		CryptReleaseContext(hProv, 0);
		CryptDestroyHash(hHash);
		return FALSE;
	}


	cbHash = SHA1LEN;
	if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
		for (DWORD i = 0; i < cbHash; i++) {
			sprintf( sha1Buf + (i * 2), "%02x", rgbHash[i]);
		}
	}
	else {
		return FALSE;
	}

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);

	return TRUE;
}


BOOL IsWow64(HANDLE pHandle)
{
	BOOL isWow64 = FALSE;

	typedef BOOL(WINAPI *PFNIsWow64Process) (HANDLE, PBOOL);
	PFNIsWow64Process _FNIsWow64Process;
	_FNIsWow64Process = (PFNIsWow64Process)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process");

	if (NULL != _FNIsWow64Process){
		if (!_FNIsWow64Process(pHandle, &isWow64)) {}
	}
	return isWow64;
}

void toMultiByte(DWORD strLen, CHAR* _Str, LPWSTR _wStr) {
	DWORD wlen = strLen * 2;
	_wStr = (LPWSTR)malloc(wlen * sizeof(wchar_t));
	mbstowcs(_wStr, _Str, strlen(_Str) + 1);
}


DWORD VerifyPESignature(PCWSTR FileName, HANDLE FileHandle)
{
	DWORD Error = ERROR_SUCCESS;
	bool WintrustCalled = false;
	GUID GenericActionId = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_DATA WintrustData = {};
	WINTRUST_FILE_INFO FileInfo = {};
	WINTRUST_SIGNATURE_SETTINGS SignatureSettings = {};

	// Setup data structures for calling WinVerifyTrust 
	WintrustData.cbStruct = sizeof(WINTRUST_DATA);
	WintrustData.dwStateAction = WTD_STATEACTION_VERIFY;
	WintrustData.dwUIChoice = WTD_UI_NONE;
	WintrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	WintrustData.dwUnionChoice = WTD_CHOICE_FILE;

	FileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO_);
	FileInfo.hFile = FileHandle;
	FileInfo.pcwszFilePath = FileName;
	WintrustData.pFile = &FileInfo;

	SignatureSettings.cbStruct = sizeof(WINTRUST_SIGNATURE_SETTINGS);
	SignatureSettings.dwFlags = WSS_GET_SECONDARY_SIG_COUNT | WSS_VERIFY_SPECIFIC;
	SignatureSettings.dwIndex = 0;
	WintrustData.pSignatureSettings = &SignatureSettings;

	Error = WinVerifyTrust(NULL, &GenericActionId, &WintrustData);
	WintrustCalled = true;
	if (Error != ERROR_SUCCESS)
	{
		goto Cleanup;
	}

	// Now attempt to verify all secondary signatures that were found 
	for (DWORD x = 1; x <= WintrustData.pSignatureSettings->cSecondarySigs; x++)
	{

		// Need to clear the previous state data from the last call to WinVerifyTrust 
		WintrustData.dwStateAction = WTD_STATEACTION_CLOSE;
		Error = WinVerifyTrust(NULL, &GenericActionId, &WintrustData);
		if (Error != ERROR_SUCCESS)
		{
			//No need to call WinVerifyTrust again 
			WintrustCalled = false;
			goto Cleanup;
		}

		WintrustData.hWVTStateData = NULL;

		// Caller must reset dwStateAction as it may have been changed during the last call 
		WintrustData.dwStateAction = WTD_STATEACTION_VERIFY;
		WintrustData.pSignatureSettings->dwIndex = x;
		Error = WinVerifyTrust(NULL, &GenericActionId, &WintrustData);
		if (Error != ERROR_SUCCESS)
		{
			goto Cleanup;
		}
	}

Cleanup:

	// Caller must call WinVerifyTrust with WTD_STATEACTION_CLOSE to free memory 
	// allocate by WinVerifyTrust 
	if (WintrustCalled != false)
	{
		WintrustData.dwStateAction = WTD_STATEACTION_CLOSE;
		WinVerifyTrust(NULL, &GenericActionId, &WintrustData);
	}


	return Error;
}




